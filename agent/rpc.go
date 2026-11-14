// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

// Request from the server on the agent's subject. Each func reads only its own fields.
type NatsMsg struct {
	Func                   string     `json:"func"`
	Timeout                int        `json:"timeout"`
	Data                   payloadMap `json:"payload"`
	Code                   string     `json:"code"`
	ScriptArgs             []string   `json:"script_args"`
	EnvVars                []string   `json:"env_vars"`
	RunAsUser              bool       `json:"run_as_user"`
	Sha256                 string     `json:"sha256"`
	Stream                 bool       `json:"stream"`
	NushellEnableConfig    bool       `json:"nushell_enable_config"`
	DenoDefaultPermissions string     `json:"deno_default_permissions"`
	ProcPID                int32      `json:"procpid"`
	Macs                   []string   `json:"macs"`
	ID                     int        `json:"id"`
	TaskPK                 int        `json:"taskpk"`
	ScheduledTask          SchedTask  `json:"schedtaskpayload"`
	RecoveryCommand        string     `json:"recoverycommand"`
	Until                  int64      `json:"until"`
	AC                     bool       `json:"ac"`
	UpdateGUIDs            []string   `json:"guids"`
	PatchMgmt              bool       `json:"patch_mgmt"`
	WUADrivers             bool       `json:"wua_drivers"`
	ChocoProgName          string     `json:"choco_prog_name"`
	PendingActionPK        int        `json:"pending_action_pk"`
	WingetID               string     `json:"winget_id"`
}

// updateSha256: the message-level hash wins over the one in payload.
func (m *NatsMsg) updateSha256() string {
	if m.Sha256 != "" {
		return m.Sha256
	}
	return m.Data["sha256"]
}

// payloadMap is the string map in "payload". The server sends strings
// only; a number or bool is taken as its text instead of dropping the
// whole request.
type payloadMap map[string]string

func (p *payloadMap) CodecEncodeSelf(e *codec.Encoder) {
	e.MustEncode(map[string]string(*p))
}

func (p *payloadMap) CodecDecodeSelf(d *codec.Decoder) {
	var raw map[string]interface{}
	d.MustDecode(&raw)
	if raw == nil {
		*p = nil
		return
	}
	m := make(payloadMap, len(raw))
	for k, v := range raw {
		switch t := v.(type) {
		case nil:
			m[k] = ""
		case string:
			m[k] = t
		case []byte:
			m[k] = string(t)
		case bool, int64, uint64, float32, float64:
			m[k] = fmt.Sprint(t)
		}
	}
	*p = m
}

var (
	updateRunning        atomic.Bool
	getWinUpdRunning     atomic.Bool
	installWinUpdRunning atomic.Bool
)

const histResultURL = "/api/v3/%d/%s/histresult/"

// postWingetResult closes the pending action of a winget install.
func (a *Agent) postWingetResult(pk int, out string, code int64) error {
	url := fmt.Sprintf("/api/v4/%s/%d/wingetresult/", a.AgentID, pk)
	return a.patchWithRetry(url, map[string]interface{}{"results": out, "exit_code": code}, pkgRetryWait)
}

// postChocoResult closes the pending action of a choco install.
func (a *Agent) postChocoResult(pk int, out string) error {
	url := fmt.Sprintf("/api/v4/%s/%d/chocoresult/", a.AgentID, pk)
	return a.patchWithRetry(url, rmm.CmdOutput{Text: out}, pkgRetryWait)
}

// notRunnable is why the service cannot start, "" when it can. A token
// that is there but does not open is a keystore problem, not a missing
// install.
func (a *Agent) notRunnable() string {
	if a.AgentID != "" && a.Token != "" {
		return ""
	}
	if _, _, err := currentKEK(); err != nil {
		return "the secrets of the config do not open: " + err.Error()
	}
	return "the agent is not installed (no agent id or token in the config)"
}

// shouldRevert is the decision of the revert timer: the previous build
// comes back only while this one has no NATS connection and the rollback
// copy is still there.
func shouldRevert(connected, previousExists bool) bool {
	return previousExists && !connected
}

// Connect, start the background work, answer requests until the process ends.
func (a *Agent) RunRPC() {
	a.Logger.Infoln("Agent service started")
	a.keepNew = a.armRevert()
	if why := a.notRunnable(); why != "" {
		a.Logger.Fatalln("RunRPC():", why)
	}
	a.setupIdentity()
	frameAgent.Store(a)
	nc, err := nats.Connect(a.NatsServer, a.setupNatsOptions()...)
	if err != nil {
		a.Logger.Fatalln("RunRPC() nats.Connect()", err)
	}

	clearExpectedStop(a.dataDir())
	go a.watchStop(nc)
	go a.watchPower(nc)
	go a.powerStartup(nc)
	go a.RunAsService(nc)

	if _, err := nc.Subscribe(a.AgentID, func(msg *nats.Msg) { a.dispatch(nc, msg) }); err != nil {
		a.Logger.Errorln("nats: subscribe:", err)
	}
	if err := nc.Flush(); err != nil {
		a.Logger.Errorf("nats: subscribing to %s failed: %v (status %v)", a.NatsServer, err, nc.Status())
	} else if runtime.GOOS != "windows" {
		// this build runs and reached the server: the rollback copy of the
		// last update has done its job
		a.keepNew()
	}
	if err := nc.LastError(); err != nil {
		a.Logger.Errorln(err)
		os.Exit(1)
	}
	select {}
}

type rpcReq struct {
	a       *Agent
	nc      *nats.Conn
	msg     *nats.Msg
	p       *NatsMsg
	replied bool
	// session of a signed command; its answer is sealed
	ctx *cmdCtx
}

func (r *rpcReq) reply(v interface{}) {
	r.replied = true
	if r.msg.Reply == "" {
		return
	}
	b, err := encodeMsgpack(v)
	if err != nil {
		r.a.Logger.Errorln("rpc", r.p.Func, "encode reply:", err)
		return
	}
	if r.ctx != nil {
		var ok bool
		if b, ok = r.a.sec2.sealReply(r.a.AgentID, r.ctx, b, time.Now()); !ok {
			r.a.Logger.Errorln("rpc", r.p.Func, "the session of the command is gone, no answer")
			return
		}
	}
	_ = r.msg.Respond(b)
}

// Runs on the subscription's goroutine: decode, then hand off. Terminal
// requests keep their order, everything else runs concurrently, the heavy
// ones and the probes each in a pool of their own.
func (a *Agent) dispatch(nc *nats.Conn, msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			a.Logger.Errorf("recovered from panic in rpc dispatch: %v\n%s", r, debug.Stack())
		}
	}()
	data, ctx, ok := a.openRequest(msg)
	if !ok {
		return
	}
	var p *NatsMsg
	mh := codec.MsgpackHandle{}
	mh.RawToString = true
	if err := codec.NewDecoderBytes(data, &mh).Decode(&p); err != nil {
		a.Logger.Errorln("rpc decode:", err)
		return
	}
	if p == nil || p.Func == "" {
		return
	}
	req := &rpcReq{a: a, nc: nc, msg: msg, p: p, ctx: ctx}
	if strings.HasPrefix(p.Func, "terminal_") {
		a.queueTerminal(req)
		return
	}
	go runBounded(p.Func, req.run, func() { req.reply("agent busy, try again") })
}

// heavyRPC funcs start a process or build a large answer; a burst of them
// would starve the agent. The read-only probes get a pool of their own, so
// long scripts cannot keep them waiting.
var (
	heavyRPC   = map[string]bool{"runscript": true, "runscriptfull": true, "rawcmd": true}
	probeRPC   = map[string]bool{"eventlog": true, "softwarelist": true, "procs": true, "wmi": true}
	heavySlots = make(chan struct{}, 16)
	probeSlots = make(chan struct{}, 8)
	// longer than this and the caller has likely given up; tests shorten it
	slotWait = 30 * time.Second
)

// runBounded runs run, for a heavy fn or a probe once a slot of its pool is
// free. When none frees up within slotWait, busy answers instead and run
// does not run. Callers start it in a goroutine, so the wait never holds
// the subscription.
func runBounded(fn string, run, busy func()) {
	slots := heavySlots
	switch {
	case probeRPC[fn]:
		slots = probeSlots
	case !heavyRPC[fn]:
		run()
		return
	}
	t := time.NewTimer(slotWait)
	defer t.Stop()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
		run()
	case <-t.C:
		busy()
	}
}

// Terminal requests of one session run in arrival order on their own
// worker, so keystrokes cannot overtake each other. A kill also runs at
// once: a write stuck on a shell that reads no input must not block it.
var terminalQueues = struct {
	sync.Mutex
	m map[string]chan *rpcReq
}{m: map[string]chan *rpcReq{}}

const terminalQueueIdle = time.Minute

func (a *Agent) queueTerminal(req *rpcReq) {
	sid := req.p.Data["session_id"]
	if req.p.Func == "terminal_kill" {
		now := *req
		go now.run()
	}
	terminalQueues.Lock()
	defer terminalQueues.Unlock()
	ch, ok := terminalQueues.m[sid]
	if !ok {
		ch = make(chan *rpcReq, 256)
		terminalQueues.m[sid] = ch
		go terminalWorker(sid, ch)
	}
	select {
	case ch <- req:
	default:
		a.Logger.Errorln("rpc: terminal queue full, dropped", req.p.Func, "for session", sid)
	}
}

func terminalWorker(sid string, ch chan *rpcReq) {
	for {
		select {
		case r := <-ch:
			r.run()
		case <-time.After(terminalQueueIdle):
			terminalQueues.Lock()
			if len(ch) == 0 {
				delete(terminalQueues.m, sid)
				terminalQueues.Unlock()
				return
			}
			terminalQueues.Unlock()
		}
	}
}

// A panic is logged and, if nothing was sent yet, answered with an error in
// the shape the func normally replies.
func (r *rpcReq) run() {
	a, p := r.a, r.p
	defer func() {
		if v := recover(); v != nil {
			a.Logger.Errorf("recovered from panic in rpc %s: %v\n%s", p.Func, v, debug.Stack())
			if !r.replied {
				r.reply(panicReply(p.Func))
			}
		}
	}()

	switch p.Func {
	case "ping":
		r.reply("pong")

	case "patchmgmt":
		r.reply(errOK(a.PatchMgmnt(p.PatchMgmt)))

	case "schedtask":
		ok, err := a.CreateSchedTask(p.ScheduledTask)
		switch {
		case err != nil:
			r.reply(err.Error())
		case !ok:
			r.reply("Something went wrong")
		default:
			r.reply("ok")
		}

	case "delschedtask":
		r.reply(errOK(DeleteSchedTask(p.ScheduledTask.Name)))

	case "listschedtasks":
		r.reply(ListSchedTasks())

	case "eventlog":
		days, _ := strconv.Atoi(p.Data["days"])
		r.reply(a.GetEventLog(p.Data["logname"], days, eventLogBudget(p.Timeout)))

	case "procs":
		r.reply(a.GetProcsRPC())

	case "killproc":
		r.reply(errOK(KillProc(p.ProcPID)))

	case "rawcmd":
		a.rpcRawCmd(r)

	case "runscript", "runscriptfull":
		a.rpcRunScript(r)

	case "registry_browse", "registry_create_key", "registry_delete_key", "registry_rename_key",
		"registry_create_value", "registry_delete_value", "registry_rename_value", "registry_modify_value":
		r.reply(registryRPC(p.Func, p.Data))

	case "winservices":
		r.reply(a.GetServices())
	case "winsvcdetail":
		r.reply(a.GetServiceDetail(p.Data["name"]))
	case "winsvcaction":
		r.reply(a.ControlService(p.Data["name"], p.Data["action"]))
	case "editwinsvc":
		r.reply(a.EditService(p.Data["name"], p.Data["startType"]))

	case "posixservices":
		svcs, err := PosixServices()
		if err != nil {
			r.reply(err.Error())
		} else {
			r.reply(svcs)
		}
	case "posixsvcaction":
		r.reply(errOK(PosixSvcAction(p.Data["name"], p.Data["action"])))
	case "posixlogs":
		logs, err := PosixLogs(p.Data)
		if err != nil {
			r.reply(err.Error())
		} else {
			r.reply(logs)
		}
	case "appupdates":
		res, err := AppUpdates(p.Data)
		if err != nil {
			r.reply(err.Error())
		} else {
			r.reply(res)
		}

	case "recover":
		if p.Data["mode"] == "mesh" {
			a.RecoverMesh()
		}
		r.reply("ok")

	case "softwarelist":
		r.reply(a.GetInstalledSoftware())

	case "shutdown", "rebootnow":
		r.reply("ok")
		a.powerAction(r.nc, p.Func == "rebootnow")

	case "suspend":
		r.reply("ok")
		a.NatsMessage(r.nc, "agent-wmi")
		_ = r.nc.Flush()
		time.Sleep(2 * time.Second)
		// an explicit suspend wins over keep-awake; stay awake on power
		// rests for 2 min so it does not hold the Mac right back
		if err := PauseKeepAwake(2 * time.Minute); err != nil {
			a.Logger.Debugln("PauseKeepAwake():", err)
		}
		// the server stores who sent the command, the agent adds no name
		_ = a.announcePower(r.nc, "sleep", "rmm", "", 2*time.Second)
		if err := a.Suspend(); err != nil {
			_ = a.announcePower(r.nc, "cancel", "rmm", "", 2*time.Second)
			a.Logger.Errorln("Suspend():", err)
			_ = PauseKeepAwake(0)
		}

	case "wakeonlan":
		r.reply(errOK(sendMagicPackets(p.Macs)))
	case "keepawake":
		r.reply(errOK(KeepAwake(p.Until)))
	case "keepawakeac":
		r.reply(errOK(KeepAwakeAC(p.AC)))
	case "idle":
		secs, err := UserIdle()
		if err != nil {
			r.reply(err.Error())
		} else {
			r.reply(secs)
		}
	case "needsreboot":
		needs, err := a.SystemRebootRequired()
		r.reply(err == nil && needs)

	case "sysinfo":
		// the server only waits for the go-ahead; agent-wmi alone can take
		// longer than its timeout
		r.reply("ok")
		for _, mode := range []string{"agent-agentinfo", "agent-disks", "agent-wmi", "agent-publicip"} {
			a.NatsMessage(r.nc, mode)
		}
	case "wmi":
		a.NatsMessage(r.nc, "agent-wmi")
	case "cpuloadavg":
		r.reply(a.GetCPULoadAvg())
	case "publicip":
		r.reply(a.PublicIP())

	case "runchecks":
		if a.ChecksRunning() {
			r.reply("busy")
			return
		}
		if runtime.GOOS == "windows" {
			r.reply("ok")
			if _, err := CMD(a.EXE, []string{"-m", "runchecks"}, checkRunnerCeiling); err != nil {
				a.Logger.Errorln("RPC RunChecks", err)
			}
			return
		}
		r.reply("ok")
		if err := a.RunChecks(true); err != nil {
			a.Logger.Debugln("RPC RunChecks", err)
		}
	case "runtask":
		if err := a.RunTask(p.TaskPK, false); err != nil {
			a.Logger.Debugln("RPC RunTask", err)
		}

	case "installnushell":
		a.InstallNushell(true)
	case "installchoco":
		a.InstallChoco()
	case "installpython":
		a.GetPython(true)
	case "installdeno":
		a.InstallDeno(true)
	case "installwithwinget":
		r.reply("ok")
		out, code := InstallWithWinget(p.WingetID)
		if err := a.postWingetResult(p.PendingActionPK, out, code); err != nil {
			a.Logger.Debugln("wingetresult:", err)
		}
	case "installwithchoco":
		r.reply("ok")
		out, err := a.InstallWithChoco(p.ChocoProgName)
		if err != nil {
			a.Logger.Errorln("InstallWithChoco():", err)
			if out == "" {
				out = err.Error()
			}
		}
		if err := a.postChocoResult(p.PendingActionPK, out); err != nil {
			a.Logger.Errorln("chocoresult:", err)
		}

	case "getwinupdates":
		if !getWinUpdRunning.CompareAndSwap(false, true) {
			a.Logger.Debugln("Already checking for windows updates")
			return
		}
		defer getWinUpdRunning.Store(false)
		a.GetWinUpdates(p.WUADrivers)
	case "installwinupdates":
		if !installWinUpdRunning.CompareAndSwap(false, true) {
			a.Logger.Debugln("Already installing windows updates")
			return
		}
		defer installWinUpdRunning.Store(false)
		a.InstallUpdates(p.UpdateGUIDs)

	case "drivers":
		r.reply("ok")
		a.SendDrivers(true)
	case "sdiodriver":
		job := p.Data["job"]
		ans := sdioAnswer(job, sdioSupported)
		r.reply(ans)
		if ans == "ok" {
			defer sdioMu.Unlock()
			a.runSdioJob(job, a.sdioHost())
		}
	case "pkgjob":
		job := p.Data["job"]
		ans := pkgAnswer(job)
		r.reply(ans)
		if ans == "ok" {
			defer pkgMu.Unlock()
			a.runPkgJob(job)
		}

	case "agentupdate":
		a.rpcAgentUpdate(r)

	case "uninstall":
		r.reply("ok")
		// the agent and its keepawake.json go, so nothing could undo a hold
		if err := PauseKeepAwake(time.Hour); err != nil {
			a.Logger.Debugln("PauseKeepAwake():", err)
		}
		expectStop(a.dataDir())
		a.AgentUninstall(p.Code)
		_ = r.nc.Flush()
		r.nc.Close()
		os.Exit(0)

	case "terminal_start", "terminal_input", "terminal_resize", "terminal_kill":
		a.rpcTerminal(r)

	default:
		// the caller would otherwise wait for its timeout
		r.reply("unknown request: " + p.Func)
	}
}

func errOK(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}

func panicReply(fn string) interface{} {
	const text = "the agent failed to run this request"
	switch {
	case strings.HasPrefix(fn, "registry_"):
		return map[string]interface{}{"error": text}
	case fn == "winsvcaction" || fn == "editwinsvc":
		return rmm.SvcActionResult{OK: false, Reason: text}
	}
	return text
}

func positiveTimeout(t int) int {
	if t <= 0 {
		return defaultCmdTimeout
	}
	return t
}

// windowsShell: rawcmd and task commands on Windows run through cmd or
// powershell only.
func windowsShell(shell string) bool {
	return shell == "cmd" || shell == "powershell"
}

func (a *Agent) rpcRawCmd(r *rpcReq) {
	p := r.p
	timeout := positiveTimeout(p.Timeout)
	shell, command, cmdID := p.Data["shell"], p.Data["command"], p.Data["cmd_id"]
	if p.Stream {
		subject := fmt.Sprintf("%s.cmdoutput.%s", a.AgentID, cmdID)
		r.framesOf(subject)
		defer frameModes.Delete(subject)
	}

	var result string
	if runtime.GOOS == "windows" {
		if !windowsShell(shell) {
			result = fmt.Sprintf("unsupported shell: %s", shell)
		} else {
			out, _ := CMDShell(shell, command, timeout, p.RunAsUser, p.Stream, &a.AgentID, &cmdID, r.nc)
			result = joinStreams(out[0], out[1])
		}
	} else {
		opts := a.NewCMDOpts()
		opts.Shell = nixShell(shell)
		opts.Command = command
		opts.Timeout = time.Duration(timeout)
		opts.Stream = p.Stream
		opts.RunAsUser = p.RunAsUser
		opts.Nc = r.nc
		opts.CmdID = cmdID
		out := a.CmdV2(opts)
		result = joinStreams(out.Stdout, out.Stderr)
	}
	r.reply(result)

	if p.ID != 0 {
		if err := a.patchHistResult(p.ID, rmm.CmdOutput{Text: result}); err != nil {
			a.Logger.Debugln("rawcmd histresult:", err)
		}
	}
}

var histRetryWait = 5 * time.Second

// patchHistResult stores a result in the command history, with one more try
// after a network error or a 5xx answer.
func (a *Agent) patchHistResult(id int, body interface{}) error {
	url := fmt.Sprintf(histResultURL, id, a.AgentID)
	var err error
	for try := 0; try < 2; try++ {
		if try > 0 {
			time.Sleep(histRetryWait)
		}
		r, perr := a.rClient.R().SetBody(body).Patch(url)
		switch {
		case perr != nil:
			err = perr
		case r.StatusCode() >= 500:
			err = fmt.Errorf("histresult answered %d", r.StatusCode())
		default:
			return nil
		}
	}
	return err
}

func (a *Agent) rpcRunScript(r *rpcReq) {
	p := r.p
	start := time.Now()
	stdout, stderr, retcode, err := a.RunScript(p.Data["code"], p.Data["shell"], p.ScriptArgs, positiveTimeout(p.Timeout),
		p.RunAsUser, p.EnvVars, p.NushellEnableConfig, p.DenoDefaultPermissions)
	res := rmm.ScriptRunResult{
		Out:      stdout,
		ErrOut:   stderr,
		ExitCode: retcode,
		Seconds:  time.Since(start).Seconds(),
		RunID:    p.ID,
	}
	if err != nil {
		// the setup codes (85 setup failed, 65 did not start) stay
		res.Out, res.ErrOut = "", err.Error()
		if res.ExitCode == 0 {
			res.ExitCode = 1
		}
	}

	if p.Func == "runscriptfull" {
		r.reply(res)
	} else if err != nil {
		r.reply(err.Error())
	} else {
		r.reply(stdout + stderr)
	}

	if p.ID != 0 {
		if err := a.patchHistResult(p.ID, map[string]interface{}{"script_results": res}); err != nil {
			a.Logger.Debugln(p.Func, "histresult:", err)
		}
	}
}

func (a *Agent) powerAction(nc *nats.Conn, reboot bool) {
	kind := "shutdown"
	if reboot {
		kind = "restart"
	}
	_ = a.announcePower(nc, kind, "rmm", "", 2*time.Second)
	if runtime.GOOS == "windows" {
		flag := "/s"
		if reboot {
			flag = "/r"
		}
		if _, err := CMD("shutdown.exe", []string{flag, "/t", "5", "/f"}, 15); err != nil {
			a.Logger.Errorln("shutdown.exe:", err)
		}
		return
	}
	opts := a.NewCMDOpts()
	opts.Command = "shutdown -h now"
	if reboot {
		opts.Command = "reboot"
	}
	if runtime.GOOS == "freebsd" {
		// -h halts without power off there; reboot(8) skips rc.shutdown
		opts.Command = "shutdown -p now"
		if reboot {
			opts.Command = "shutdown -r now"
		}
	}
	a.CmdV2(opts)
}

func (a *Agent) rpcAgentUpdate(r *rpcReq) {
	if !updateRunning.CompareAndSwap(false, true) {
		r.reply("updaterunning")
		return
	}
	// also after a recovered panic; the success path ends in os.Exit
	defer updateRunning.Store(false)
	r.reply("ok")
	p := r.p
	inno, link, version, sha := p.Data["inno"], p.Data["url"], p.Data["version"], p.updateSha256()
	refuse := func(why string) {
		a.Logger.Errorln("AgentUpdate(): refused:", why)
		a.queueSecurityEvent("update_refused", why)
	}
	if runtime.GOOS == "windows" && !plainFileName(inno) {
		refuse("installer name is not a plain file name")
		return
	}
	noop, err := a.checkUpdate(link, version, sha, p.Data["sig"])
	if err != nil {
		refuse(err.Error())
		return
	}
	if noop {
		a.Logger.Infoln("AgentUpdate(): already running", version)
		return
	}
	err = a.AgentUpdate(link, inno, version, sha)
	if errors.As(err, new(badDownload)) {
		refuse(err.Error())
		return
	}
	if err != nil {
		a.Logger.Errorln("AgentUpdate():", err)
		return
	}
	_ = r.nc.Flush()
	r.nc.Close()
	a.ControlService(winSvcName, "stop")
	os.Exit(0)
}

// joinStreams keeps stdout and appends stderr below it.
func joinStreams(stdout, stderr string) string {
	if stderr != "" {
		return stdout + "\n" + stderr
	}
	return stdout
}

// plainFileName accepts a bare file name, nothing that walks directories.
func plainFileName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\:`) && !strings.Contains(name, "..")
}

func (a *Agent) rpcTerminal(r *rpcReq) {
	p := r.p
	sid := p.Data["session_id"]
	if sid == "" {
		a.Logger.Errorln(p.Func, "without session_id")
		return
	}
	win := runtime.GOOS == "windows"
	switch p.Func {
	case "terminal_start":
		r.framesOf(fmt.Sprintf("%s.terminal.%s", a.AgentID, sid))
		shell := p.Data["shell"]
		var err error
		if win {
			if shell == "" {
				shell = "cmd"
			}
			err = StartTerminalSessionWindows(a.AgentID, a.ProgramDir, sid, shell, p.RunAsUser, r.nc, a.Logger)
		} else {
			if shell == "" {
				shell = "/bin/bash"
			}
			err = a.StartTerminalSession(sid, nixShell(shell), r.nc)
		}
		if err != nil {
			a.Logger.Errorln("terminal_start:", err)
			a.sendTerminalError(r.nc, sid, err.Error())
			forgetFrames(fmt.Sprintf("%s.terminal.%s", a.AgentID, sid), time.Minute)
		}
	case "terminal_input":
		data := p.Data["data"]
		if data == "" {
			return
		}
		var err error
		if win {
			err = FeedTerminalInputWindows(sid, data)
		} else {
			err = a.FeedTerminalInput(sid, data)
		}
		if err != nil {
			a.Logger.Errorln("terminal_input:", err)
		}
	case "terminal_resize":
		rows, err1 := strconv.Atoi(p.Data["rows"])
		cols, err2 := strconv.Atoi(p.Data["cols"])
		if err1 != nil || err2 != nil || rows <= 0 || cols <= 0 {
			a.Logger.Debugln("terminal_resize: ignoring size", p.Data["rows"], p.Data["cols"])
			return
		}
		var err error
		if win {
			err = ResizeTerminalSessionWindows(sid, rows, cols)
		} else {
			err = a.ResizeTerminalSession(sid, rows, cols)
		}
		if err != nil {
			a.Logger.Debugln("terminal_resize:", err)
		}
	case "terminal_kill":
		var err error
		if win {
			err = KillTerminalSessionWindows(sid)
		} else {
			err = a.KillTerminalSession(sid)
		}
		if err != nil {
			a.Logger.Debugln("terminal_kill:", err)
		}
		// the shell's last frame comes after the kill
		forgetFrames(fmt.Sprintf("%s.terminal.%s", a.AgentID, sid), time.Minute)
	}
}

const (
	registryPageSizeMax = 1000
	regKeyDenied        = "this registry key is protected and cannot be used from the dashboard"
)

// registryRPC checks the arguments of a registry func and runs it. The
// error texts of the checks are what the web UI already knows. A blank
// value name is the key's default value.
func registryRPC(fn string, d payloadMap) map[string]interface{} {
	fail := func(msg string) map[string]interface{} { return map[string]interface{}{"error": msg} }
	blank := func(k string) bool { return strings.TrimSpace(d[k]) == "" }
	path := d["path"]

	switch fn {
	case "registry_browse":
		if path == "" {
			return fail("missing path")
		}
		page, size := 1, 200
		if v, err := strconv.Atoi(d["page"]); err == nil {
			page = v
		}
		if v, err := strconv.Atoi(d["page_size"]); err == nil {
			size = v
		}
		if page < 1 {
			return fail("page must be 1 or higher")
		}
		if size < 1 || size > registryPageSizeMax {
			return fail(fmt.Sprintf("page_size must be between 1 and %d", registryPageSizeMax))
		}
		if regDenied(path, false, false) {
			return fail(regKeyDenied)
		}
		subkeys, values, more, err := BrowseRegistry(path, page, size)
		if err != nil {
			return fail(err.Error())
		}
		return map[string]interface{}{"path": path, "subkeys": subkeys, "values": values, "has_more": more}

	case "registry_create_key", "registry_delete_key":
		if blank("path") {
			return fail("Missing or empty path")
		}
		if r := regRootName(path); r != "" && fn == "registry_delete_key" {
			return fail(fmt.Sprintf("deleting root hive '%s' is not allowed", r))
		}
		if regDenied(path, true, fn == "registry_delete_key") {
			return fail(regKeyDenied)
		}
		var err error
		if fn == "registry_create_key" {
			err = CreateRegistryKey(path)
		} else {
			err = DeleteRegistryKey(path)
		}
		if err != nil {
			return fail(err.Error())
		}
		return map[string]interface{}{"success": true}

	case "registry_rename_key":
		oldPath, newPath := d["old_path"], d["new_path"]
		if blank("old_path") || blank("new_path") {
			return fail("Both old_path and new_path are required")
		}
		if oldPath == newPath {
			return fail("Old and new path cannot be the same")
		}
		if regDenied(oldPath, true, true) || regDenied(newPath, true, false) {
			return fail(regKeyDenied)
		}
		if err := RenameRegistryKey(oldPath, newPath); err != nil {
			return fail(err.Error())
		}
		return map[string]interface{}{"success": true}

	case "registry_create_value", "registry_modify_value":
		if blank("path") {
			return fail("Missing path")
		}
		if blank("type") {
			return fail("Missing value type")
		}
		if regDenied(path, true, false) {
			return fail(regKeyDenied)
		}
		name, typ := d["name"], d["type"]
		var res map[string]interface{}
		var err error
		if fn == "registry_create_value" {
			res, err = CreateRegistryValue(path, name, typ, d["data"])
		} else {
			res, err = ModifyRegistryValue(path, name, typ, d["data"])
		}
		if err != nil {
			return fail(err.Error())
		}
		out := map[string]interface{}{"status": "success", "name": name, "type": typ, "data": d["data"]}
		for _, k := range []string{"name", "type", "data"} {
			if v, ok := res[k]; ok {
				out[k] = v
			}
		}
		return out

	case "registry_delete_value":
		if blank("path") {
			return fail("Missing path")
		}
		if regDenied(path, true, false) {
			return fail(regKeyDenied)
		}
		if err := DeleteRegistryValue(path, d["name"]); err != nil {
			return fail(err.Error())
		}
		return map[string]interface{}{"status": "success", "name": d["name"]}

	case "registry_rename_value":
		if blank("path") {
			return fail("Missing path")
		}
		if blank("old_name") {
			return fail("Missing old_name")
		}
		if blank("new_name") {
			return fail("Missing new_name")
		}
		if regDenied(path, true, false) {
			return fail(regKeyDenied)
		}
		newName, err := RenameRegistryValue(path, d["old_name"], d["new_name"])
		if err != nil {
			return fail(err.Error())
		}
		return map[string]interface{}{"status": "success", "new_name": newName}
	}
	return fail("unknown registry function")
}
