// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"runtime"
	"strings"
	"sync"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// Check results go to PATCH /api/v3/checkrunner/ as JSON. Each one starts
// with resultHead; the server drops a result that lacks agent_id.

type resultHead struct {
	CheckID int    `json:"id"`
	AgentID string `json:"agent_id"`
}

func (a *Agent) checkHead(c rmm.CheckDef) resultHead { return resultHead{c.CheckID, a.AgentID} }

type DiskCheckResult struct {
	resultHead
	Info    string  `json:"more_info"`
	UsedPct float64 `json:"percent_used"`
	Found   bool    `json:"exists"`
}

// CPUMemResult serves the cpuload and the memory check.
type CPUMemResult struct {
	resultHead
	Pct int `json:"percent"`
}

type ScriptCheckResult struct {
	resultHead
	Out      string  `json:"stdout"`
	ErrOut   string  `json:"stderr"`
	ExitCode int     `json:"retcode"`
	Secs     float64 `json:"runtime"`
}

// WinSvcCheckResult also carries the container check.
type WinSvcCheckResult struct {
	resultHead
	Info  string `json:"more_info"`
	State string `json:"status"`
}

type EventLogCheckResult struct {
	resultHead
	Entries []rmm.EventEntry `json:"log"`
}

type PingCheckResult struct {
	resultHead
	State string `json:"status"`
	Text  string `json:"output"`
}

type HealthCheckResult struct {
	resultHead
	Health *Health `json:"health"`
}

// RunChecks runs all checks (force) or only the ones the server says are
// due.
func (a *Agent) RunChecks(force bool) error {
	endpoint := "checkrunner"
	if force {
		endpoint = "runchecks"
	}
	r, err := a.rClient.R().Get("/api/v3/" + a.AgentID + "/" + endpoint + "/")
	switch {
	case err != nil:
		return err
	case r.IsError():
		a.Logger.Debugln("Checkrunner response code:", r.StatusCode())
		return nil
	}
	var data rmm.CheckSet
	if err := json.Unmarshal(r.Body(), &data); err != nil {
		return err
	}

	var wg sync.WaitGroup
	run := func(name string, fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.guard(name, fn)
		}()
	}
	var winSvcChecks, eventLogChecks, healthChecks, containerChecks []rmm.CheckDef
	for _, c := range data.List {
		c := c
		switch c.Kind {
		case "diskspace":
			run("DiskCheck", func() { randomCheckDelay(); a.sendCheckResult(a.DiskCheck(c)) })
		case "cpuload":
			run("CPULoadCheck", func() { a.sendCheckResult(a.CPULoadCheck(c)) })
		case "memory":
			run("MemCheck", func() {
				randomCheckDelay()
				if res, ok := a.MemCheck(c); ok {
					a.sendCheckResult(res)
				}
			})
		case "ping":
			run("PingCheck", func() { randomCheckDelay(); a.sendCheckResult(a.PingCheck(c)) })
		case "script":
			run("ScriptCheck", func() { randomCheckDelay(); a.sendCheckResult(a.ScriptCheck(c)) })
		case "winsvc":
			winSvcChecks = append(winSvcChecks, c)
		case "eventlog":
			eventLogChecks = append(eventLogChecks, c)
		case "security", "hwhealth":
			healthChecks = append(healthChecks, c)
		case "systemd":
			run("SystemdCheck", func() { randomCheckDelay(); a.sendCheckResult(a.SystemdCheck(c)) })
		case "container":
			containerChecks = append(containerChecks, c)
		}
	}
	if len(winSvcChecks) > 0 {
		run("WinSvcCheck", func() {
			for _, c := range winSvcChecks {
				a.sendCheckResult(a.WinSvcCheck(c))
			}
		})
	}
	if len(eventLogChecks) > 0 {
		run("EventLogCheck", func() {
			for _, c := range eventLogChecks {
				a.sendCheckResult(a.EventLogCheck(c))
			}
		})
	}
	if len(healthChecks) > 0 {
		run("HealthCheck", func() {
			h := a.Health()
			for _, c := range healthChecks {
				a.sendCheckResult(HealthCheckResult{resultHead: a.checkHead(c), Health: h})
			}
		})
	}
	if len(containerChecks) > 0 {
		run("ContainerCheck", func() { a.ContainerChecks(containerChecks) })
	}
	wg.Wait()
	return nil
}

func (a *Agent) sendCheckResult(payload interface{}) {
	if _, err := a.rClient.R().SetBody(payload).Patch("/api/v3/checkrunner/"); err != nil {
		a.Logger.Debugln("check result:", err)
	}
}

func (a *Agent) DiskCheck(c rmm.CheckDef) DiskCheckResult {
	res := DiskCheckResult{resultHead: a.checkHead(c)}
	usage, err := statBounded(c.Drive, diskCheckWait)
	if err != nil {
		a.Logger.Debugln("DiskCheck():", err)
		res.Info = fmt.Sprintf("Disk %s does not exist", c.Drive)
		if errors.Is(err, errStatTimeout) {
			res.Info = fmt.Sprintf("Disk %s does not respond", c.Drive)
		}
		return res
	}
	res.Found = true
	res.UsedPct = usage.UsedPercent
	res.Info = fmt.Sprintf("Total: %s, Free: %s", ByteCountSI(usage.Total), ByteCountSI(usage.Free))
	return res
}

func (a *Agent) CPULoadCheck(c rmm.CheckDef) CPUMemResult {
	return CPUMemResult{resultHead: a.checkHead(c), Pct: a.GetCPULoadAvg()}
}

// Used memory in percent; false when it cannot be read.
func (a *Agent) MemCheck(c rmm.CheckDef) (CPUMemResult, bool) {
	total, used, err := memTotalUsed()
	if err != nil {
		a.Logger.Debugln("MemCheck():", err)
		return CPUMemResult{}, false
	}
	pct := int(math.Round(float64(used) / float64(total) * 100))
	return CPUMemResult{resultHead: a.checkHead(c), Pct: pct}, true
}

func (a *Agent) PingCheck(c rmm.CheckDef) PingCheckResult {
	res := PingCheckResult{resultHead: a.checkHead(c)}
	out, err := DoPing(c.Target)
	if err != nil {
		a.Logger.Debugln("PingCheck():", err)
		res.State, res.Text = "failing", err.Error()
		return res
	}
	res.State, res.Text = out.Status, out.Output
	return res
}

func (a *Agent) ScriptCheck(c rmm.CheckDef) ScriptCheckResult {
	res := ScriptCheckResult{resultHead: a.checkHead(c)}
	began := time.Now()
	res.Out, res.ErrOut, res.ExitCode, _ = a.RunScript(c.Script.Source, c.Script.Interp, c.Args, c.TimeoutSec,
		c.Script.AsUser, c.Env, c.NuConfig, c.DenoPerms)
	res.Secs = time.Since(began).Seconds()
	return res
}

func (a *Agent) WinSvcCheck(c rmm.CheckDef) WinSvcCheckResult {
	state, err := GetServiceStatus(c.Svc)
	status, info := winSvcVerdict(c, state, err, func() string {
		if !a.ControlService(c.Svc, "start").OK {
			return state
		}
		return waitSvcRunning(func() (string, error) { return GetServiceStatus(c.Svc) }, svcStartWait, 250*time.Millisecond)
	})
	return WinSvcCheckResult{resultHead: a.checkHead(c), Info: info, State: status}
}

var svcStartWait = 5 * time.Second

// the SCM accepts a start before the service runs; the last state seen
// within d counts
func waitSvcRunning(get func() (string, error), d, every time.Duration) string {
	deadline := time.Now().Add(d)
	for {
		state, err := get()
		if err == nil && state == "running" || time.Now().After(deadline) {
			return state
		}
		time.Sleep(every)
	}
}

// start is called only when the check may restart the service; it returns
// the state after the attempt.
func winSvcVerdict(c rmm.CheckDef, state string, err error, start func() string) (status, moreInfo string) {
	if err != nil {
		if c.OKIfMissing {
			return "passing", err.Error()
		}
		return "failing", err.Error()
	}
	ok := func(s string) bool { return s == "running" || s == "start_pending" && c.OKIfStarting }
	if !ok(state) && c.Restart {
		state = start()
	}
	if ok(state) {
		return "passing", "Status: " + state
	}
	return "failing", "Status: " + state
}

func (a *Agent) SystemdCheck(c rmm.CheckDef) WinSvcCheckResult {
	status, info := systemdUnitCheck(c)
	return WinSvcCheckResult{resultHead: a.checkHead(c), Info: info, State: status}
}

type unitState struct{ load, active, sub, restarts string }

// systemctl show -p LoadState -p ActiveState -p SubState -p NRestarts
func parseUnitShow(out string) unitState {
	var u unitState
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "LoadState":
			u.load = v
		case "ActiveState":
			u.active = v
		case "SubState":
			u.sub = v
		case "NRestarts":
			u.restarts = v
		}
	}
	return u
}

func (u unitState) info() string {
	s := u.active + "/" + u.sub
	if u.restarts != "" {
		s += ", restarts " + u.restarts
	}
	return s
}

// start is called once, only when the check may restart the unit.
func systemdVerdict(c rmm.CheckDef, have bool, st unitState, err error, start func() (unitState, error)) (status, moreInfo string) {
	fail := func(info string) (string, string) {
		if c.OKIfMissing {
			return "passing", info
		}
		return "failing", info
	}
	switch {
	case !have:
		return fail("systemd not available")
	case err != nil:
		return "failing", err.Error()
	case st.load == "not-found":
		return fail("Unit " + c.Svc + " not found")
	case st.active == "active" || st.active == "reloading":
		return "passing", st.info()
	case c.Restart:
		again, err := start()
		if err != nil {
			return "failing", st.info() + ", start failed: " + err.Error()
		}
		if again.active == "active" || again.active == "reloading" {
			return "passing", again.info()
		}
		return "failing", again.info()
	}
	return "failing", st.info()
}

func (a *Agent) EventLogCheck(c rmm.CheckDef) EventLogCheckResult {
	entries := a.GetEventLog(c.Log, c.Days, 0)
	return EventLogCheckResult{resultHead: a.checkHead(c), Entries: filterEventLog(c, entries)}
}

// Entries the check asks for; never nil.
func filterEventLog(c rmm.CheckDef, entries []rmm.EventEntry) []rmm.EventEntry {
	ret := []rmm.EventEntry{}
	for _, e := range entries {
		if e.Kind != c.EventKind {
			continue
		}
		if !c.AnyEvent && int(e.Code) != c.EventCode {
			continue
		}
		if c.EventSrc != "" && !strings.Contains(e.Src, c.EventSrc) {
			continue
		}
		if c.EventText != "" && !strings.Contains(e.Text, c.EventText) {
			continue
		}
		ret = append(ret, e)
	}
	return ret
}

type taskResult struct {
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	Retcode  int     `json:"retcode"`
	ExecTime float64 `json:"execution_time"`
}

// Scheduled runs (-m taskrunner) wait a random bit first so a fleet does not
// start at the same second.
func (a *Agent) RunTask(id int, jitter bool) error {
	if jitter {
		d := time.Duration(mrand.Int63n(int64(15 * time.Second)))
		a.Logger.Debugf("Applying startup jitter before task id %d: %v", id, d)
		time.Sleep(d)
	}
	url := fmt.Sprintf("/api/v3/%d/%s/taskrunner/", id, a.AgentID)
	var task rmm.TaskDef
	reason := ""
	r, err := a.rClient.R().Get(url)
	switch {
	case err != nil:
		reason = "the server could not be reached"
	case r.IsError():
		reason = fmt.Sprintf("the server answered %d", r.StatusCode())
	case json.Unmarshal(r.Body(), &task) != nil:
		reason = "the task data could not be read"
	}
	var res taskResult
	if reason != "" {
		// without an answer the run stays "running" on the server
		a.Logger.Debugln("Run Task:", reason, err)
		res = taskResult{Stderr: "The agent could not load the task: " + reason, Retcode: 1}
	} else {
		res = a.runTaskActions(task)
	}
	if err := a.patchWithRetry(url, res, pkgRetryWait); err != nil {
		a.Logger.Debugln("RunTask() patch:", err)
		return err
	}
	return nil
}

func (a *Agent) runTaskActions(task rmm.TaskDef) taskResult {
	var res taskResult
	start := time.Now()
	multi := len(task.Steps) > 1
	for _, act := range task.Steps {
		actStart := time.Now()
		var stdout, stderr string
		var stop bool
		switch act.Kind {
		case "script":
			var err error
			stdout, stderr, res.Retcode, err = a.RunScript(act.Source, act.Interp, act.Params, act.TimeoutSec,
				act.AsUser, act.Env, act.NuConfig, act.DenoPerms)
			if err != nil {
				a.Logger.Debugln("RunTask() script:", err)
			}
			if multi {
				res.Stdout += taskHeader("Script", act.ScriptTitle, actStart)
			}
			// stderr output ends the task, not the exit code; tasks rely on it
			stop = !task.KeepGoing && stderr != ""
		case "cmd":
			stdout, stderr, res.Retcode = a.runTaskCommand(act)
			if multi {
				res.Stdout += taskHeader("Command", act.Cmd, actStart)
			}
			stop = !task.KeepGoing && res.Retcode != 0
		default:
			a.Logger.Debugln("Invalid Action", act.Kind)
			continue
		}
		res.Stdout += stdout
		res.Stderr += stderr
		if stop {
			break
		}
	}
	res.ExecTime = time.Since(start).Seconds()
	return res
}

func taskHeader(kind, name string, start time.Time) string {
	return fmt.Sprintf("\n------------\nRunning %s: %s. Execution Time: %f\n------------\n\n", kind, name, time.Since(start).Seconds())
}

// runTaskCommand: on Windows any stderr output counts as failure.
func (a *Agent) runTaskCommand(act rmm.TaskStep) (stdout, stderr string, retcode int) {
	if runtime.GOOS == "windows" {
		if !windowsShell(act.Interp) {
			return "", fmt.Sprintf("unsupported shell: %s", act.Interp), 1
		}
		out, err := CMDShell(act.Interp, []string{}, act.Cmd, act.TimeoutSec, false, act.AsUser, false, nil, nil, nil)
		if err != nil {
			a.Logger.Debugln("RunTask() cmd:", err)
		}
		if out[1] != "" {
			retcode = 1
		}
		return out[0], out[1], retcode
	}
	opts := a.NewCMDOpts()
	opts.Shell = act.Interp
	opts.Command = act.Cmd
	opts.Timeout = time.Duration(act.TimeoutSec)
	opts.RunAsUser = act.AsUser
	out := a.CmdV2(opts)
	return out.Stdout, out.Stderr, out.Status.Exit
}
