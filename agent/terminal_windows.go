// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/fourcorelabs/wintoken"
	winpty "github.com/iamacarpet/go-winpty"
	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// Web terminals on Windows: a shell on a pseudo console (ConPTY, Windows 10
// 1809 and later) or on winpty for older versions. Output goes to
// <agentID>.terminal.<session>; terminal.go holds the posix side.

type winTerm struct {
	id      string
	agentID string
	nc      *nats.Conn
	log     *logrus.Logger

	in, out *os.File
	// proc is the shell; the exit watcher waits on its own duplicate
	proc windows.Handle
	// job ends everything in it when its handle is closed
	job windows.Handle

	mu  sync.Mutex // hpc and pty, so a resize never meets a closed console
	hpc windows.Handle
	pty *winpty.WinPTY

	lastUse atomic.Int64
	pumped  chan struct{}
	once    sync.Once
}

var winTerms = struct {
	sync.Mutex
	m       map[string]*winTerm
	pending map[string]termSize
	reaper  sync.Once
}{m: map[string]*winTerm{}, pending: map[string]termSize{}}

func termRoom(sid string) error {
	_, ok := winTerms.m[sid]
	return termRoomErr(sid, ok, len(winTerms.m))
}

func checkTermRoom(sid string) error {
	winTerms.Lock()
	defer winTerms.Unlock()
	return termRoom(sid)
}

// addTerm registers a started session and applies a size that came first.
func addTerm(t *winTerm) error {
	winTerms.Lock()
	if err := termRoom(t.id); err != nil {
		winTerms.Unlock()
		return err
	}
	winTerms.m[t.id] = t
	size, pending := takePendingSize(winTerms.pending, t.id)
	winTerms.Unlock()
	if pending {
		_ = t.resize(size.rows, size.cols)
	}
	winTerms.reaper.Do(func() { go reapIdleTerms() })
	return nil
}

func findTerm(sid string) *winTerm {
	winTerms.Lock()
	defer winTerms.Unlock()
	return winTerms.m[sid]
}

// takeTerm unregisters a session; nil when it was not registered.
func takeTerm(sid string) *winTerm {
	winTerms.Lock()
	defer winTerms.Unlock()
	t := winTerms.m[sid]
	delete(winTerms.m, sid)
	delete(winTerms.pending, sid)
	return t
}

func reapIdleTerms() {
	for range time.Tick(time.Minute) {
		var idle []string
		winTerms.Lock()
		for id, t := range winTerms.m {
			if time.Since(time.Unix(0, t.lastUse.Load())) > termIdleLimit {
				idle = append(idle, id)
			}
		}
		winTerms.Unlock()
		for _, id := range idle {
			_ = KillTerminalSessionWindows(id)
		}
	}
}

func (t *winTerm) touch() { t.lastUse.Store(time.Now().UnixNano()) }

func (t *winTerm) publish(v interface{}) error {
	return publishWinTerm(t.nc, t.agentID, t.id, v)
}

func publishWinTerm(nc *nats.Conn, agentID, sid string, v interface{}) error {
	return publishFrame(nc, fmt.Sprintf("%s.terminal.%s", agentID, sid), v)
}

func sendWinTermInfo(nc *nats.Conn, agentID, sid, msg string) {
	_ = publishWinTerm(nc, agentID, sid, map[string]interface{}{
		"output":     "[INFO] " + msg + "\r\n",
		"session_id": sid,
		"done":       false,
		"exit_code":  0,
	})
}

// StartTerminalSessionWindows starts the shell of a web terminal. Errors
// go back to the web terminal through the RPC layer.
func StartTerminalSessionWindows(agentID, programDir, sid, shell string, runAsUser bool, nc *nats.Conn, logger *logrus.Logger) error {
	if sid == "" {
		return errors.New("missing session_id")
	}
	if err := checkTermRoom(sid); err != nil {
		return err
	}
	t := &winTerm{id: sid, agentID: agentID, nc: nc, log: logger, pumped: make(chan struct{})}
	t.touch()
	if modkernel32.NewProc("CreatePseudoConsole").Find() == nil {
		return t.startConPTY(shell, runAsUser)
	}
	return t.startWinPTY(programDir, shell, runAsUser)
}

// termWorkDir is the agent's home directory (for SYSTEM the system profile)
// when it exists, else the current directory.
func termWorkDir() string {
	for _, d := range []string{os.Getenv("HOME"), os.Getenv("USERPROFILE"), os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")} {
		if d == "" {
			continue
		}
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	wd, _ := os.Getwd()
	return wd
}

func customShellExists(p string) error {
	st, err := os.Stat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("custom shell not found: %s", p)
	case err != nil:
		return fmt.Errorf("custom shell is not accessible: %s", p)
	case st.IsDir():
		return fmt.Errorf("custom shell is a directory: %s", p)
	}
	return nil
}

// newTermJob is a job object that ends all its processes when its last
// handle is closed.
func newTermJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info struct {
		Basic                 jobObjectBasicLimitInfo
		IO                    windows.IO_COUNTERS
		ProcessMemoryLimit    uintptr
		JobMemoryLimit        uintptr
		PeakProcessMemoryUsed uintptr
		PeakJobMemoryUsed     uintptr
	}
	info.Basic.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func dupHandle(h windows.Handle) (windows.Handle, error) {
	var d windows.Handle
	self := windows.CurrentProcess()
	err := windows.DuplicateHandle(self, h, self, &d, 0, false, windows.DUPLICATE_SAME_ACCESS)
	return d, err
}

func (t *winTerm) startConPTY(shell string, runAsUser bool) error {
	exe, err := termShellPath(shell, getCMDExe(), getPowershellExe())
	if err != nil {
		return err
	}
	if exe != getCMDExe() && exe != getPowershellExe() {
		exe = filepath.Clean(exe)
		if err := customShellExists(exe); err != nil {
			return err
		}
	}

	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, nil, 0); err != nil {
		return fmt.Errorf("CreatePipe: %w", err)
	}
	if err := windows.CreatePipe(&outR, &outW, nil, 0); err != nil {
		windows.CloseHandle(inR)
		windows.CloseHandle(inW)
		return fmt.Errorf("CreatePipe: %w", err)
	}
	t.in, t.out = os.NewFile(uintptr(inW), "conin"), os.NewFile(uintptr(outR), "conout")
	err = windows.CreatePseudoConsole(windows.Coord{X: termCols, Y: termRows}, inR, outW, 0, &t.hpc)
	// the console holds its own copies
	windows.CloseHandle(inR)
	windows.CloseHandle(outW)
	if err != nil {
		t.in.Close()
		t.out.Close()
		return fmt.Errorf("CreatePseudoConsole: %w", err)
	}
	started := false
	defer func() {
		if !started {
			close(t.pumped)
			t.cleanup()
		}
	}()

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return fmt.Errorf("ProcThreadAttributeList: %w", err)
	}
	defer attrs.Delete()
	// the attribute value is the console handle itself, not its address
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&t.hpc)), unsafe.Sizeof(t.hpc)); err != nil {
		return fmt.Errorf("ProcThreadAttributeList: %w", err)
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	// suspended until it is in the job, so no child can start outside it
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_SUSPENDED)
	cmdLine, dir := quoteCmdArg(exe), termWorkDir()

	var tok *wintoken.Token
	var env *uint16
	if runAsUser {
		tok, env, dir = userSession(t.log, dir)
		if tok == nil {
			sendWinTermInfo(t.nc, t.agentID, t.id, "Run as user was not available. Falling back to SYSTEM.")
		} else {
			defer tok.Close()
			defer DestroyEnvironmentBlock(env)
		}
	}

	var pi *windows.ProcessInformation
	if tok != nil {
		pi, err = CreateProcessAsUser(tok.Token(), cmdLine, false, flags, env, dir, &si.StartupInfo)
	} else {
		pi = new(windows.ProcessInformation)
		err = createProcess(cmdLine, flags, dir, &si.StartupInfo, pi)
	}
	if err != nil {
		return fmt.Errorf("CreateProcess: %w", err)
	}
	t.proc = pi.Process
	job, err := newTermJob()
	if err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		return fmt.Errorf("failed to create terminal cleanup guard: %w", err)
	}
	t.job = job
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		return fmt.Errorf("failed to assign terminal cleanup guard: %w", err)
	}
	_, rerr := windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)
	if rerr != nil {
		return fmt.Errorf("ResumeThread: %w", rerr)
	}
	if err := t.run(); err != nil {
		return err
	}
	started = true
	return nil
}

func createProcess(cmdLine string, flags uint32, dir string, si *windows.StartupInfo, pi *windows.ProcessInformation) error {
	cl, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return err
	}
	d, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if dir == "" {
		d = nil
	}
	return windows.CreateProcess(nil, cl, nil, nil, false, flags, nil, d, si, pi)
}

// userSession gets the signed-in user's token, environment block and
// profile directory; a nil token when any of it is missing.
func userSession(log *logrus.Logger, dir string) (*wintoken.Token, *uint16, string) {
	tok, err := getUserToken()
	if err != nil {
		log.Debugln("terminal run as user:", err)
		return nil, nil, dir
	}
	env, err := CreateEnvironmentBlock(tok.Token())
	if err != nil {
		log.Debugln("terminal run as user: environment:", err)
		tok.Close()
		return nil, nil, dir
	}
	if home, err := tok.Token().GetUserProfileDirectory(); err == nil && home != "" {
		dir = home
	}
	return tok, env, dir
}

func (t *winTerm) startWinPTY(programDir, shell string, runAsUser bool) error {
	if runAsUser {
		sendWinTermInfo(t.nc, t.agentID, t.id, "This EOL Windows version does not support remote terminal 'Run as user'. Continuing as SYSTEM.")
	}
	if _, err := EnsureWinPTY(programDir, false); err != nil {
		return err
	}
	exe := winptyShellPath(shell, getCMDExe(), getPowershellExe())
	pty, err := winpty.OpenWithOptions(winpty.Options{
		DLLPrefix:   programDir,
		Command:     quoteCmdArg(exe),
		Dir:         termWorkDir(),
		Env:         os.Environ(),
		InitialCols: termCols,
		InitialRows: termRows,
	})
	if err != nil {
		return fmt.Errorf("winpty open failed (%v)", err)
	}
	t.pty, t.in, t.out = pty, pty.StdIn, pty.StdOut
	// winpty closes its handle on Close, the session keeps its own; without
	// one nothing would see the shell exit
	d, err := dupHandle(windows.Handle(pty.GetProcHandle()))
	if err != nil {
		close(t.pumped)
		t.cleanup()
		return fmt.Errorf("winpty process handle: %w", err)
	}
	t.proc = d
	if canNestJobs() {
		if job, err := newTermJob(); err == nil {
			if windows.AssignProcessToJobObject(job, t.proc) == nil {
				t.job = job
			} else {
				windows.CloseHandle(job)
			}
		}
	}
	if err := t.run(); err != nil {
		close(t.pumped)
		t.cleanup()
		return err
	}
	return nil
}

// run registers the started session and starts its output pump and exit
// watcher.
func (t *winTerm) run() error {
	var wait windows.Handle
	if t.proc != 0 {
		d, err := dupHandle(t.proc)
		if err != nil {
			return fmt.Errorf("DuplicateHandle: %w", err)
		}
		wait = d
	}
	if err := addTerm(t); err != nil {
		if wait != 0 {
			windows.CloseHandle(wait)
		}
		return err
	}
	t.log.Debugln("Registered terminal session", t.id)
	go t.pump()
	go t.watch(wait)
	return nil
}

// pump forwards console output; a failed publish ends the session.
func (t *winTerm) pump() {
	defer close(t.pumped)
	if err := pumpTermOutput(t.out, func(b []byte) error { return t.publish(b) }, t.touch); err != nil {
		t.log.Debugln("terminal output:", err)
		go func() { _ = KillTerminalSessionWindows(t.id) }()
	}
}

// watch waits for the shell. When the session was still registered (no
// kill came first) the web terminal gets done with the exit code.
func (t *winTerm) watch(wait windows.Handle) {
	code := uint32(0)
	if wait != 0 {
		_, _ = windows.WaitForSingleObject(wait, windows.INFINITE)
		_ = windows.GetExitCodeProcess(wait, &code)
		windows.CloseHandle(wait)
	}
	registered := takeTerm(t.id) == t
	t.cleanup()
	t.log.Debugf("Terminal session %s exited with %d", t.id, code)
	if registered && wait != 0 {
		_ = t.publish(map[string]interface{}{"done": true, "exit_code": int(code)})
	}
}

// cleanup ends what is left of the session once: the job (the shell and
// everything it started), the pipes and the console. The output still in
// the console is read before its pipe is closed.
func (t *winTerm) cleanup() {
	t.once.Do(func() {
		if t.job != 0 {
			_ = windows.TerminateJobObject(t.job, 1)
			windows.CloseHandle(t.job)
		} else if t.proc != 0 {
			_ = windows.TerminateProcess(t.proc, 1)
		}
		if t.proc != 0 {
			windows.CloseHandle(t.proc)
		}
		if t.in != nil {
			t.in.Close()
		}
		t.mu.Lock()
		hpc, pty := t.hpc, t.pty
		t.hpc, t.pty = 0, nil
		t.mu.Unlock()
		if hpc != 0 {
			// it may wait until the pump has read the last output
			go windows.ClosePseudoConsole(hpc)
		}
		if pty != nil && t.job == 0 && t.proc == 0 {
			// no handle to the shell: closing winpty is what ends it
			pty.Close()
			pty = nil
		}
		select {
		case <-t.pumped:
		case <-time.After(terminalDrain):
		}
		if t.out != nil {
			t.out.Close()
		}
		if pty != nil {
			pty.Close()
		}
	})
}

func (t *winTerm) resize(rows, cols int) error {
	c, r := termDim(cols), termDim(rows)
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.hpc != 0:
		return windows.ResizePseudoConsole(t.hpc, windows.Coord{X: c, Y: r})
	case t.pty != nil:
		t.pty.SetSize(uint32(c), uint32(r))
	}
	return nil
}

func FeedTerminalInputWindows(sid, data string) error {
	t := findTerm(sid)
	if t == nil {
		return fmt.Errorf("session not found: %s", sid)
	}
	if t.in == nil {
		return fmt.Errorf("stdin pipe not initialized for session: %s", sid)
	}
	t.touch()
	_, err := t.in.Write([]byte(data))
	return err
}

// ResizeTerminalSessionWindows keeps a size that arrives before its session
// and applies it when the session starts.
func ResizeTerminalSessionWindows(sid string, rows, cols int) error {
	if rows <= 0 || cols <= 0 {
		return nil
	}
	winTerms.Lock()
	t, ok := winTerms.m[sid]
	if !ok {
		addPendingSize(winTerms.pending, sid, rows, cols, time.Now())
		winTerms.Unlock()
		return nil
	}
	winTerms.Unlock()
	return t.resize(rows, cols)
}

// KillTerminalSessionWindows ends a session; the web terminal gets one
// done with exit code -1 (as on Linux and macOS), the exit watcher stays
// quiet because the session is gone. An unknown session is no error.
func KillTerminalSessionWindows(sid string) error {
	if t := takeTerm(sid); t != nil {
		t.cleanup()
		_ = t.publish(map[string]interface{}{"done": true, "exit_code": -1})
	}
	return nil
}
