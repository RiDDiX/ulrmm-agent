// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

func sh(a *Agent, command string, timeout int) CmdStatus {
	opts := a.NewCMDOpts()
	opts.Shell = "/bin/sh"
	opts.Command = command
	opts.Timeout = time.Duration(timeout)
	return a.CmdV2(opts)
}

func TestCmdV2Output(t *testing.T) {
	a := testUpdateAgent()
	out := sh(a, `printf 'a\r\nb'; printf 'err' 1>&2; exit 3`, 10)
	if out.Stdout != "a\nb\n" || out.Stderr != "err\n" || out.Status.Exit != 3 || out.Status.Error != nil {
		t.Fatalf("got %+v", out)
	}
	if out := sh(a, "true", 10); out.Stdout != "" || out.Status.Exit != 0 {
		t.Fatalf("empty output: %+v", out)
	}
	// the old line reader stopped at 16 KiB
	long := sh(a, "head -c 20000 /dev/zero | tr '\\000' x", 10)
	if len(long.Stdout) != 20001 {
		t.Fatalf("long line cut to %d bytes", len(long.Stdout))
	}
	if out := sh(a, `printf 'a\000b\377c'`, 10); out.Stdout != "abc\n" {
		t.Fatalf("not cleaned: %q", out.Stdout)
	}
}

func TestCmdV2Modes(t *testing.T) {
	a := testUpdateAgent()
	opts := a.NewCMDOpts()
	opts.IsScript, opts.Shell, opts.Args = true, "/bin/echo", []string{"x y", "z"}
	if out := a.CmdV2(opts); out.Stdout != "x y z\n" {
		t.Fatalf("script mode: %q", out.Stdout)
	}
	opts = a.NewCMDOpts()
	opts.IsExecutable, opts.Shell, opts.Command = true, "/bin/echo", "one arg"
	if out := a.CmdV2(opts); out.Stdout != "one arg\n" {
		t.Fatalf("executable mode: %q", out.Stdout)
	}
	opts = a.NewCMDOpts()
	opts.IsScript, opts.Shell = true, "/nonexistent/prog"
	if out := a.CmdV2(opts); out.Status.Exit != -1 || out.Status.Error == nil {
		t.Fatalf("start failure: %+v", out)
	}
	opts = a.NewCMDOpts()
	opts.Shell, opts.Command, opts.EnvVars = "/bin/sh", "echo $ULRMM_TEST_VAR", []string{"ULRMM_TEST_VAR=1"}
	if out := a.CmdV2(opts); out.Stdout != "1\n" {
		t.Fatalf("env: %q", out.Stdout)
	}
}

func TestCmdV2TimeoutKillsTree(t *testing.T) {
	a := testUpdateAgent()
	pidFile := filepath.Join(t.TempDir(), "pid")
	start := time.Now()
	out := sh(a, "echo before; (sleep 30 & echo $! > "+pidFile+"; wait) ; sleep 30", 1)
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("timeout took %v", took)
	}
	if out.Status.Exit != 98 || !strings.HasSuffix(out.Stderr, "\nTimed out after 1 seconds") || out.Stdout != "before\n" {
		t.Fatalf("got %+v", out)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	time.Sleep(200 * time.Millisecond)
	if alive(pid) {
		t.Fatalf("grandchild %d survived the timeout", pid)
	}
}

// alive: a zombie waiting for its reaper counts as dead
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	return len(f) == 0 || f[0] != "Z"
}

func TestCmdV2RetriesETXTBSY(t *testing.T) {
	calls := 0
	startCmd = func(c *exec.Cmd) error {
		if calls++; calls < 3 {
			return &os.PathError{Op: "fork/exec", Path: c.Path, Err: syscall.ETXTBSY}
		}
		return c.Start()
	}
	defer func() { startCmd = (*exec.Cmd).Start }()
	out := sh(testUpdateAgent(), "echo ok", 10)
	if calls != 3 || out.Stdout != "ok\n" || out.Status.Exit != 0 || out.Status.Error != nil {
		t.Fatalf("calls=%d out=%+v", calls, out)
	}
}

func TestCmdV2ZeroTimeoutIsDefault(t *testing.T) {
	if out := sh(testUpdateAgent(), "echo ok", 0); out.Status.Exit != 0 || out.Stdout != "ok\n" {
		t.Fatalf("timeout 0: %+v", out)
	}
}

func TestLineCollector(t *testing.T) {
	var lines []string
	l := &lineCollector{onLine: func(s string) { lines = append(lines, s) }}
	for _, p := range []string{"ab", "c\nd", "\r\n\n", "tail"} {
		l.Write([]byte(p))
	}
	if got := l.text(); got != "abc\nd\n\ntail\n" {
		t.Fatalf("text %q", got)
	}
	if strings.Join(lines, "|") != "abc|d||tail" {
		t.Fatalf("lines %q", lines)
	}
}

func TestLineCollectorKeepsHeadAndTail(t *testing.T) {
	oh, ot := cmdKeepHead, cmdKeepTail
	cmdKeepHead, cmdKeepTail = 10, 8
	defer func() { cmdKeepHead, cmdKeepTail = oh, ot }()
	streamed := 0
	l := &lineCollector{onLine: func(string) { streamed++ }}
	for i := 0; i < 100; i++ {
		fmt.Fprintf(l, "l%02d\n", i)
	}
	got := l.text()
	if streamed != 100 {
		t.Fatalf("streamed %d lines, want all 100", streamed)
	}
	// head: two lines of 4 bytes, tail: the last two, the rest counted
	if want := "l00\nl01\n[... 384 bytes of output left out ...]\nl98\nl99\n"; got != want {
		t.Fatalf("text %q, want %q", got, want)
	}
	small := &lineCollector{}
	small.Write([]byte("short\n"))
	if small.text() != "short\n" {
		t.Fatal("output under the limit changed")
	}
}

func TestRunAsEnv(t *testing.T) {
	u := &runAs{name: "alice", home: "/home/alice"}
	got := runAsEnv([]string{"PATH=/bin", "HOME=/root", "USER=root", "LOGNAME=root", "XDG_RUNTIME_DIR=/run/user/0", "LANG=C"}, u)
	want := []string{"PATH=/bin", "LANG=C", "HOME=/home/alice", "USER=alice", "LOGNAME=alice"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("env %q", got)
	}
}

func TestCmdV2RunAsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	u, err := lookupRunAs("nobody")
	if err != nil {
		t.Skip("no user nobody:", err)
	}
	a := testUpdateAgent()
	opts := a.NewCMDOpts()
	opts.Shell = "/bin/sh"
	opts.Command = `id -un; echo "$HOME"`
	opts.RunAsUser, opts.user = true, u
	out := a.CmdV2(opts)
	if want := "nobody\n" + u.home + "\n"; out.Stdout != want || out.Status.Exit != 0 {
		t.Fatalf("as nobody: %+v", out)
	}

	// a script handed to the user must be readable for it
	a.UnixTmpDir = t.TempDir()
	os.Chmod(a.UnixTmpDir, 0o711)
	os.Chmod(filepath.Dir(a.UnixTmpDir), 0o711)
	f, _ := createNixTmpFile(a.UnixTmpDir)
	f.WriteString("#!/bin/sh\nid -u\n")
	f.Close()
	os.Chmod(f.Name(), 0o770)
	os.Chown(f.Name(), int(u.uid), int(u.gid))
	opts = a.NewCMDOpts()
	opts.IsScript, opts.Shell = true, f.Name()
	opts.RunAsUser, opts.user = true, u
	if out := a.CmdV2(opts); out.Stdout != strconv.Itoa(int(u.uid))+"\n" {
		t.Fatalf("script as nobody: %+v", out)
	}
}

func TestRunAsUserWithNobodyLoggedIn(t *testing.T) {
	if sessionUser() != "" {
		t.Skip("someone is logged in here")
	}
	a := testUpdateAgent()
	a.UnixTmpDir = t.TempDir()
	_, stderr, code, err := a.RunScript("#!/bin/sh\necho hi", "shell", nil, 10, true, nil, false, "")
	if err != errNobodyLoggedIn || stderr != errNobodyLoggedIn.Error() || code == 0 {
		t.Fatalf("script: %q %d %v", stderr, code, err)
	}
	opts := a.NewCMDOpts()
	opts.Shell, opts.Command, opts.RunAsUser = "/bin/sh", "echo hi", true
	if out := a.CmdV2(opts); out.Stdout != "" || out.Stderr != errNobodyLoggedIn.Error() || out.Status.Exit != -1 {
		t.Fatalf("command: %+v", out)
	}
	if u := a.LoggedOnUser(); u != "None" {
		t.Fatalf("LoggedOnUser = %q, want None", u)
	}
}

func TestRunTaskActions(t *testing.T) {
	a := testUpdateAgent()
	a.UnixTmpDir = t.TempDir()
	script := func(name, code string) rmm.TaskStep {
		return rmm.TaskStep{Kind: "script", ScriptTitle: name, Interp: "shell", Source: code, TimeoutSec: 30}
	}
	task := rmm.TaskDef{Steps: []rmm.TaskStep{
		script("one", "#!/bin/sh\necho one\necho warn >&2\nexit 4"),
		script("two", "#!/bin/sh\necho two"),
	}}
	res := a.runTaskActions(task)
	if strings.Contains(res.Stdout, "two") || !strings.Contains(res.Stdout, "Running Script: one. Execution Time: ") || res.Retcode != 4 || res.Stderr != "warn\n" {
		t.Fatalf("stop on stderr: %+v", res)
	}

	task.KeepGoing = true
	res = a.runTaskActions(task)
	if !strings.Contains(res.Stdout, "Running Script: two") || !strings.HasSuffix(res.Stdout, "two\n") || res.Retcode != 0 {
		t.Fatalf("continue on error: %+v", res)
	}

	task = rmm.TaskDef{Steps: []rmm.TaskStep{
		{Kind: "cmd", Interp: "/bin/sh", Cmd: "echo c; exit 2", TimeoutSec: 10},
		{Kind: "foo"},
		script("never", "#!/bin/sh\necho never"),
	}}
	res = a.runTaskActions(task)
	if res.Retcode != 2 || strings.Contains(res.Stdout, "never") || !strings.Contains(res.Stdout, "Running Command: echo c; exit 2") {
		t.Fatalf("failing cmd: %+v", res)
	}

	single := a.runTaskActions(rmm.TaskDef{Steps: []rmm.TaskStep{script("s", "#!/bin/sh\necho s")}})
	if single.Stdout != "s\n" {
		t.Fatalf("a single action has no header: %q", single.Stdout)
	}
}

func TestRunTaskReports(t *testing.T) {
	var report map[string]interface{}
	notFound := false
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/9/agent1/taskrunner/" {
			t.Errorf("path %s", r.URL.Path)
		}
		switch {
		case r.Method == http.MethodGet && notFound:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet:
			w.Write([]byte(`{"id": 9, "continue_on_error": false, "task_actions": [{"type": "cmd", "shell": "/bin/sh", "command": "echo hi", "timeout": 10}]}`))
		default:
			json.NewDecoder(r.Body).Decode(&report)
		}
	})
	if err := a.RunTask(9, false); err != nil {
		t.Fatal(err)
	}
	if report["stdout"] != "hi\n" || report["retcode"] != 0.0 || report["execution_time"] == nil || len(report) != 4 {
		t.Fatalf("report %v", report)
	}
	// a task the agent cannot load is reported, else the run stays open
	report, notFound = nil, true
	if err := a.RunTask(9, false); err != nil || report["retcode"] != 1.0 || report["stderr"] != "The agent could not load the task: the server answered 404" {
		t.Fatalf("404: %v %v", err, report)
	}
}

func TestKillProcTree(t *testing.T) {
	a := testUpdateAgent()
	pidFile := filepath.Join(t.TempDir(), "pids")
	done := make(chan CmdStatus)
	go func() { done <- sh(a, "sleep 30 & echo $$ $! > "+pidFile+"; wait", 30) }()
	var pids []string
	for i := 0; i < 50 && len(pids) < 2; i++ {
		time.Sleep(100 * time.Millisecond)
		b, _ := os.ReadFile(pidFile)
		pids = strings.Fields(string(b))
	}
	if len(pids) < 2 {
		t.Fatal("test shell did not start")
	}
	parent, _ := strconv.Atoi(pids[0])
	child, _ := strconv.Atoi(pids[1])
	if err := KillProc(int32(parent)); err != nil {
		t.Fatal(err)
	}
	<-done
	time.Sleep(200 * time.Millisecond)
	if alive(child) {
		t.Fatalf("child %d survived", child)
	}

	for _, pid := range []int32{0, 1, int32(os.Getpid())} {
		if KillProc(pid) == nil {
			t.Fatalf("pid %d was not refused", pid)
		}
	}
}
