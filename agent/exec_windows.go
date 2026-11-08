// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/fourcorelabs/wintoken"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/sys/windows"
)

// SetDetached gives a child no console and its own process group.
func SetDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: detachedFlags}
}

// getUserToken is the token of the user at the console or in the active
// remote session: an administrator's elevated linked token when there is
// one, else the session's own token. The caller closes it.
func getUserToken() (*wintoken.Token, error) {
	tok, err := wintoken.GetInteractiveToken(wintoken.TokenLinked)
	if err == nil {
		return tok, nil
	}
	return wintoken.GetInteractiveToken(wintoken.TokenPrimary)
}

// winExec runs cmd, made with exec.CommandContext(ctx, ...), to its end.
// Where jobs nest, the process goes into a job object; at the deadline the
// job, so everything the child started, is terminated. A normal end leaves
// background children alone. err is a start failure (a *startError, code
// -1) or a wait failure, a non-zero exit status is only in code.
func winExec(ctx context.Context, cmd *exec.Cmd, stdout, stderr io.Writer) (code int, timedOut bool, err error) {
	var job windows.Handle
	if canNestJobs() {
		if j, err := windows.CreateJobObject(nil, nil); err == nil {
			job = j
			defer windows.CloseHandle(job)
		}
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Cancel = func() error {
		if job != 0 {
			_ = windows.TerminateJobObject(job, 1)
		}
		killTree(int32(cmd.Process.Pid))
		_ = cmd.Process.Kill()
		return nil
	}
	// a background child holding the pipes must not block the wait
	cmd.WaitDelay = cmdIODrain
	if err := cmd.Start(); err != nil {
		return -1, false, &startError{err}
	}
	if job != 0 {
		if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
			_ = windows.AssignProcessToJobObject(job, h)
			windows.CloseHandle(h)
		}
	}
	werr := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		return cmdTimeoutExit, true, ctx.Err()
	}
	var ee *exec.ExitError
	switch {
	case werr == nil || errors.Is(werr, exec.ErrWaitDelay):
		return cmd.ProcessState.ExitCode(), false, nil
	case errors.As(werr, &ee):
		return ee.ExitCode(), false, nil
	}
	return 1, false, werr
}

func canNestJobs() bool {
	v := windows.RtlGetVersion()
	return nestedJobs(v.MajorVersion, v.MinorVersion)
}

func secondsCtx(timeout int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(positiveTimeout(timeout))*time.Second)
}

// CMD runs exe with args. On any failure (start, non-zero exit, timeout)
// the output is dropped and the error carries the cleaned stderr; the
// mesh, shutdown and service callers rely on that.
func CMD(exe string, args []string, timeout int, detached bool) ([2]string, error) {
	ctx, cancel := secondsCtx(timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	if detached {
		cmd.SysProcAttr = SetDetached()
	}
	var stdout, stderr bytes.Buffer
	code, _, err := winExec(ctx, cmd, &stdout, &stderr)
	if err == nil && code != 0 {
		err = fmt.Errorf("exit status %d", code)
	}
	if err != nil {
		return [2]string{}, fmt.Errorf("%w: %s", err, CleanString(stderr.String()))
	}
	return [2]string{CleanString(stdout.String()), CleanString(stderr.String())}, nil
}

// CMDShell runs a command line through cmd or powershell, for rawcmd, task
// command actions and the power helpers. With stream set every output line
// also goes to <agentID>.cmdoutput.<cmdID>, then one done message with the
// exit code. It returns the cleaned output and the wait or timeout error.
func CMDShell(shell string, cmdArgs []string, command string, timeout int, detached, runAsUser, stream bool, agentID, cmdID *string, nc *nats.Conn) ([2]string, error) {
	argv, rawLine, err := cmdShellArgv(shell, cmdArgs, command, getCMDExe(), getPowershellExe())
	if err != nil {
		return [2]string{"", err.Error()}, err
	}
	ctx, cancel := secondsCtx(timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	attr := &syscall.SysProcAttr{CmdLine: rawLine}
	if detached {
		attr.CreationFlags |= detachedFlags
	}
	if runAsUser {
		tok, err := getUserToken()
		if err != nil {
			return [2]string{"", err.Error()}, err
		}
		defer tok.Close()
		attr.Token = syscall.Token(tok.Token())
		attr.CreationFlags |= windows.CREATE_NO_WINDOW
	}
	cmd.SysProcAttr = attr

	stdout, stderr := newCappedOutput(), newCappedOutput()
	var outW, errW io.Writer = stdout, stderr
	var publish func(v interface{})
	var outLines, errLines *lineCollector
	if stream && nc != nil && agentID != nil && cmdID != nil {
		subject := fmt.Sprintf("%s.cmdoutput.%s", *agentID, *cmdID)
		publish = func(v interface{}) { _ = publishFrame(nc, subject, v) }
		line := func(s string) { publish(CleanString(s)) }
		outLines, errLines = &lineCollector{onLine: line}, &lineCollector{onLine: line}
		outW, errW = io.MultiWriter(stdout, outLines), io.MultiWriter(stderr, errLines)
	}

	code, _, err := winExec(ctx, cmd, outW, errW)
	if publish != nil {
		outLines.text()
		errLines.text()
		publish(map[string]interface{}{"done": true, "exit_code": code})
	}
	if err == nil && code != 0 {
		err = fmt.Errorf("exit status %d", code)
	}
	return [2]string{CleanString(stdout.String()), CleanString(stderr.String())}, err
}

// RunScript writes the script to the work directory and runs it with the
// interpreter of shell. Exit codes: 85 setup failed, 65 the process did
// not start, 98 timeout, else the script's own. Run as user takes the
// signed-in user's token and the run-as-user directory.
func (a *Agent) RunScript(code, shell string, args []string, timeout int, runAsUser bool, envVars []string, nushellEnableConfig bool, denoDefaultPermissions string) (stdout, stderr string, exitcode int, e error) {
	setupFail := func(err error) (string, string, int, error) { return "", err.Error(), scriptSetupExit, err }
	timeout = positiveTimeout(timeout)

	if err := createWinTempDir(); err != nil {
		return setupFail(err)
	}
	var tok *wintoken.Token
	if runAsUser {
		var err error
		if tok, err = getUserToken(); err != nil {
			return "", "run as user: no logged in user: " + err.Error(), scriptSetupExit, nil
		}
		defer tok.Close()
	}
	f, err := os.CreateTemp(a.WinTmpDir, "ulrmm*"+scriptExt(shell))
	if err != nil {
		return setupFail(err)
	}
	script := f.Name()
	defer func() { os.Remove(script) }()
	_, err = f.WriteString(scriptText(shell, code))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && tok != nil {
		// written in the admins-only directory and moved with its own DACL,
		// so other users of the run-as-user directory never get to read it
		var dst string
		if dst, err = userScript(script, a.WinRunAsUserTmpDir, tok.Token()); err == nil {
			script = dst
		}
	}
	if err != nil {
		return setupFail(err)
	}

	bins := winScriptBins{
		powershell: getPowershellExe(),
		python:     a.PyBin,
		nu:         a.NuBin,
		deno:       a.DenoBin,
		nuConfDir:  filepath.Join(a.ProgramDir, "etc", "nushell"),
	}
	argv, env, needs, err := winScriptArgv(shell, script, bins, args, envVars, nushellEnableConfig, denoDefaultPermissions)
	if err != nil {
		return "", err.Error(), scriptStartExit, err
	}
	env = a.dropDeniedEnv(env)
	if needs != "" && !rmm.FileExists(needs) {
		a.Logger.Errorln("RunScript():", shell, "is not installed at", needs)
		return "", "File Not Found: " + needs, scriptSetupExit, nil
	}

	ctx, cancel := secondsCtx(timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if tok != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok.Token()), HideWindow: true}
		if len(env) > 0 {
			base, err := tok.Token().Environ(false)
			if err != nil {
				a.Logger.Debugln("RunScript(): user environment:", err)
				base = os.Environ()
			}
			cmd.Env = append(base, env...)
		}
	} else if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	out, errOut := newCappedOutput(), newCappedOutput()
	exitcode, timedOut, err := winExec(ctx, cmd, out, errOut)
	if err != nil && !timedOut {
		a.Logger.Debugln("RunScript():", err)
	}
	return scriptReply(CleanString(out.String()), CleanString(errOut.String()), exitcode, timedOut, err, timeout)
}

// userScript gives the script at path SYSTEM and Administrators full access
// and the token's user read and execute, nothing inherited, then moves it
// into dir. A move on the same volume keeps that DACL.
func userScript(path, dir string, tok windows.Token) (string, error) {
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	if err := setPathSecurity(path, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;"+u.User.Sid.String()+")"); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, filepath.Base(path))
	return dst, os.Rename(path, dst)
}
