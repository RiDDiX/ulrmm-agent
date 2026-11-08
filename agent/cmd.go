// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	nats "github.com/nats-io/nats.go"
)

// CmdOptions describes one command for CmdV2. Timeout counts seconds even
// though it is a Duration (installed callers set it that way).
type CmdOptions struct {
	Shell, Command string
	Args, EnvVars  []string
	Timeout        time.Duration

	IsScript, IsExecutable, Detached bool

	// Stream publishes output lines on Nc under CmdID
	Stream bool
	Nc     *nats.Conn
	CmdID  string
	// RunAsUser runs the command as the signed-in user instead of root
	RunAsUser bool
	user      *runAs
}

// runAs is the account a command runs as (unix only).
type runAs struct {
	name     string
	uid, gid uint32
	groups   []uint32
	home     string
}

type ExitStatus struct {
	Exit  int
	Error error
	PID   int
}

type CmdStatus struct {
	Status ExitStatus
	Stdout string
	Stderr string
}

const (
	defaultCmdTimeout = 60
	cmdTimeoutExit    = 98
	cmdIODrain        = 5 * time.Second
)

// startCmd is replaced in tests to simulate ETXTBSY.
var startCmd = (*exec.Cmd).Start

// nixShell: /bin/sh for "sh", and for /bin/bash where there is none
// (FreeBSD, Alpine). Anything else is the caller's.
func nixShell(shell string) string {
	if shell == "sh" || (shell == "/bin/bash" && !rmm.FileExists(shell)) {
		return "/bin/sh"
	}
	return shell
}

func (a *Agent) NewCMDOpts() *CmdOptions {
	return &CmdOptions{Shell: "/bin/bash", Timeout: defaultCmdTimeout}
}

// CmdV2 runs a command on Linux and macOS and collects its output line by
// line. Modes: IsScript runs Shell with Args, IsExecutable runs Shell with
// Command as its only argument, otherwise Shell (which may carry leading
// arguments) gets "-c Command". The child gets its own process group; on
// timeout the whole group and every descendant is killed and the result has
// exit code 98.
func (a *Agent) CmdV2(c *CmdOptions) CmdStatus {
	secs := int(c.Timeout)
	if secs <= 0 {
		secs = defaultCmdTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()

	var stream func(string)
	if c.Stream && c.Nc != nil {
		subject := fmt.Sprintf("%s.cmdoutput.%s", a.AgentID, c.CmdID)
		stream = func(line string) {
			_ = publishFrame(c.Nc, subject, CleanString(line))
		}
	}

	stdout, stderr := &lineCollector{onLine: stream}, &lineCollector{onLine: stream}
	var cmd *exec.Cmd
	var err, userErr error
	if c.RunAsUser && c.user == nil {
		c.user, userErr = sessionRunAs()
		err = userErr
	}
	// a script written a moment ago can still be open for writing (ETXTBSY)
	for attempt := 1; userErr == nil; attempt++ {
		stdout, stderr = &lineCollector{onLine: stream}, &lineCollector{onLine: stream}
		cmd = a.buildCmd(ctx, c)
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err = startCmd(cmd); err == nil || !errors.Is(err, syscall.ETXTBSY) || attempt == 5 {
			break
		}
		a.Logger.Debugln("CmdV2 syscall.ETXTBSY, retrying...")
		time.Sleep(500 * time.Millisecond)
	}

	var res CmdStatus
	timedOut := false
	if err != nil {
		res.Status = ExitStatus{Exit: -1, Error: err}
	} else {
		res.Status.PID = cmd.Process.Pid
		werr := cmd.Wait()
		timedOut = ctx.Err() == context.DeadlineExceeded
		switch {
		case timedOut:
			a.Logger.Debugf("Command timed out after %d seconds", secs)
			res.Status.Exit = cmdTimeoutExit
		case werr == nil || errors.Is(werr, exec.ErrWaitDelay):
			res.Status.Exit = cmd.ProcessState.ExitCode()
		default:
			var ee *exec.ExitError
			if errors.As(werr, &ee) && ee.ExitCode() >= 0 {
				res.Status.Exit = ee.ExitCode()
			} else {
				res.Status = ExitStatus{Exit: -1, Error: werr, PID: res.Status.PID}
			}
		}
		if !timedOut {
			a.Logger.Debugln("CmdV2 exit code:", res.Status.Exit)
		}
	}

	res.Stdout = CleanString(stdout.text())
	res.Stderr = CleanString(stderr.text())
	if userErr != nil {
		res.Stderr = userErr.Error()
	}
	if timedOut {
		res.Stderr += fmt.Sprintf("\nTimed out after %d seconds", secs)
	}
	if stream != nil {
		_ = publishFrame(c.Nc, fmt.Sprintf("%s.cmdoutput.%s", a.AgentID, c.CmdID), map[string]interface{}{"done": true, "exit_code": res.Status.Exit})
	}
	return res
}

func (a *Agent) buildCmd(ctx context.Context, c *CmdOptions) *exec.Cmd {
	var cmd *exec.Cmd
	switch {
	case c.IsScript:
		cmd = exec.CommandContext(ctx, c.Shell, c.Args...)
	case c.IsExecutable:
		cmd = exec.CommandContext(ctx, c.Shell, c.Command)
	default:
		argv := strings.Fields(c.Shell)
		if len(argv) == 0 || (argv[0] == "/bin/bash" && !rmm.FileExists("/bin/bash")) {
			// no shell given, or a host without bash (Alpine, busybox)
			argv = []string{"/bin/sh"}
		}
		argv = append(argv, "-c", c.Command)
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
	}
	if len(c.EnvVars) > 0 {
		cmd.Env = append(os.Environ(), c.EnvVars...)
	}
	setProcGroup(cmd, c.Detached)
	if c.user != nil {
		applyRunAs(cmd, c.user)
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		a.Logger.Debugln("Killing process with PID", cmd.Process.Pid)
		killProcGroup(cmd.Process.Pid)
		killTree(int32(cmd.Process.Pid))
		return nil
	}
	// a killed child can leave a grandchild holding the pipes open
	cmd.WaitDelay = cmdIODrain
	return cmd
}

// What the reply keeps of each stream: the first and the last part, the
// middle is replaced by a marker. A streamed command still sends every line.
var (
	cmdKeepHead = 2 << 20
	cmdKeepTail = 2 << 20
)

// lineCollector gathers output as lines ending in "\n" (a missing last
// newline is added, a trailing "\r" dropped) and hands each line to onLine.
type lineCollector struct {
	mu      sync.Mutex
	head    strings.Builder
	tail    []byte
	dropped int
	partial []byte
	onLine  func(string)
}

func (l *lineCollector) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			l.partial = append(l.partial, p...)
			// output that never ends a line (head -c of /dev/zero) is kept in pieces
			if len(l.partial) >= cmdKeepTail {
				l.addLine(string(l.partial))
				l.partial = l.partial[:0]
			}
			return n, nil
		}
		l.partial = append(l.partial, p[:i]...)
		l.addLine(string(l.partial))
		l.partial = l.partial[:0]
		p = p[i+1:]
	}
}

func (l *lineCollector) addLine(line string) {
	line = strings.TrimSuffix(line, "\r")
	if l.onLine != nil {
		l.onLine(line)
	}
	if l.tail == nil && l.head.Len()+len(line)+1 <= cmdKeepHead {
		l.head.WriteString(line)
		l.head.WriteByte('\n')
		return
	}
	l.tail = append(append(l.tail, line...), '\n')
	// trimmed in steps, not per line
	if len(l.tail) > 2*cmdKeepTail {
		l.trimTail()
	}
}

// trimTail keeps the last cmdKeepTail bytes, from a line start when one is
// in reach.
func (l *lineCollector) trimTail() {
	if len(l.tail) <= cmdKeepTail {
		return
	}
	cut := len(l.tail) - cmdKeepTail
	if i := bytes.IndexByte(l.tail[cut:], '\n'); i >= 0 && cut+i+1 < len(l.tail) {
		cut += i + 1
	}
	l.dropped += cut
	l.tail = append(l.tail[:0], l.tail[cut:]...)
}

// text flushes an unterminated last line and returns what was kept.
func (l *lineCollector) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.partial) > 0 {
		l.addLine(string(l.partial))
		l.partial = nil
	}
	l.trimTail()
	if l.dropped == 0 {
		return l.head.String() + string(l.tail)
	}
	return fmt.Sprintf("%s[... %d bytes of output left out ...]\n%s", l.head.String(), l.dropped, l.tail)
}
