// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Argument building and checks with no Windows API, so the Linux test run covers them.

// scriptExt is the file extension Windows needs to run a script of shell.
func scriptExt(shell string) string {
	switch shell {
	case "powershell":
		return ".ps1"
	case "python":
		return ".py"
	case "cmd":
		return ".bat"
	case "nushell":
		return ".nu"
	case "deno":
		return ".ts"
	}
	return ""
}

type winScriptBins struct {
	powershell, python, nu, deno string
	// directory of config.nu and env.nu
	nuConfDir string
}

// winScriptArgv is the command line for a script file and the extra
// environment that goes with it (a DENO_PERMISSIONS entry is taken out and
// becomes deno flags). needs names a runtime that has to exist first.
func winScriptArgv(shell, script string, bins winScriptBins, args, env []string, nuConfig bool, denoDefaults string) (argv, outEnv []string, needs string, err error) {
	switch shell {
	case "powershell":
		argv = []string{bins.powershell, "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}
	case "python":
		argv = []string{bins.python, script}
	case "cmd":
		argv = []string{script}
	case "nushell":
		argv, needs = []string{bins.nu}, bins.nu
		if nuConfig {
			argv = append(argv, "--config", bins.nuConfDir+`\config.nu`, "--env-config", bins.nuConfDir+`\env.nu`)
		} else {
			argv = append(argv, "--no-config-file")
		}
		argv = append(argv, script)
	case "deno":
		var perms []string
		env, perms = denoPermissions(env, denoDefaults)
		argv, needs = append(append([]string{bins.deno, "run", "--no-prompt"}, perms...), script), bins.deno
	default:
		return nil, nil, "", fmt.Errorf("unsupported shell: %s", shell)
	}
	return append(argv, args...), env, needs, nil
}

// cmdShellArgv builds a CMDShell command. A command string for cmd goes to
// Windows as raw text after /C (rawLine), so the caller's quoting is kept;
// otherwise argv is used.
func cmdShellArgv(shell string, args []string, command, cmdExe, psExe string) (argv []string, rawLine string, err error) {
	switch shell {
	case "cmd":
		if len(args) > 0 && command == "" {
			return append([]string{cmdExe, "/C"}, args...), "", nil
		}
		return []string{cmdExe}, quoteCmdArg(cmdExe) + " /C " + command, nil
	case "powershell":
		if len(args) > 0 && command == "" {
			return append([]string{psExe, "-NonInteractive", "-NoProfile"}, args...), "", nil
		}
		return []string{psExe, "-NonInteractive", "-NoProfile", command}, "", nil
	}
	return nil, "", fmt.Errorf("unsupported shell: %s", shell)
}

func quoteCmdArg(p string) string {
	if strings.ContainsAny(p, " \t") && !(len(p) > 1 && strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`)) {
		return `"` + p + `"`
	}
	return p
}

// Windows 8 and Server 2012 (6.2) are the first that let a process in a job
// put its own children into another job. Before that an agent job would break
// installers that use one.
func nestedJobs(major, minor uint32) bool {
	return major > 6 || (major == 6 && minor >= 2)
}

// One output stream of a script or command.
const scriptOutputMax = 16 << 20

// cappedOutput keeps the first scriptOutputMax bytes and counts the rest.
// The child never sees a write error, so it is not stopped by the cap.
type cappedOutput struct {
	buf     bytes.Buffer
	limit   int
	dropped int64
}

func newCappedOutput() *cappedOutput { return &cappedOutput{limit: scriptOutputMax} }

func (c *cappedOutput) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room >= len(p) {
		return c.buf.Write(p)
	}
	if room > 0 {
		c.buf.Write(p[:room])
	} else {
		room = 0
	}
	c.dropped += int64(len(p) - room)
	return len(p), nil
}

func (c *cappedOutput) String() string {
	if c.dropped == 0 {
		return c.buf.String()
	}
	return c.buf.String() + fmt.Sprintf("\n[output truncated, %d bytes not shown]\n", c.dropped)
}

const (
	termMaxSessions = 8
	termCols        = 120
	termRows        = 30
)

var (
	errCustomShell = errors.New("invalid custom shell path: must be an absolute .exe path")
	driveExeRe     = regexp.MustCompile(`^[A-Za-z]:[\\/][^:]*\.[Ee][Xx][Ee]$`)
)

// termShellPath resolves the shell of terminal_start: cmd and powershell by
// name, anything else must be a local absolute .exe path. UNC and device
// paths are refused: as SYSTEM they would run a program from another host.
func termShellPath(shell, cmdExe, psExe string) (string, error) {
	s := strings.TrimSpace(shell)
	switch strings.ToLower(s) {
	case "", "cmd", "cmd.exe":
		return cmdExe, nil
	case "powershell", "powershell.exe":
		return psExe, nil
	}
	if strings.ContainsAny(s, "\"\r\n") || !driveExeRe.MatchString(s) {
		return "", errCustomShell
	}
	return s, nil
}

// winptyShellPath: the winpty backend knows only cmd and powershell, any
// other value runs cmd.
func winptyShellPath(shell, cmdExe, psExe string) string {
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "powershell", "powershell.exe":
		return psExe
	}
	return cmdExe
}

// termDim clamps a terminal size to what a console COORD holds.
func termDim(n int) int16 {
	switch {
	case n < 1:
		return 1
	case n > 32767:
		return 32767
	}
	return int16(n)
}

// Exit codes of RunScript the dashboard shows.
const (
	scriptSetupExit = 85
	scriptStartExit = 65
)

// winExec error for a process that never started.
type startError struct{ err error }

func (e *startError) Error() string { return e.err.Error() }
func (e *startError) Unwrap() error { return e.err }

// Only a start error means the script did not run: -1 is also a real exit
// code, on 386 `exit -1` (0xFFFFFFFF) does not fit an int.
func scriptReply(stdout, stderr string, code int, timedOut bool, err error, timeout int) (string, string, int, error) {
	var se *startError
	switch {
	case timedOut:
		return stdout, stderr + fmt.Sprintf("\nScript timed out after %d seconds", timeout), cmdTimeoutExit, nil
	case errors.As(err, &se):
		return "", CleanString(err.Error()), scriptStartExit, err
	}
	return stdout, stderr, code, nil
}
