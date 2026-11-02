// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestWinScriptArgv(t *testing.T) {
	bins := winScriptBins{
		powershell: `C:\ps.exe`, python: `C:\py\python.exe`, nu: `C:\bin\nu.exe`, deno: `C:\bin\deno.exe`,
		nuConfDir: `C:\Agent\etc\nushell`,
	}
	cases := []struct {
		shell    string
		nuConf   bool
		env      []string
		defaults string
		argv     []string
		outEnv   []string
		needs    string
	}{
		{shell: "powershell", argv: []string{`C:\ps.exe`, "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "s", "a", "b c"}},
		{shell: "python", argv: []string{`C:\py\python.exe`, "s", "a", "b c"}},
		{shell: "cmd", env: []string{"A=1"}, argv: []string{"s", "a", "b c"}, outEnv: []string{"A=1"}},
		{shell: "nushell", nuConf: true, needs: `C:\bin\nu.exe`,
			argv: []string{`C:\bin\nu.exe`, "--config", `C:\Agent\etc\nushell\config.nu`, "--env-config", `C:\Agent\etc\nushell\env.nu`, "s", "a", "b c"}},
		{shell: "nushell", needs: `C:\bin\nu.exe`, argv: []string{`C:\bin\nu.exe`, "--no-config-file", "s", "a", "b c"}},
		{shell: "deno", env: []string{"A=1", "DENO_PERMISSIONS=--allow-read --allow-net"}, defaults: "--allow-all", needs: `C:\bin\deno.exe`,
			argv: []string{`C:\bin\deno.exe`, "run", "--no-prompt", "--allow-read", "--allow-net", "s", "a", "b c"}, outEnv: []string{"A=1"}},
		{shell: "deno", defaults: "--allow-all", needs: `C:\bin\deno.exe`,
			argv: []string{`C:\bin\deno.exe`, "run", "--no-prompt", "--allow-all", "s", "a", "b c"}},
		{shell: "deno", needs: `C:\bin\deno.exe`, argv: []string{`C:\bin\deno.exe`, "run", "--no-prompt", "s", "a", "b c"}},
	}
	for _, c := range cases {
		argv, env, needs, err := winScriptArgv(c.shell, "s", bins, []string{"a", "b c"}, c.env, c.nuConf, c.defaults)
		if err != nil || !reflect.DeepEqual(argv, c.argv) || needs != c.needs || len(env) != len(c.outEnv) || (len(env) > 0 && !reflect.DeepEqual(env, c.outEnv)) {
			t.Errorf("%s: argv %q env %q needs %q err %v", c.shell, argv, env, needs, err)
		}
	}
	if _, _, _, err := winScriptArgv("bash", "s", bins, nil, nil, false, ""); err == nil || err.Error() != "unsupported shell: bash" {
		t.Errorf("unknown shell: %v", err)
	}
	for shell, ext := range map[string]string{"powershell": ".ps1", "python": ".py", "cmd": ".bat", "nushell": ".nu", "deno": ".ts", "bash": ""} {
		if scriptExt(shell) != ext {
			t.Errorf("%s: ext %q", shell, scriptExt(shell))
		}
	}
}

func TestCmdShellArgv(t *testing.T) {
	const cmdExe, psExe = `C:\Windows\System32\cmd.exe`, `C:\Program Files\ps.exe`
	cases := []struct {
		shell, command string
		args           []string
		argv           []string
		raw            string
	}{
		{"cmd", `echo "a b" & dir`, nil, []string{cmdExe}, cmdExe + ` /C echo "a b" & dir`},
		{"cmd", "", []string{"ipconfig", "/all"}, []string{cmdExe, "/C", "ipconfig", "/all"}, ""},
		{"powershell", "Get-Date; 'x'", nil, []string{psExe, "-NonInteractive", "-NoProfile", "Get-Date; 'x'"}, ""},
		{"powershell", "", []string{"-File", "x.ps1"}, []string{psExe, "-NonInteractive", "-NoProfile", "-File", "x.ps1"}, ""},
	}
	for _, c := range cases {
		argv, raw, err := cmdShellArgv(c.shell, c.args, c.command, cmdExe, psExe)
		if err != nil || !reflect.DeepEqual(argv, c.argv) || raw != c.raw {
			t.Errorf("%s %q: %q %q %v", c.shell, c.command, argv, raw, err)
		}
	}
	if _, raw, _ := cmdShellArgv("cmd", nil, "x", `C:\a b\cmd.exe`, psExe); raw != `"C:\a b\cmd.exe" /C x` {
		t.Errorf("quoted exe: %q", raw)
	}
	for _, sh := range []string{"", "bash", `C:\custom.exe`} {
		if _, _, err := cmdShellArgv(sh, nil, "x", cmdExe, psExe); err == nil {
			t.Errorf("%q accepted", sh)
		}
	}
}

func TestQuoteCmdArg(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Windows\cmd.exe`:   `C:\Windows\cmd.exe`,
		`C:\Program Files\x`:   `"C:\Program Files\x"`,
		`"C:\Program Files\x"`: `"C:\Program Files\x"`,
		"C:\\a\tb":             "\"C:\\a\tb\"",
	} {
		if got := quoteCmdArg(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestCappedOutput(t *testing.T) {
	c := newCappedOutput()
	c.limit = 5
	for _, p := range []string{"abc", "defg", "hij"} {
		if n, err := c.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("write %q: %d %v", p, n, err)
		}
	}
	if got := c.String(); got != "abcde\n[output truncated, 5 bytes not shown]\n" {
		t.Errorf("got %q", got)
	}
	small := newCappedOutput()
	small.Write([]byte("hi\r\n"))
	if small.String() != "hi\r\n" {
		t.Errorf("small: %q", small.String())
	}
}

func TestTermShellPath(t *testing.T) {
	const cmdExe, psExe = `C:\W\cmd.exe`, `C:\W\powershell.exe`
	for in, want := range map[string]string{
		"": cmdExe, " CMD ": cmdExe, "cmd.exe": cmdExe, "PowerShell": psExe, "powershell.exe": psExe,
		`C:\Program Files\PowerShell\7\pwsh.exe`: `C:\Program Files\PowerShell\7\pwsh.exe`,
		`d:/tools/x.EXE`:                         `d:/tools/x.EXE`,
	} {
		if got, err := termShellPath(in, cmdExe, psExe); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{
		`pwsh.exe`, `bin\pwsh.exe`, `C:\x\pwsh.bat`, `C:\x\pwsh`, `\\server\share\x.exe`, `//server/share/x.exe`,
		`\\?\C:\x.exe`, `\\.\C:\x.exe`, `C:\x "y".exe`, "C:\\x\r\n.exe", `C:\a.txt:b.exe`, `C:x.exe`, `bash`,
	} {
		if _, err := termShellPath(bad, cmdExe, psExe); err != errCustomShell {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if winptyShellPath(`C:\x\pwsh.exe`, cmdExe, psExe) != cmdExe || winptyShellPath("powershell", cmdExe, psExe) != psExe {
		t.Error("winpty shell")
	}
}

func TestNestedJobs(t *testing.T) {
	cases := []struct {
		major, minor uint32
		want         bool
	}{{6, 1, false}, {6, 0, false}, {5, 2, false}, {6, 2, true}, {6, 3, true}, {10, 0, true}}
	for _, c := range cases {
		if nestedJobs(c.major, c.minor) != c.want {
			t.Errorf("%d.%d: want %v", c.major, c.minor, c.want)
		}
	}
}

func TestTermDim(t *testing.T) {
	for in, want := range map[int]int16{-3: 1, 0: 1, 1: 1, 120: 120, 32767: 32767, 70000: 32767} {
		if termDim(in) != want {
			t.Errorf("%d: %d", in, termDim(in))
		}
	}
	if !strings.Contains(errCustomShell.Error(), "absolute .exe path") {
		t.Error("error text")
	}
}

func TestScriptReply(t *testing.T) {
	// exit -1 on a 386 build: a normal end, no start failure, no panic
	if o, e, c, err := scriptReply("out", "err", -1, false, nil, 5); o != "out" || e != "err" || c != -1 || err != nil {
		t.Fatalf("exit -1: %q %q %d %v", o, e, c, err)
	}
	start := &startError{errors.New("file not found")}
	if o, e, c, err := scriptReply("x", "y", -1, false, start, 5); o != "" || e != "file not found" || c != scriptStartExit || !errors.Is(err, start.err) {
		t.Fatalf("start failure: %q %q %d %v", o, e, c, err)
	}
	if _, e, c, err := scriptReply("x", "y", cmdTimeoutExit, true, context.DeadlineExceeded, 3); c != cmdTimeoutExit || err != nil || !strings.HasSuffix(e, "y\nScript timed out after 3 seconds") {
		t.Fatalf("timeout: %q %d %v", e, c, err)
	}
	// a wait failure after a start keeps the script's code
	if _, _, c, err := scriptReply("x", "y", 1, false, errors.New("pipe"), 5); c != 1 || err != nil {
		t.Fatalf("wait failure: %d %v", c, err)
	}
}
