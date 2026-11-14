// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestFormatWinOS(t *testing.T) {
	cases := []struct {
		name, arch, ver, build, want string
	}{
		{"Windows 11 Pro", "x86_64", "24H2", "26100", "Windows 11 Pro, 64 bit v24H2 (build 26100)"},
		{"Windows 10 Pro", "x86", "2009", "19045", "Windows 10 Pro, 32 bit v2009 (build 19045)"},
		{"Windows 11 Pro", "arm64", "23H2", "22631", "Windows 11 Pro, ARM 64 bit v23H2 (build 22631)"},
		{"Windows Server 2012 R2 Standard", "x86_64", "", "9600", "Windows Server 2012 R2 Standard, 64 bit (build 9600)"},
	}
	for _, c := range cases {
		if got := formatWinOS(c.name, winOSArch(c.arch), c.ver, c.build); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
	if winOSArch("mips") != "" {
		t.Error("unknown arch should be empty")
	}
}

func TestPickLoggedOnUser(t *testing.T) {
	called := false
	logons := func(names ...string) func() []string {
		return func() []string { called = true; return names }
	}
	cases := []struct {
		sessions []string
		ok       bool
		logons   []string
		want     string
		fallback bool
	}{
		{[]string{"", "alice"}, true, []string{"bob"}, "alice", false},
		{[]string{"", ""}, true, []string{"bob"}, "None", false},
		{nil, true, nil, "None", false},
		{nil, false, []string{"", "bob"}, "bob", true},
		{nil, false, nil, "None", true},
		{[]string{"Jürgen"}, true, []string{"jürgen"}, "jürgen", true},
		{[]string{"Jürgen"}, true, nil, "None", true},
	}
	for _, c := range cases {
		called = false
		if got := pickLoggedOnUser(c.sessions, c.ok, logons(c.logons...)); got != c.want {
			t.Errorf("%v %v: %q, want %q", c.sessions, c.ok, got, c.want)
		}
		if called != c.fallback {
			t.Errorf("%v %v: logon sessions asked %v", c.sessions, c.ok, called)
		}
	}
}

func TestMeshHelpers(t *testing.T) {
	for id, want := range map[string]bool{
		"":                      false,
		"Not defined":           false,
		"NodeID is NOT DEFINED": false,
		"nmRH7bQ6Z8@k$aBC":      true,
	} {
		if meshNodeIDUsable(id) != want {
			t.Errorf("meshNodeIDUsable(%q) != %v", id, want)
		}
	}
	if got := meshInstallArgs(""); !reflect.DeepEqual(got, []string{"-fullinstall"}) {
		t.Error(got)
	}
	if got := meshInstallArgs("http://p:3128"); !reflect.DeepEqual(got, []string{"-fullinstall", "--WebProxy=http://p:3128"}) {
		t.Error(got)
	}
}

func TestApplyCheckInOverrides(t *testing.T) {
	server := AgentCheckInConfig{Hello: 40, AgentInfo: 300, WinSvc: 2500, PubIP: 400, Disks: 1500, SW: 3000, WMI: 3500, SyncMesh: 900}
	vals := map[string]string{
		"CheckInHello":     "100,200",
		"CheckInAgentInfo": "abc",
		"CheckInWinSvc":    "5",
		"CheckInPubIP":     "10,10",
		"CheckInDisks":     "20,10",
		"CheckInLimitData": "true",
	}
	got := applyCheckInOverrides(server, func(n string) string { return vals[n] })
	if got.Hello < 100 || got.Hello >= 200 {
		t.Errorf("Hello %d not in [100,200)", got.Hello)
	}
	got.Hello = server.Hello
	want := server
	want.LimitData = true
	if got != want {
		t.Errorf("%+v, want %+v", got, want)
	}
	if applyCheckInOverrides(server, func(n string) string {
		if n == "CheckInLimitData" {
			return "yes"
		}
		return ""
	}).LimitData {
		t.Error("LimitData takes only the text true")
	}
}

func TestCheckUpdateRequest(t *testing.T) {
	const sha = "ab"
	good := "ulrmm-agent-v2.11.10.2026-windows-amd64.exe"
	ok := []struct{ url, inno, ver, sha string }{
		{"https://rmm/agentdist/x.exe", good, "2.11.10.2026", sha},
		{"https://rmm/agentdist/x.exe", "SETUP.EXE", "2.11.10.2026", ""},
		{"http://rmm/agentdist/x.exe", good, "2.11.10.2026", sha},
	}
	for _, c := range ok {
		if err := checkUpdateRequest(c.url, c.inno, c.ver, c.sha); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []struct{ url, inno, ver, sha string }{
		{"https://x", `..\..\Windows\x.exe`, "1", sha},
		{"https://x", "a/b.exe", "1", sha},
		{"https://x", `C:x.exe`, "1", sha},
		{"https://x", "x.msi", "1", sha},
		{"https://x", "x .exe", "1", sha},
		{"https://x", "", "1", sha},
		{"https://x", good, `1\..\x`, sha},
		{"https://x", good, "..", sha},
		{"https://x", good, "", sha},
		{"http://x", good, "1", ""},
	}
	for _, c := range bad {
		if err := checkUpdateRequest(c.url, c.inno, c.ver, c.sha); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if got := updateLogName("2.11.10.2026"); got != IdentArtifact+"_update_v2.11.10.2026.txt" {
		t.Error(got)
	}
}

func TestIsChecksRun(t *testing.T) {
	self := `C:\Program Files\ULRMM Agent\ulrmm-agent.exe`
	cases := []struct {
		exe  string
		args []string
		want bool
	}{
		{self, []string{self, "-m", "runchecks"}, true},
		{strings.ToLower(self), []string{"x", "-m", "checkrunner"}, true},
		{self, []string{self, "-m", "svc"}, false},
		{`C:\other.exe`, []string{"-m", "runchecks"}, false},
		{"", []string{"runchecks"}, false},
	}
	for _, c := range cases {
		if got := isChecksRun(c.exe, c.args, self); got != c.want {
			t.Errorf("%q %q: %v", c.exe, c.args, got)
		}
	}
	if isChecksRun("", []string{"runchecks"}, "") {
		t.Error("empty self")
	}
}

func TestWinRuntimeURLs(t *testing.T) {
	if got := winNushellRelease("amd64", "0.99.1"); got != nuReleaseURL+"/0.99.1/nu-0.99.1-x86_64-pc-windows-msvc.zip" {
		t.Error(got)
	}
	if got := winNushellRelease("arm64", "0.99.1"); !strings.HasSuffix(got, "/nu-0.99.1-aarch64-pc-windows-msvc.zip") {
		t.Error(got)
	}
	if winNushellRelease("386", "1") != "" || winDenoRelease("arm64", "1") != "" {
		t.Error("no release expected")
	}
	if got := winDenoRelease("amd64", "v2.1.4"); got != denoReleaseURL+"/v2.1.4/deno-x86_64-pc-windows-msvc.zip" {
		t.Error(got)
	}
	if got := pythonZipURL("", "https://rmm.example/", "py3.14.5_amd64.zip"); got != "https://rmm.example/agentdist/python/py3.14.5_amd64.zip" {
		t.Error(got)
	}
	if got := pythonZipURL("https://cdn.example/py/", "https://rmm", "py3.8.7_386.zip"); got != "https://cdn.example/py/py3.8.7_386.zip" {
		t.Error(got)
	}
}

func TestFindFile(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nu-0.99-x86_64-pc-windows-msvc")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "nu.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := findFile(dir, "nu.exe"); err != nil || got != filepath.Join(nested, "nu.exe") {
		t.Errorf("%q %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nu.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := findFile(dir, "nu.exe"); err != nil || got != filepath.Join(dir, "nu.exe") {
		t.Errorf("top level first: %q %v", got, err)
	}
	if _, err := findFile(dir, "deno.exe"); err == nil {
		t.Error("missing file found")
	}
}

func TestPowercfgSteps(t *testing.T) {
	want := [][]string{
		{"/setdcvalueindex", "scheme_current", "sub_buttons", "lidaction", "0"},
		{"/x", "-standby-timeout-dc", "0"},
		{"/x", "-hibernate-timeout-dc", "0"},
		{"/x", "-disk-timeout-dc", "0"},
		{"/x", "-monitor-timeout-dc", "0"},
	}
	if got := powercfgSteps("dc"); !reflect.DeepEqual(got, want) {
		t.Errorf("%q", got)
	}
}

func TestPSEncoded(t *testing.T) {
	if got := psEncoded("a"); got != "YQA=" {
		t.Error(got)
	}
	b, err := base64.StdEncoding.DecodeString(psEncoded("ä €"))
	if err != nil || len(b) != 6 {
		t.Fatal(b, err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	if string(utf16.Decode(u)) != "ä €" {
		t.Error(u)
	}
}

func TestExistingInstallText(t *testing.T) {
	got := existingInstallText(`C:\Program Files\ULRMM Agent\unins000.exe`)
	if !strings.HasPrefix(got, "Existing installation found and must be removed before attempting to reinstall.\n") ||
		!strings.Contains(got, `"C:\Program Files\ULRMM Agent\unins000.exe" /VERYSILENT /UNINSTALLCODE=<uninstall code>`) ||
		strings.Contains(got, "and start this installer again") {
		t.Error(got)
	}
}

func TestSetupArgs(t *testing.T) {
	for _, tc := range []struct {
		got  []string
		want string
	}{
		{updateSetupArgs(`C:\tmp dir\u.log`), `/VERYSILENT /S /LOG=C:\tmp dir\u.log`},
		{healSetupArgs(`C:\w\h.log`), `/VERYSILENT /S /SUPPRESSMSGBOXES /NORESTART /LOG=C:\w\h.log`},
		{uninstallerArgs("c0de"), `/VERYSILENT /S /UNINSTALLCODE=c0de`},
		{uninstallerArgs(""), `/VERYSILENT /S`},
	} {
		if got := strings.Join(tc.got, " "); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
