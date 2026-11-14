// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/creack/pty"
	"github.com/go-resty/resty/v2"
	"github.com/shirou/gopsutil/v3/disk"
)

func tempConfig(t *testing.T) {
	t.Helper()
	old := etcConfig
	t.Cleanup(func() { etcConfig = old })
	etcConfig = filepath.Join(t.TempDir(), "agent")
}

func writeShim(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewAgentConfig(t *testing.T) {
	tempConfig(t)
	if c := NewAgentConfig(); !reflect.DeepEqual(*c, rmm.LocalConfig{}) {
		t.Fatalf("missing file: %+v", c)
	}
	os.WriteFile(etcConfig, []byte(`{"BaseURL": "https://rmm", "agentid": "abc", "agentpk": "12",
		"natspinginterval": 30, "pins": "{\"seq\":3}", "tmpdir": "/var/tmp", "meshdir": "/m",
		"natsproxyport": "8443", "Token": "upper", "token": "lower"}`), 0o600)
	c := NewAgentConfig()
	if c.ServerBase != "https://rmm" || c.ID != "abc" || c.PKNum != 12 || c.PKText != "12" ||
		c.NATSPing != 30 || c.PinsJSON != `{"seq":3}` || c.UnixTemp != "/var/tmp" ||
		c.MeshDir != "/m" || c.NATSProxyPort != "8443" || c.AuthToken != "lower" {
		t.Fatalf("got %+v", c)
	}
	os.WriteFile(etcConfig, []byte(`{"agentpk": "abc", "natspinginterval": "45"}`), 0o600)
	if c := NewAgentConfig(); c.PKNum != 0 || c.NATSPing != 45 {
		t.Fatalf("got %+v", c)
	}
	os.WriteFile(etcConfig, []byte(`{not json`), 0o600)
	if c := NewAgentConfig(); c.ID != "" {
		t.Fatalf("corrupt file: %+v", c)
	}
}

func TestCreateAgentConfigFormat(t *testing.T) {
	tempConfig(t)
	createAgentConfig("https://api.example", "id", "api.example", "tok", "7", "", "", "", "", "")
	b, err := os.ReadFile(etcConfig)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, " ") != "agentid agentpk apiurl baseurl cert meshdir natsstandardport proxy tmpdir token uninstallcode" {
		t.Fatalf("keys %v", keys)
	}
	if len(m["uninstallcode"]) != uninstallCodeLen || strings.HasSuffix(string(b), "\n") ||
		!strings.Contains(string(b), "\n  \"agentid\": \"id\",") {
		t.Fatalf("file text:\n%s", b)
	}
	// a fresh install never takes over an existing config
	if err := writeConfFile(map[string]interface{}{"a": "b"}, true); err == nil {
		t.Fatal("existing config overwritten")
	}
	if tok, _ := confValue("token"); tok != "tok" {
		t.Fatalf("token %q", tok)
	}

}

// An older install's insecure=true leaves the config on service start and
// is reported once.
func TestInsecureConfigDropped(t *testing.T) {
	tempConfig(t)
	createAgentConfig("https://api.example", "id", "api.example", "tok", "7", "", "", "", "", "")
	if err := setConfValues(map[string]string{"insecure": "true"}); err != nil {
		t.Fatal(err)
	}
	a := testUpdateAgent()
	a.dropInsecure()
	conf, _ := readConfFile()
	if _, ok := conf["insecure"]; ok || conf["token"] != "tok" {
		t.Fatalf("config after the start: %v", conf)
	}
	if len(a.events) != 1 || a.events[0].Kind != "insecure_dropped" {
		t.Fatalf("events %v", a.events)
	}
	a.dropInsecure()
	if len(a.events) != 1 {
		t.Fatalf("reported again: %v", a.events)
	}
}

func TestSetConfValues(t *testing.T) {
	tempConfig(t)
	if err := setConfValues(map[string]string{"a": "1"}); err == nil || !strings.Contains(err.Error(), "agent is not installed") {
		t.Fatalf("not installed: %v", err)
	}
	os.WriteFile(etcConfig, []byte(`{"agentid": "x", "natspinginterval": 30}`), 0o644)
	if err := setConfValues(map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(etcConfig)
	if !strings.Contains(string(b), `"natspinginterval": 30`) || !strings.Contains(string(b), `"a": "1"`) {
		t.Fatalf("file:\n%s", b)
	}
	if st, _ := os.Stat(etcConfig); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(etcConfig), ".conf*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	if v, err := confValue("missing"); v != "" || err != nil {
		t.Fatalf("missing key: %q %v", v, err)
	}
	os.WriteFile(etcConfig, []byte(`{broken`), 0o600)
	if _, err := confValue("a"); err == nil {
		t.Fatal("corrupt config read without error")
	}
}

func TestDiskList(t *testing.T) {
	a := testUpdateAgent()
	parts := []disk.PartitionStat{
		{Device: "/dev/sda1", Mountpoint: "/", Fstype: "ext4"},
		{Device: "/dev/loop3", Mountpoint: "/snap/x"},
		{Device: "devfs", Mountpoint: "/dev"},
		{Device: "/dev/sdb1", Mountpoint: "/broken"},
	}
	usage := func(m string) (*disk.UsageStat, error) {
		if m == "/broken" {
			return nil, fmt.Errorf("no access")
		}
		return &disk.UsageStat{Total: 1 << 30, Used: 1536, Free: 1023, UsedPercent: 42.9}, nil
	}
	got := a.diskList(parts, usage)
	want := []rmm.DiskUsage{{Dev: "/dev/sda1", FSType: "ext4", TotalText: "1.0 GB", UsedText: "1.5 kB", FreeText: "1023 B", UsedPct: 42}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := a.diskList(nil, usage); got == nil || len(got) != 0 {
		t.Fatalf("empty list: %#v", got)
	}
}

func TestHardwareHelpers(t *testing.T) {
	if s := formatOS("ubuntu", "22.04", "x86_64", "5.15.0-91-generic"); s != "Ubuntu 22.04 x86_64 5.15.0-91-generic" {
		t.Fatalf("os %q", s)
	}
	if ips := filterLocalIPs([]string{"127.0.0.1/8", "::1/128", "192.168.1.5/24", "fe80::1/64", "10.127.0.5/24", "127.0.0.2", "bogus"}); !reflect.DeepEqual(ips, []string{"192.168.1.5/24", "fe80::1/64", "10.127.0.5/24", "bogus"}) {
		t.Fatalf("ips %v", ips)
	}
	if s := diskLine("unknown", "Samsung SSD", "SCSI", "SSD", "sda", 1<<30); s != "Samsung SSD SCSI SSD sda 1.0 GB" {
		t.Fatalf("disk %q", s)
	}
	if v := gpuValue([]string{"unknown unknown"}); v != "" {
		t.Fatalf("gpu %#v", v)
	}
	if v := gpuValue([]string{}); !reflect.DeepEqual(v, []string{}) {
		t.Fatalf("no gpu %#v", v)
	}
	pi := "processor\t: 0\nModel\t\t: Raspberry Pi 4 Model B Rev 1.4\n"
	if m := raspberryModel(pi); m != "Raspberry Pi 4 Model B Rev 1.4" {
		t.Fatalf("pi %q", m)
	}
	if m := raspberryModel("Hardware : BCM2835 raspberry: x: y\n"); m != "" {
		t.Fatalf("line with two colons used: %q", m)
	}
	io := `+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000213>
    {
      "IOPlatformUUID" = "0B1F"
      "IOPlatformSerialNumber" = "C02XK1ABCDEF"
    }`
	if s := ioregSerial(io); s != "C02XK1ABCDEF" {
		t.Fatalf("serial %q", s)
	}
}

func TestSystemRebootRequired(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir := t.TempDir()
	oldF, oldB := rebootRequiredFiles, needsRestartingBins
	defer func() { rebootRequiredFiles, needsRestartingBins = oldF, oldB }()
	a := testUpdateAgent()

	flag := filepath.Join(dir, "reboot-required")
	rebootRequiredFiles, needsRestartingBins = []string{flag}, nil
	if r, err := a.SystemRebootRequired(); r || err != nil {
		t.Fatalf("nothing present: %v %v", r, err)
	}
	os.WriteFile(flag, nil, 0o644)
	if r, _ := a.SystemRebootRequired(); !r {
		t.Fatal("flag file ignored")
	}
	os.Remove(flag)

	for code, want := range map[int]bool{0: false, 1: true, 2: false} {
		nr := writeShim(t, filepath.Join(dir, "nr"), fmt.Sprintf(`[ "$1" = "-r" ] || exit 9; exit %d`, code))
		needsRestartingBins = []string{nr}
		if r, _ := a.SystemRebootRequired(); r != want {
			t.Fatalf("exit %d: %v", code, r)
		}
	}
	// a candidate that cannot start is skipped
	broken := filepath.Join(dir, "broken")
	os.WriteFile(broken, []byte("not a program"), 0o755)
	second := writeShim(t, filepath.Join(dir, "nr2"), "exit 1")
	needsRestartingBins = []string{broken, second}
	if r, _ := a.SystemRebootRequired(); !r {
		t.Fatal("second candidate not asked")
	}
}

func TestRunScriptResults(t *testing.T) {
	tmp := t.TempDir()
	a := testUpdateAgent()
	a.UnixTmpDir = filepath.Join(tmp, "scripts")

	out, errOut, code, err := a.RunScript("#!/bin/sh\r\necho \"$FOO\" \"$1\"\r\necho e >&2\r\nexit 7\r\n", "shell",
		[]string{"a b"}, 30, false, []string{"FOO=1", "BAD NAME=x", "FOO=2"}, false, "")
	if out != "2 a b\n" || errOut != "e\n" || code != 7 || err != nil {
		t.Fatalf("got %q %q %d %v", out, errOut, code, err)
	}
	_, errOut, code, err = a.RunScript("echo no shebang", "shell", nil, 30, false, nil, false, "")
	if code != -1 || err != nil || !strings.HasSuffix(errOut, "\n") || errOut == "\n" {
		t.Fatalf("no shebang: %q %d %v", errOut, code, err)
	}
	for _, sh := range []string{"nushell", "deno"} {
		a.NuBin, a.DenoBin = filepath.Join(tmp, "nu"), filepath.Join(tmp, "deno")
		_, errOut, code, err = a.RunScript("x", sh, nil, 30, false, nil, false, "")
		if code != 85 || err == nil || !strings.HasPrefix(errOut, "File Not Found: "+tmp) {
			t.Fatalf("%s missing: %q %d %v", sh, errOut, code, err)
		}
	}
	if left, _ := os.ReadDir(a.UnixTmpDir); len(left) != 0 {
		t.Fatalf("script files left: %v", left)
	}

	a.UnixTmpDir = filepath.Join(tmp, "file")
	os.WriteFile(a.UnixTmpDir, nil, 0o600)
	if _, _, code, err := a.RunScript("x", "shell", nil, 30, false, nil, false, ""); code != 85 || err == nil {
		t.Fatalf("tmpdir is a file: %d %v", code, err)
	}
}

func TestRunScriptRuntimeArgs(t *testing.T) {
	tmp := t.TempDir()
	a := testUpdateAgent()
	a.UnixTmpDir = tmp
	echo := `for x in "$@"; do printf '[%s]' "$x"; done; echo; echo "perm=$DENO_PERMISSIONS"`
	a.NuBin = writeShim(t, filepath.Join(tmp, "nu"), echo)
	a.DenoBin = writeShim(t, filepath.Join(tmp, "deno"), echo)
	oldEtc := nixAgentEtcDir
	defer func() { nixAgentEtcDir = oldEtc }()
	nixAgentEtcDir = "/data/etc"

	argv := func(out string) []string {
		line := strings.SplitN(out, "\n", 2)[0]
		return strings.Split(strings.Trim(line, "[]"), "][")
	}
	out, _, _, _ := a.RunScript("x", "nushell", []string{"p"}, 30, false, nil, true, "")
	if got := argv(out); len(got) != 6 || got[0] != "--config" || got[1] != "/data/etc/nushell/config.nu" ||
		got[2] != "--env-config" || got[3] != "/data/etc/nushell/env.nu" || got[5] != "p" {
		t.Fatalf("nushell argv %v", got)
	}
	out, _, _, _ = a.RunScript("x", "nushell", nil, 30, false, nil, false, "")
	if got := argv(out); got[0] != "--no-config-file" {
		t.Fatalf("nushell argv %v", got)
	}

	out, _, _, _ = a.RunScript("x", "deno", []string{"p"}, 30, false,
		[]string{"DENO_PERMISSIONS=--allow-read=/tmp  --allow-net"}, false, "--allow-all")
	got := argv(out)
	if strings.Join(got[:4], " ") != "run --no-prompt --allow-read=/tmp --allow-net" ||
		!strings.HasSuffix(got[4], ".ts") || got[5] != "p" || !strings.Contains(out, "perm=\n") {
		t.Fatalf("deno argv %v\n%s", got, out)
	}
	out, _, _, _ = a.RunScript("x", "deno", nil, 30, false, nil, false, "--allow-all")
	if got := argv(out); strings.Join(got[:3], " ") != "run --no-prompt --allow-all" {
		t.Fatalf("deno default permissions %v", got)
	}
	out, _, _, _ = a.RunScript("x", "deno", nil, 30, false, nil, false, "")
	if got := argv(out); len(got) != 3 || got[0] != "run" {
		t.Fatalf("deno without permissions %v", got)
	}
}

func TestNixMeshNodeID(t *testing.T) {
	dir := t.TempDir()
	old := meshRetryPause
	meshRetryPause = 0
	defer func() { meshRetryPause = old }()
	a := testUpdateAgent()

	a.MeshSystemEXE = filepath.Join(dir, "none")
	if id := a.NixMeshNodeID(); id != "" {
		t.Fatalf("no mesh agent: %q", id)
	}
	count := filepath.Join(dir, "count")
	a.MeshSystemEXE = writeShim(t, filepath.Join(dir, "mesh"), `[ "$1" = "-nodeid" ] || exit 9
echo x >> `+count+`
[ $(wc -l < `+count+`) -gt 3 ] && echo NODE123`)
	if id := a.NixMeshNodeID(); id != "NODE123\n" {
		t.Fatalf("got %q", id)
	}
	a.MeshSystemEXE = writeShim(t, filepath.Join(dir, "gui"), "echo 'Needs the Graphical Version'")
	if id := a.NixMeshNodeID(); id != "error getting meshnodeid" {
		t.Fatalf("got %q", id)
	}
}

func TestCheckExecFormat(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkExecFormat(self, "linux", runtime.GOARCH); err != nil {
		t.Fatalf("test binary refused: %v", err)
	}
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	if checkExecFormat(self, "linux", other) == nil {
		t.Fatal("binary of another arch accepted")
	}
	if checkExecFormat(self, "darwin", "arm64") == nil {
		t.Fatal("ELF accepted on macOS")
	}
	page := filepath.Join(t.TempDir(), "page")
	os.WriteFile(page, []byte("<html>proxy login</html>"), 0o755)
	if checkExecFormat(page, "linux", runtime.GOARCH) == nil {
		t.Fatal("HTML accepted as agent")
	}
	if err := testUpdateAgent().checkAgentBinary(page, "linux", runtime.GOARCH, "1.0"); err == nil {
		t.Fatal("HTML accepted as agent")
	}
}

func TestUninstallPlan(t *testing.T) {
	describe := func(plan []uninstallStep) string {
		var s []string
		for _, p := range plan {
			if p.remove != "" {
				s = append(s, "rm "+p.remove)
			} else {
				s = append(s, strings.Join(p.argv, " "))
			}
		}
		return strings.Join(s, "\n")
	}
	linux := describe(uninstallPlan("linux", []string{"/opt/ulrmm-mesh/meshagent"}))
	want := strings.Join([]string{
		"env XAUTHORITY=foo DISPLAY=bar /opt/ulrmm-mesh/meshagent -uninstall",
		"systemctl disable --now meshagent.service",
		"systemctl disable --now " + IdentNixSvc,
		"rm /lib/systemd/system/meshagent.service",
		"rm /etc/systemd/system/" + IdentNixSvc,
		"systemctl daemon-reload",
		"rm /usr/local/bin/" + IdentNixBin,
		"rm " + nixMeshDir,
		"rm " + etcConfig,
		"rm " + etcConfig + ".kek",
		"rm " + etcConfig + ".kek.cred",
		"rm " + etcConfig + ".kek.host.cred",
		"rm " + nixAgentDir,
		"rm /var/log/" + IdentNixBin + ".log",
		"rm /var/log/" + IdentNixBin + ".log.1",
		"rm /var/log/" + IdentNixBin + ".log.2",
	}, "\n")
	if linux != want {
		t.Fatalf("linux plan:\n%s", linux)
	}
	mac := describe(uninstallPlan("darwin", []string{"/a/meshagent", "/b/meshagent"}))
	if !strings.HasPrefix(mac, "/a/meshagent -fulluninstall\n/b/meshagent -fulluninstall\nlaunchctl bootout system "+macPlistPath+
		"\nsecurity delete-generic-password -s "+macPlistName+" -a kek /Library/Keychains/System.keychain\n") ||
		!strings.Contains(mac, "rm "+etcConfig+".kek\nrm "+etcConfig+".kek.cred\nrm "+etcConfig+".kek.host.cred\n") ||
		!strings.Contains(mac, "rm "+macMeshAgentPlist) || !strings.HasSuffix(mac, "rm "+nixAgentDir+"\nrm "+NixLogFile+"\nrm "+NixLogFile+".1\nrm "+NixLogFile+".2") {
		t.Fatalf("mac plan:\n%s", mac)
	}
}

func TestInstallRuntimeChecksSha256(t *testing.T) {
	body := []byte("runtime build")
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
	defer ts.Close()
	sum := sha256.Sum256(body)
	a := testUpdateAgent()
	a.Cert = writeCA(t, ts)
	bin := filepath.Join(t.TempDir(), "bin", "deno")
	rt := scriptRuntime{name: "deno", bin: bin, version: "1", customURL: ts.URL + "/deno", tmpBase: t.TempDir()}

	rt.sha256 = strings.Repeat("0", 64)
	if err := a.installRuntime(rt, true); err == nil || !strings.Contains(err.Error(), "sha256 of the deno download") || rmm.FileExists(bin) {
		t.Fatalf("wrong sha: %v, installed %v", err, rmm.FileExists(bin))
	}
	rt.sha256 = ""
	if err := a.installRuntime(rt, true); err == nil || err.Error() != "the server sent no sha256 for deno" || rmm.FileExists(bin) {
		t.Fatalf("no sha: %v, installed %v", err, rmm.FileExists(bin))
	}
	rt.sha256 = strings.ToUpper(hex.EncodeToString(sum[:]))
	if err := a.installRuntime(rt, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != string(body) {
		t.Fatalf("installed %q", b)
	}
}

func TestDefaultScriptDir(t *testing.T) {
	old := nixTmpDir
	nixTmpDir = filepath.Join(t.TempDir(), "tmp")
	defer func() { nixTmpDir = old }()
	os.MkdirAll(nixTmpDir, 0o777)
	f, err := createNixTmpFile("")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	st, _ := os.Stat(nixTmpDir)
	if filepath.Dir(f.Name()) != nixTmpDir || st.Mode().Perm() != 0o711 {
		t.Fatalf("script %s in a dir with mode %v", f.Name(), st.Mode().Perm())
	}
	custom := filepath.Join(t.TempDir(), "custom")
	if f, err := createNixTmpFile(custom, "deno"); err != nil || filepath.Dir(f.Name()) != custom || !strings.HasSuffix(f.Name(), ".ts") {
		t.Fatalf("tmpdir: %v %v", f, err)
	}
}

func TestTerminalKillEndsTheSessionGroup(t *testing.T) {
	a := testUpdateAgent()
	a.TerminalSessions = map[string]*TerminalSession{}
	pidFile := filepath.Join(t.TempDir(), "pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 300 & echo $! > "+pidFile+"; wait")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skip("no pty:", err)
	}
	waited := make(chan struct{})
	go func() { cmd.Wait(); close(waited) }()
	a.TerminalSessions["k"] = &TerminalSession{ID: "k", Cmd: cmd, Ptmx: ptmx}
	var pid int
	for i := 0; i < 50 && pid == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		b, _ := os.ReadFile(pidFile)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if pid == 0 {
		t.Fatal("no background pid")
	}
	a.KillTerminalSession("k")
	<-waited
	for i := 0; i < 50; i++ {
		if !alive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background process %d of the shell survived the kill", pid)
}

// Closing the terminal hangs up the jobs in groups of their own: one that
// ignores SIGHUP keeps running, the other ends.
func TestTerminalKillHangsUpJobs(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hupFile, nohupFile := filepath.Join(dir, "hup"), filepath.Join(dir, "nohup")
	a := testUpdateAgent()
	a.TerminalSessions = map[string]*TerminalSession{}
	cmd := exec.Command("/bin/sh", "-c", `"$0" -own-group "$1" & "$0" -own-group "$2" nohup & wait`, self, hupFile, nohupFile)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skip("no pty:", err)
	}
	waited := make(chan struct{})
	go func() { cmd.Wait(); close(waited) }()
	a.TerminalSessions["k"] = &TerminalSession{ID: "k", Cmd: cmd, Ptmx: ptmx}
	readPID := func(f string) int {
		for i := 0; i < 100; i++ {
			b, _ := os.ReadFile(f)
			if pid, _ := strconv.Atoi(string(b)); pid != 0 {
				return pid
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("no job pid in", f)
		return 0
	}
	hup, nohup := readPID(hupFile), readPID(nohupFile)
	t.Cleanup(func() { syscall.Kill(hup, syscall.SIGKILL); syscall.Kill(nohup, syscall.SIGKILL) })
	for _, pid := range []int{hup, nohup} {
		if g, err := syscall.Getpgid(pid); err != nil || g != pid || g == cmd.Process.Pid {
			t.Fatalf("job %d: group %d, %v", pid, g, err)
		}
	}
	a.KillTerminalSession("k")
	<-waited
	if !waitDead(hup) {
		t.Fatalf("job %d survived the hang-up", hup)
	}
	if !alive(nohup) {
		t.Fatalf("job %d that ignores SIGHUP was killed", nohup)
	}
}

// An exited child nobody has waited for yet is a zombie: dead to alive().
func TestAliveCountsZombieDead(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-exit", "0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	for i := 0; i < 250; i++ {
		if !alive(cmd.Process.Pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("an exited, unreaped child counts as alive")
}

func TestTerminalLimits(t *testing.T) {
	a := testUpdateAgent()
	a.TerminalSessions = map[string]*TerminalSession{}
	for i := 0; i < termMaxSessions; i++ {
		a.TerminalSessions[fmt.Sprint(i)] = &TerminalSession{}
	}
	if err := a.StartTerminalSession("new", "/bin/sh", nil); err == nil || err.Error() != fmt.Sprintf("too many terminal sessions on this agent (limit %d)", termMaxSessions) {
		t.Fatalf("cap: %v", err)
	}
	a.PendingTerminalResizes = map[string]PendingTerminalResize{"stale": {Rows: 1, Cols: 1, at: time.Now().Add(-2 * termPendingTTL)}}
	a.ResizeTerminalSession("fresh", 30, 100)
	if _, ok := a.PendingTerminalResizes["stale"]; ok || a.PendingTerminalResizes["fresh"].Cols != 100 {
		t.Fatalf("pending sizes %v", a.PendingTerminalResizes)
	}
}

func TestInstallNushell(t *testing.T) {
	asset := nushellRelease(runtime.GOOS, runtime.GOARCH, "0.1")
	if asset == "" {
		t.Skip("no nushell release for this platform")
	}
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "nu.tar.gz")
	writeTarGz(t, archive,
		&tar.Header{Name: "nu-0.1/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "nu-0.1/nu", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
	)
	tarSum, _ := fileSHA256(archive)
	customSum := sha256.Sum256([]byte("custom"))
	var downloads atomic.Int32
	var conf atomic.Value
	conf.Store(`{"install_nushell": true, "install_nushell_version": "0.1", "nushell_enable_config": true, "install_nushell_sha256": "` + tarSum + `"}`)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(conf.Load().(string)))
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			downloads.Add(1)
			http.ServeFile(w, r, archive)
		case r.URL.Path == "/custom/linux/"+runtime.GOARCH+"/0.1/nu":
			downloads.Add(1)
			w.Write([]byte("custom"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	oldURL, oldDelay, oldEtc := nuReleaseURL, runtimeInstallDelay, nixAgentEtcDir
	defer func() { nuReleaseURL, runtimeInstallDelay, nixAgentEtcDir = oldURL, oldDelay, oldEtc }()
	nuReleaseURL, runtimeInstallDelay, nixAgentEtcDir = ts.URL, func() {}, filepath.Join(tmp, "etc")

	a := testUpdateAgent()
	a.AgentID = "agent"
	a.NuBin = filepath.Join(tmp, "bin", "nu")
	a.Cert = writeCA(t, ts)
	a.rClient = resty.NewWithClient(ts.Client()).SetBaseURL(ts.URL)

	a.InstallNushell(false)
	if b, _ := os.ReadFile(a.NuBin); string(b) != "nn" {
		t.Fatalf("nu holds %q", b)
	}
	if st, _ := os.Stat(a.NuBin); st.Mode().Perm() != 0o755 {
		t.Fatalf("nu mode %v", st.Mode().Perm())
	}
	for _, f := range []string{"config.nu", "env.nu"} {
		if st, err := os.Stat(filepath.Join(nixAgentEtcDir, "nushell", f)); err != nil || st.Mode().Perm() != 0o744 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	a.InstallNushell(false)
	if downloads.Load() != 1 {
		t.Fatal("installed again without force")
	}

	// a failed forced download keeps the runtime that is there
	os.Rename(archive, archive+".gone")
	a.InstallNushell(true)
	if b, _ := os.ReadFile(a.NuBin); string(b) != "nn" {
		t.Fatalf("nu lost after a failed download: %q", b)
	}

	rt := scriptRuntime{name: "nushell", bin: a.NuBin, version: "0.1", customURL: ts.URL + "/custom/{OS}/{ARCH}/{VERSION}/nu", sha256: hex.EncodeToString(customSum[:])}
	if runtime.GOOS == "linux" {
		if err := a.installRuntime(rt, true); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(a.NuBin); string(b) != "custom" {
			t.Fatalf("custom url: nu holds %q", b)
		}
	}

	conf.Store(`{"install_nushell": false}`)
	os.Remove(a.NuBin)
	a.InstallNushell(true)
	if rmm.FileExists(a.NuBin) {
		t.Fatal("installed although the server switched it off")
	}
}

func TestUnixStubReplies(t *testing.T) {
	if r := registryRPC("registry_browse", payloadMap{"path": `HKLM\SOFTWARE`}); r["error"] != "registry access is only supported on Windows" {
		t.Fatalf("browse %v", r)
	}
	if r := registryRPC("registry_rename_value", payloadMap{"path": "x", "old_name": "a", "new_name": "b"}); r["error"] != "renaming registry values is only supported on Windows" {
		t.Fatalf("rename value %v", r)
	}
	a := testUpdateAgent()
	if r := a.ControlService("x", "start"); r.OK || r.Reason != "/na" {
		t.Fatalf("winsvcaction %+v", r)
	}
	for name, v := range map[string]interface{}{
		"listschedtasks": ListSchedTasks(),
		"eventlog":       a.GetEventLog("System", 1, 0),
		"winservices":    a.GetServices(),
		"softwarelist":   a.GetInstalledSoftware(),
	} {
		b, err := encodeMsgpack(v)
		if err != nil || len(b) != 1 || b[0] != 0x90 {
			t.Fatalf("%s is not an empty list: %x %v", name, b, err)
		}
	}
}
