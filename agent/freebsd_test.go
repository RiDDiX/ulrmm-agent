// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// unit tests run against the default layout, also on a TrueNAS host
func init() { setNixLayout(false) }

func rmmSvc(name, status string, enabled bool) rmm.UnixService {
	return rmm.UnixService{Unit: name, State: status, OnBoot: ptr(enabled)}
}

// testdata/freebsd: output captured on the FreeBSD 14.4 test VM, after the
// header that says how.
func fbFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "freebsd", name))
	if err != nil {
		t.Fatal(err)
	}
	_, out, ok := strings.Cut(string(b), "# ---\n")
	if !ok {
		t.Fatalf("%s: no header", name)
	}
	return out
}

func TestRcNames(t *testing.T) {
	if rcName() != "ulrmm_agent" || rcScriptPath() != "/usr/local/etc/rc.d/ulrmm_agent" || healCronPath() != "/etc/cron.d/ulrmm-agent-selfheal" {
		t.Fatalf("%s %s %s", rcName(), rcScriptPath(), healCronPath())
	}
	old := IdentNixSvc
	defer func() { IdentNixSvc = old }()
	IdentNixSvc = "acme-rmm-agent.service"
	if rcName() != "acme_rmm_agent" || healCronPath() != "/etc/cron.d/acme-rmm-agent-selfheal" {
		t.Fatalf("%s %s", rcName(), healCronPath())
	}
}

func TestRcScript(t *testing.T) {
	old := BrandAgentName
	defer func() { BrandAgentName = old }()
	BrandAgentName = `Joe's "RMM" $agent`
	s := rcScript("/usr/local/bin/ulrmm-agent")
	for _, want := range []string{
		"# PROVIDE: ulrmm_agent\n# REQUIRE: LOGIN NETWORKING\n# KEYWORD: shutdown\n",
		"name=ulrmm_agent\n", "rcvar=ulrmm_agent_enable\n", `: ${ulrmm_agent_enable:="NO"}`,
		`desc='Joe'\''s "RMM" $agent'`,
		`pidfile="/var/run/${name}.pid"`, `procname="/usr/sbin/daemon"`,
		`command_args="-R 5 -P ${pidfile} -f /usr/local/bin/ulrmm-agent -m svc"`,
		`run_rc_command "$1"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte(s), 0o755)
	if out, err := exec.Command("/bin/sh", "-n", f).CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v %s", err, out)
	}
	// the description survives the quoting
	if out, err := exec.Command("/bin/sh", "-c", "eval \"$(grep ^desc= "+f+")\"; printf %s \"$desc\"").Output(); err != nil || string(out) != BrandAgentName {
		t.Fatalf("desc %q %v", out, err)
	}
	if c := healCron("/opt/ulrmm-agent/selfheal/ulrmm-agent"); !strings.Contains(c, "\n*/15 * * * * root /opt/ulrmm-agent/selfheal/ulrmm-agent -m selfheal >/dev/null 2>&1\n") ||
		!strings.Contains(c, "\nPATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\n") {
		t.Fatalf("cron:\n%s", c)
	}
}

func TestParseRcd(t *testing.T) {
	en := parseServiceEnabled(fbFixture(t, "service_e.txt"))
	if !en["sshd"] || !en["cron"] || !en["firstboot_freebsd_update"] || en["ntpd"] || en["/etc/rc.d/sshd"] {
		t.Fatalf("enabled: %v", en)
	}
	list := strings.Fields(fbFixture(t, "service_l.txt"))
	if len(list) < 150 || !stringInSlice("sshd", list) || !stringInSlice("ntpd", list) {
		t.Fatalf("service -l: %d names", len(list))
	}
	for _, n := range list {
		if !nixNameRe.MatchString(n) {
			t.Fatalf("%q refused", n)
		}
	}
	if st, pid := parseRcdStatus(fbFixture(t, "onestatus_running.txt")); st != "running" || pid == nil || *pid != 937 {
		t.Fatalf("running: %s %v", st, pid)
	}
	if st, pid := parseRcdStatus(fbFixture(t, "onestatus_stopped.txt")); st != "stopped" || pid != nil {
		t.Fatalf("stopped: %s %v", st, pid)
	}
	if st, _ := parseRcdStatus(fbFixture(t, "onestatus_nostatus.txt")); st != "unknown" {
		t.Fatalf("no status: %s", st)
	}
	if d := rcDesc("#!/bin/sh\n. /etc/rc.subr\n\nname=\"sshd\"\ndesc=\"Secure Shell Daemon\"\n"); d != "Secure Shell Daemon" {
		t.Fatalf("desc %q", d)
	}

	// /etc/rc.d/newsyslog of the VM
	newsyslog := "name=\"newsyslog\"\ndesc=\"Logfile rotation\"\nrcvar=\"newsyslog_enable\"\nrequired_files=\"/etc/newsyslog.conf\"\ncommand=\"/usr/sbin/${name}\"\nstart_cmd=\"newsyslog_start\"\nstop_cmd=\":\"\n"
	if !rcOneshot(newsyslog) || rcOneshot("name=sshd\npidfile=/var/run/sshd.pid\n") {
		t.Fatal("one-shot")
	}
	svcs := []nixSvc{
		{UnixService: rmmSvc("sshd", "running", true)},
		{UnixService: rmmSvc("ntpd", "stopped", true)},
		{UnixService: rmmSvc("zfs", "unknown", true)},
		{UnixService: rmmSvc("newsyslog", "stopped", true), oneshot: true},
	}
	total, failed, units := rcdFailed(svcs)
	if total != 2 || failed != 1 || len(units) != 1 || units[0].Name != "ntpd" || units[0].Active != "failed" {
		t.Fatalf("%d %d %+v", total, failed, units)
	}

	s := nixSvc{UnixService: rmmSvc("sshd", "running", true)}
	s.Init = "rc.d"
	for action, want := range map[string][]string{
		"start": {"service", "sshd", "onestart"}, "stop": {"service", "sshd", "onestop"}, "restart": {"service", "sshd", "onerestart"},
		"enable": {"service", "sshd", "enable"}, "disable": {"service", "sshd", "disable"},
	} {
		if got := svcActionArgv(s, action); !reflect.DeepEqual(got, [][]string{want}) {
			t.Fatalf("%s: %v", action, got)
		}
	}
}

func TestParsePsFreeBSD(t *testing.T) {
	// FreeBSD ps reads "pid=,uid=,..." as one column with a long header
	if got := parsePs(fbFixture(t, "ps_combined_o.txt"), func(string) string { return "" }); len(got) != 0 {
		t.Fatalf("combined -o parsed: %v", got)
	}
	got := parsePs(fbFixture(t, "ps.txt"), func(uid string) string { return "u" + uid })
	if _, ok := got[0]; ok || len(got) < 30 {
		t.Fatalf("%d processes, pid 0 kept: %v", len(got), ok)
	}
	if p := got[1]; p.name != "init" || p.user != "u0" || p.mem != 1336*1024 || p.cpu != 800*time.Millisecond {
		t.Fatalf("init: %+v", p)
	}
}

func TestParseFreeBSDHardware(t *testing.T) {
	if d := parseGeomDisks(fbFixture(t, "geom_disk_list.txt")); !reflect.DeepEqual(d, []string{"vtbd0 " + ByteCountSI(21474836480)}) {
		t.Fatalf("disks %q", d)
	}
	ssd := "Geom name: ada0\nProviders:\n1. Name: ada0\n   Mediasize: 500107862016 (466G)\n   descr: Samsung SSD 860 EVO 500GB\n   rotationrate: 0\n\nGeom name: ada1\nProviders:\n1. Name: ada1\n   Mediasize: 4000787030016 (3.6T)\n   descr: WDC WD40EFRX\n   rotationrate: 5400\n"
	if d := parseGeomDisks(ssd); !reflect.DeepEqual(d, []string{"Samsung SSD 860 EVO 500GB  SSD ada0 " + ByteCountSI(500107862016), "WDC WD40EFRX  HDD ada1 " + ByteCountSI(4000787030016)}) {
		t.Fatalf("disks %q", d)
	}
	if g := parsePciconfGPUs(fbFixture(t, "pciconf_lv.txt")); !reflect.DeepEqual(g, []string{"0x1234 0x1111"}) {
		t.Fatalf("gpus %q", g)
	}
	named := "vgapci0@pci0:0:2:0:\tclass=0x030000 rev=0x0c hdr=0x00 vendor=0x8086 device=0x0412\n    vendor     = 'Intel Corporation'\n    device     = 'Xeon E3-1200 v3/4th Gen Core Processor Integrated Graphics Controller'\n    class      = display\n    subclass   = VGA\n"
	if g := parsePciconfGPUs(named); !reflect.DeepEqual(g, []string{"Intel Corporation Xeon E3-1200 v3/4th Gen Core Processor Integrated Graphics Controller"}) {
		t.Fatalf("gpus %q", g)
	}

	vt := fbFixture(t, "ifconfig_m_vtnet0.txt")
	if w := parseIfconfigWoL(vt); w != "unsupported" {
		t.Fatalf("vtnet0: %s", w)
	}
	// WOL_MAGIC added to the captured lines, as em(4) reports it
	off := strings.Replace(vt, "capabilities=990028<VLAN_MTU,", "capabilities=990028<WOL_MAGIC,VLAN_MTU,", 1)
	on := strings.Replace(off, "options=880028<VLAN_MTU,", "options=880028<WOL_MAGIC,VLAN_MTU,", 1)
	if parseIfconfigWoL(off) != "off" || parseIfconfigWoL(on) != "on" {
		t.Fatalf("%s %s", parseIfconfigWoL(off), parseIfconfigWoL(on))
	}
}

func TestParseFreeBSDSensors(t *testing.T) {
	if s := parseSysctlTemps(fbFixture(t, "sysctl_temps_qemu.txt")); len(s) != 0 {
		t.Fatalf("QEMU has no sensors: %+v", s)
	}
	// value format of coretemp(4) and acpi_thermal(4): Celsius with a trailing C
	out := "dev.cpu.0.temperature=45.0C\ndev.cpu.1.temperature=47.0C\ndev.cpu.0.%desc=ACPI CPU\n" +
		"hw.acpi.thermal.tz0.temperature=95.0C\nhw.acpi.thermal.tz0._CRT=100.0C\nhw.acpi.thermal.tz0._HOT=-1\nhw.acpi.thermal.tz0._PSV=90.0C\n" +
		"hw.acpi.thermal.tz1.temperature=27.9C\nhw.acpi.thermal.tz1._CRT=-1C\n"
	got := sysctlSensors(parseSysctlTemps(out))
	if len(got) != 4 || got[0].Name != "cpu0" || got[0].Value != 45 || got[0].Source != "sysctl" || got[0].Status != "ok" {
		t.Fatalf("%+v", got)
	}
	tz0 := got[2]
	if tz0.Name != "acpi tz0" || *tz0.Crit != 100 || *tz0.Warn != 90 || tz0.Status != "warn" {
		t.Fatalf("tz0 %+v", tz0)
	}
	if got[3].Crit != nil || got[3].Warn != nil {
		t.Fatalf("tz1 limits %+v", got[3])
	}
	if s := parseSleepS3(fbFixture(t, "sysctl_sleep.txt")); !s {
		t.Fatal("S3 not seen")
	}
}

func TestParseGeomRaid(t *testing.T) {
	ok := parseGeomRaid(fbFixture(t, "gmirror_complete.txt"), "gmirror")
	if len(ok) != 1 || ok[0].Name != "mirror/test_gm0" || ok[0].Health != "ok" || ok[0].State != "complete" || *ok[0].Devices != 2 || *ok[0].Failed != 0 {
		t.Fatalf("%+v", ok)
	}
	deg := parseGeomRaid(fbFixture(t, "gmirror_degraded.txt"), "gmirror")
	if len(deg) != 1 || deg[0].Health != "degraded" || *deg[0].Devices != 1 {
		t.Fatalf("%+v", deg)
	}
	syn := parseGeomRaid(fbFixture(t, "gmirror_sync.txt"), "gmirror")
	if len(syn) != 1 || syn[0].Health != "degraded" || syn[0].SyncPct == nil || *syn[0].SyncPct != 4 || *syn[0].Failed != 0 {
		t.Fatalf("%+v", syn)
	}
	// graid could not be built on md(4) disks (no serial); g_raid state names
	gr := parseGeomRaid("raid/r0  SUBOPTIMAL  ada0 (ACTIVE (ACTIVE))\nraid/r0  SUBOPTIMAL  ada1 (FAILED)\n", "graid")
	if len(gr) != 1 || gr[0].Health != "degraded" || *gr[0].Failed != 1 || gr[0].Kind != "graid" {
		t.Fatalf("%+v", gr)
	}
	if z := parseZpool(fbFixture(t, "zpool_list.txt")); len(z) != 1 || z[0].Name != "zroot" || z[0].Health != "ok" {
		t.Fatalf("%+v", z)
	}
}

func TestParseFreeBSDServicesOut(t *testing.T) {
	tm, ok := parseNtpqRV(fbFixture(t, "ntpq_rv_unsynced.txt"))
	if !ok || tm.Source != "ntpd" || tm.Synced == nil || *tm.Synced || tm.Server != "" || tm.OffsetMs == nil || *tm.OffsetMs != 0 {
		t.Fatalf("%+v", tm)
	}
	if tm, _ := parseNtpqRV(fbFixture(t, "ntpq_rv_syncing.txt")); *tm.Synced {
		t.Fatal("leap=11 counted as synced")
	}
	tm, _ = parseNtpqRV(fbFixture(t, "ntpq_rv_synced.txt"))
	if !*tm.Synced || tm.Server != "46.4.54.78" || *tm.OffsetMs != 0.493952 {
		t.Fatalf("%+v", tm)
	}
	if scan := parseSmartScan(fbFixture(t, "smartctl_scan.txt")); len(scan) != 2 || scan[0] != [2]string{"/dev/cd0", "atacam"} {
		t.Fatalf("scan %v", scan)
	}
	if d, err := parseSmartctl([]byte(fbFixture(t, "smartctl_cd0.json"))); err != nil || d.Bus != "ata" || d.Smart != "unknown" {
		t.Fatalf("cd0 %+v %v", d, err)
	}
	if _, ok := parseNtpqRV("ntpq: read: Connection refused\n"); ok {
		t.Fatal("ntpd not running parsed")
	}
	if p := parsePfInfo(fbFixture(t, "pfctl_info_disabled.txt")); p == nil || *p {
		t.Fatalf("disabled %v", p)
	}
	if p := parsePfInfo(fbFixture(t, "pfctl_info_enabled.txt")); p == nil || !*p {
		t.Fatalf("enabled %v", p)
	}
	if parsePfInfo("pfctl: /dev/pf: No such file or directory\n") != nil {
		t.Fatal("no pf parsed")
	}
	// labels as in the acpiconf binary of 14.4 (strings); no battery in QEMU
	b := parseAcpiconfBattery("Design capacity:\t48000 mWh\nLast full capacity:\t41280 mWh\nTechnology:\tsecondary (rechargeable)\nCycle Count:\t\t312\nState:\t\t\thigh\n")
	if b == nil || *b.MaxCapacityPct != 86 || *b.Cycles != 312 {
		t.Fatalf("%+v", b)
	}
	if parseAcpiconfBattery("Design capacity:\tunknown\nState:\t\t\tnot present\n") != nil {
		t.Fatal("absent battery parsed")
	}
	if ttys, err := parseWhoTTYs(fbFixture(t, "who.txt")); err != nil || strings.Join(ttys, ",") != "ttyu0,pts/0" {
		t.Fatalf("%v %v", ttys, err)
	}
	if !fstabHasProcfs("# Device Mountpoint FStype Options Dump Pass#\n/dev/gpt/efiboot0 /boot/efi msdosfs rw 2 2\nproc\t/proc\tprocfs\trw\t0\t0\n") ||
		fstabHasProcfs("#proc /proc procfs rw 0 0\n") {
		t.Fatal("fstab procfs line")
	}
	if !strings.Contains(fbFixture(t, "mount_procfs.txt"), " on /proc ") {
		t.Fatal("mount -t procfs format")
	}
}

func TestEnsureProcfsFstab(t *testing.T) {
	old := fstabPath
	defer func() { fstabPath = old }()
	fstabPath = filepath.Join(t.TempDir(), "fstab")
	os.WriteFile(fstabPath, []byte("/dev/gpt/efiboot0 /boot/efi msdosfs rw 2 2"), 0o644)
	if addProcfsToFstab() != nil || addProcfsToFstab() != nil {
		t.Fatal("write")
	}
	b, _ := os.ReadFile(fstabPath)
	if string(b) != "/dev/gpt/efiboot0 /boot/efi msdosfs rw 2 2\nproc\t/proc\tprocfs\trw\t0\t0\n" {
		t.Fatalf("%q", b)
	}
}

func TestUninstallPlanFreeBSD(t *testing.T) {
	var s []string
	for _, p := range uninstallPlan("freebsd", []string{"/opt/ulrmm-mesh/meshagent"}) {
		if p.remove != "" {
			s = append(s, "rm "+p.remove)
		} else {
			s = append(s, strings.Join(p.argv, " "))
		}
	}
	want := []string{
		"env XAUTHORITY=foo DISPLAY=bar /opt/ulrmm-mesh/meshagent -uninstall",
		"service meshagent onestop",
		"sysrc -x meshagent_enable",
		"rm /usr/local/etc/rc.d/meshagent",
		"service ulrmm_agent onestop",
		"sysrc -x ulrmm_agent_enable",
		"rm /usr/local/etc/rc.d/ulrmm_agent",
		"rm /usr/local/bin/" + IdentNixBin,
		"rm /opt/ulrmm-mesh",
		"rm " + IdentNixConf,
		"rm " + IdentNixConf + ".kek",
		"rm " + IdentNixConf + ".kek.cred",
		"rm " + IdentNixConf + ".kek.host.cred",
		"rm " + IdentNixDir,
		"rm /var/log/" + IdentNixBin + ".log",
		"rm /var/log/" + IdentNixBin + ".log.1",
		"rm /var/log/" + IdentNixBin + ".log.2",
	}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("plan:\n%s", strings.Join(s, "\n"))
	}
}

func TestTrueNASLayout(t *testing.T) {
	defer setNixLayout(false)
	setNixLayout(false)
	def := []string{etcConfig, nixAgentDir, nixAgentBin, nixAgentBinDir, nixAgentEtcDir, nixMeshDir, nixMeshAgentBin, nixMeshUnit, nixMainBin, rollbackCopy, nixTmpDir}
	if !reflect.DeepEqual(def, []string{"/etc/ulrmm-agent", "/opt/ulrmm-agent", "/opt/ulrmm-agent/ulrmm-agent", "/opt/ulrmm-agent/bin", "/opt/ulrmm-agent/etc",
		"/opt/ulrmm-mesh", "/opt/ulrmm-mesh/meshagent", "/lib/systemd/system/meshagent.service", "/usr/local/bin/ulrmm-agent",
		"/opt/ulrmm-agent/ulrmm-agent.previous", "/opt/ulrmm-agent/tmp"}) || onTrueNAS {
		t.Fatalf("default layout %q", def)
	}

	setNixLayout(true)
	got := []string{etcConfig, nixAgentDir, nixAgentBin, nixAgentBinDir, nixAgentEtcDir, nixMeshDir, nixMeshAgentBin, nixMeshUnit, nixMainBin, rollbackCopy, nixTmpDir}
	want := []string{"/root/ulrmm-agent/ulrmm-agent.conf", "/root/ulrmm-agent", "/root/ulrmm-agent/ulrmm-agent", "/root/ulrmm-agent/bin", "/root/ulrmm-agent/etc",
		"/root/ulrmm-mesh", "/root/ulrmm-mesh/meshagent", "/etc/systemd/system/meshagent.service", "/root/ulrmm-agent/ulrmm-agent",
		"/root/ulrmm-agent/ulrmm-agent.previous", "/var/tmp/ulrmm-agent"}
	if !reflect.DeepEqual(got, want) || !onTrueNAS {
		t.Fatalf("TrueNAS layout %q", got)
	}
	for _, p := range got {
		if strings.HasPrefix(p, "/opt/") || strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/tmp/") {
			t.Fatalf("%s is read-only on TrueNAS", p)
		}
	}
	if c := trueNASInitCommand(); c != "/root/ulrmm-agent/selfheal/ulrmm-agent -m selfheal" {
		t.Fatalf("init command %q", c)
	}
	u := trueNASMeshUnit()
	for _, l := range []string{"WorkingDirectory=/root/ulrmm-mesh\n", "ExecStart=/root/ulrmm-mesh/meshagent\n", "Restart=always\n", "RestartSec=3\n", "StandardOutput=null\n", "WantedBy=multi-user.target\n"} {
		if !strings.Contains(u, l) {
			t.Fatalf("mesh unit lacks %q:\n%s", l, u)
		}
	}

	var s []string
	for _, p := range uninstallPlan("linux", []string{nixMeshAgentBin}) {
		if p.remove != "" {
			s = append(s, "rm "+p.remove)
		}
	}
	if strings.Join(s, "\n") != "rm /etc/systemd/system/meshagent.service\nrm /etc/systemd/system/ulrmm-agent.service\nrm /root/ulrmm-agent/ulrmm-agent\n"+
		"rm /root/ulrmm-mesh\nrm /root/ulrmm-agent/ulrmm-agent.conf\nrm /root/ulrmm-agent/ulrmm-agent.conf.kek\nrm /root/ulrmm-agent/ulrmm-agent.conf.kek.cred\nrm /root/ulrmm-agent/ulrmm-agent.conf.kek.host.cred\nrm /root/ulrmm-agent\nrm /var/log/ulrmm-agent.log\nrm /var/log/ulrmm-agent.log.1\nrm /var/log/ulrmm-agent.log.2" {
		t.Fatalf("TrueNAS plan:\n%s", strings.Join(s, "\n"))
	}
}

func TestIsTrueNAS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	old := trueNASMarkers
	defer func() { trueNASMarkers = old }()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "manifest.json"), filepath.Join(dir, "midclt")
	trueNASMarkers = []string{a, b}
	if isTrueNAS() {
		t.Fatal("no markers")
	}
	os.WriteFile(a, []byte(`{"version": "25.04.2.6"}`), 0o644)
	if isTrueNAS() {
		t.Fatal("one marker")
	}
	os.WriteFile(b, nil, 0o755)
	if !isTrueNAS() {
		t.Fatal("both markers")
	}
}

func TestCheckExecFormatFreeBSD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	self, _ := os.Executable()
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	// EI_OSABI, ELFOSABI_FREEBSD: how Go marks a FreeBSD build
	b[7] = 9
	fb := filepath.Join(t.TempDir(), "agent")
	os.WriteFile(fb, b, 0o755)
	if err := checkExecFormat(fb, "freebsd", runtime.GOARCH); err != nil {
		t.Fatalf("FreeBSD ELF refused: %v", err)
	}
	if checkExecFormat(self, "freebsd", runtime.GOARCH) == nil {
		t.Fatal("Linux ELF accepted on FreeBSD")
	}
	if checkExecFormat(fb, "linux", runtime.GOARCH) == nil {
		t.Fatal("FreeBSD ELF accepted on Linux")
	}
}

func TestFreeBSDSmallRules(t *testing.T) {
	if !meshSupported("freebsd", "amd64") || meshSupported("freebsd", "arm64") || !meshSupported("linux", "arm64") || !meshSupported("darwin", "arm64") {
		t.Fatal("mesh support")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if nushellRelease("freebsd", arch, "0.1") != "" || denoRelease("freebsd", arch, "1.0") != "" {
			t.Fatalf("a %s release on freebsd", arch)
		}
	}
	if nixShell("sh") != "/bin/sh" || nixShell("/bin/zsh") != "/bin/zsh" || nixShell("") != "" {
		t.Fatal("nixShell")
	}
	bash := "/bin/sh"
	if _, err := os.Stat("/bin/bash"); err == nil {
		bash = "/bin/bash"
	}
	if nixShell("/bin/bash") != bash {
		t.Fatal("nixShell bash")
	}
}

func TestScriptDirRefusesALink(t *testing.T) {
	old := nixTmpDir
	defer func() { nixTmpDir = old }()
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "elsewhere"), 0o755)
	nixTmpDir = filepath.Join(dir, "tmp")
	os.Symlink(filepath.Join(dir, "elsewhere"), nixTmpDir)
	if f, err := createNixTmpFile(""); err == nil {
		f.Close()
		t.Fatal("script dir behind a link accepted")
	}
	if st, _ := os.Stat(filepath.Join(dir, "elsewhere")); st.Mode().Perm() != 0o755 {
		t.Fatalf("link target changed to %v", st.Mode().Perm())
	}
}
