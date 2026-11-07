// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/ugorji/go/codec"
)

// recorded on Debian 13 (systemd 257); the bullet line is the older systemd format
const sampleUnits = `apparmor.service                                      loaded    active   exited  Load AppArmor profiles
auditd.service                                        not-found inactive dead    auditd.service
cron.service                                          loaded    active   running Regular background program processing daemon
e2scrub_reap.service                                  loaded    inactive dead    Remove Stale Online ext4 Metadata Check Snapshots
getty@tty1.service                                    loaded    failed   failed  Getty on tty1
ssh.service                                           loaded    active   running OpenBSD Secure Shell server
systemd-fsck@dev-disk-by\x2duuid-316C\x2dC52A.service loaded    active   exited  File System Check on /dev/disk/by-uuid/316C-C52A
● ntpd.service                                        loaded    activating start   Network Time Service
mnt-data.mount                                        loaded    active   mounted /mnt/data
`

const sampleUnitFiles = `apparmor.service                             enabled         enabled
cron.service                                 enabled         enabled
cryptdisks.service                           masked          enabled
e2scrub_reap.service                         enabled         enabled
getty@.service                               enabled         enabled
rsync.service                                disabled        enabled
ssh.service                                  enabled         enabled
sshd.service                                 alias           -
sshd@.service                                indirect        enabled
systemd-journald.service                     static          -
`

const sampleShow = `MainPID=1449
Id=cron.service

MainPID=1106
Id=ssh.service

MainPID=0
Id=apparmor.service
`

func TestParseSystemd(t *testing.T) {
	svcs := mergeSystemd(parseSystemctlUnits(sampleUnits), parseUnitFiles(sampleUnitFiles))
	got := map[string]nixSvc{}
	for _, s := range svcs {
		got[s.Unit] = s
	}
	if _, ok := got["auditd.service"]; ok {
		t.Fatal("not-found unit listed")
	}
	if _, ok := got["mnt-data.mount"]; ok {
		t.Fatal("non-service listed")
	}
	for _, name := range []string{"getty@.service", "sshd@.service", "sshd.service"} {
		if _, ok := got[name]; ok {
			t.Fatal("template or alias listed:", name)
		}
	}
	for name, want := range map[string][2]string{
		"apparmor.service":         {"running", "true"},
		"cron.service":             {"running", "true"},
		"e2scrub_reap.service":     {"stopped", "true"},
		"getty@tty1.service":       {"failed", "nil"},
		"ntpd.service":             {"unknown", "nil"},
		"cryptdisks.service":       {"stopped", "false"},
		"rsync.service":            {"stopped", "false"},
		"systemd-journald.service": {"stopped", "nil"},
		`systemd-fsck@dev-disk-by\x2duuid-316C\x2dC52A.service`: {"running", "nil"},
	} {
		s, ok := got[name]
		if !ok {
			t.Fatal("missing", name)
		}
		en := "nil"
		if s.OnBoot != nil {
			en = map[bool]string{true: "true", false: "false"}[*s.OnBoot]
		}
		if s.State != want[0] || en != want[1] || s.Init != "systemd" {
			t.Fatalf("%s: got %s %s %s", name, s.State, en, s.Init)
		}
	}
	if d := got["ssh.service"].Desc; d != "OpenBSD Secure Shell server" {
		t.Fatal(d)
	}
	pids := parseSystemctlShow(sampleShow)
	if !reflect.DeepEqual(pids, map[string]int{"cron.service": 1449, "ssh.service": 1106}) {
		t.Fatal(pids)
	}
}

// launchctl list as root, print-disabled from macOS 14 plus the older true/false form
const sampleLaunchctl = "PID\tStatus\tLabel\n" +
	"-\t0\tcom.apple.ftp-proxy\n" +
	"412\t0\tcom.openssh.sshd\n" +
	"-\t78\tcom.example.crashy\n" +
	"-\t-15\tcom.example.stopped\n"

const samplePrintDisabled = `disabled services = {
	"com.apple.ftpd" => disabled
	"com.openssh.sshd" => enabled
	"com.example.crashy" => true
}
login item associations = {
}
`

func TestParseLaunchd(t *testing.T) {
	dir := t.TempDir()
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>Label</key>
	<string>com.example.agentd</string>
	<key>Disabled</key>
	<true/>
</dict></plist>`
	must(t, os.WriteFile(filepath.Join(dir, "agentd.plist"), []byte(xml), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "com.example.stopped.plist"), []byte("bplist00\x00\x01"), 0o644))

	plists := launchdPlists(dir)
	if p := plists["com.example.agentd"]; !p.disabled || p.path != filepath.Join(dir, "agentd.plist") {
		t.Fatal(plists)
	}
	svcs := mergeLaunchd(parseLaunchctlList(sampleLaunchctl), plists, parsePrintDisabled(samplePrintDisabled))
	got := map[string]nixSvc{}
	for _, s := range svcs {
		got[s.Unit] = s
	}
	if len(got) != 5 {
		t.Fatal(len(got), got)
	}
	ssh := got["com.openssh.sshd"]
	if ssh.State != "running" || ssh.MainPID == nil || *ssh.MainPID != 412 || ssh.OnBoot == nil || !*ssh.OnBoot || !ssh.loaded {
		t.Fatalf("%+v", ssh)
	}
	if s := got["com.example.crashy"]; s.State != "failed" || s.OnBoot == nil || *s.OnBoot {
		t.Fatalf("%+v", s)
	}
	if s := got["com.example.stopped"]; s.State != "stopped" || s.OnBoot == nil || !*s.OnBoot || s.plist == "" {
		t.Fatalf("%+v", s)
	}
	if s := got["com.example.agentd"]; s.loaded || s.State != "stopped" || s.OnBoot == nil || *s.OnBoot {
		t.Fatalf("%+v", s)
	}
	if s := got["com.apple.ftp-proxy"]; s.OnBoot != nil || s.MainPID != nil {
		t.Fatalf("%+v", s)
	}
}

// recorded on Alpine 3 (openrc, busybox-openrc), crond is listed twice there
const sampleRcStatus = ` * Caching service dependencies ... [ ok ]
Runlevel: nonetwork
Runlevel: default
 crond                                                             [  started  ]
 local                                                             [  stopped  ]
Runlevel: sysinit
Runlevel: boot
 syslog                                                            [  started  ]
 networking                                                        [  crashed  ]
Runlevel: shutdown
Dynamic Runlevel: hotplugged
Dynamic Runlevel: needed/wanted
 sysfs                                                             [  started 00:12:01 (0)  ]
Dynamic Runlevel: manual
 crond                                                             [  started  ]
 ` + "\x1b[0;32mnginx\x1b[0m" + `                                                             [  starting  ]
`

const sampleRcUpdate = `                crond |      default
                local |      default
               syslog | boot
           networking | boot default
`

func TestParseOpenRC(t *testing.T) {
	levels := parseRcUpdate(sampleRcUpdate)
	if !reflect.DeepEqual(levels["networking"], []string{"boot", "default"}) || len(levels) != 4 {
		t.Fatal(levels)
	}
	var got []string
	for _, s := range parseRcStatus(sampleRcStatus) {
		got = append(got, s.Unit+"="+s.State)
	}
	want := []string{"crond=running", "local=stopped", "syslog=running", "networking=failed", "sysfs=running", "nginx=unknown"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestNixNames(t *testing.T) {
	for _, ok := range []string{"ssh.service", "com.openssh.sshd", "net.eth0", "user@0.service", `systemd-fsck@dev-disk-by\x2duuid-316C\x2dC52A.service`} {
		if !nixNameRe.MatchString(ok) {
			t.Fatal("rejected", ok)
		}
	}
	for _, bad := range []string{"", "-rf", "--now", "a b", "a;b", `a"b`, "a'b", "../x", "a/b", "$(id)", "a\nb", strings.Repeat("a", 256)} {
		if nixNameRe.MatchString(bad) {
			t.Fatal("accepted", bad)
		}
	}
}

func TestSvcActionArgv(t *testing.T) {
	svc := func(mgr string) nixSvc {
		return nixSvc{UnixService: rmm.UnixService{Unit: "x", Init: mgr}}
	}
	ld, ldFile := svc("launchd"), svc("launchd")
	ld.loaded = true
	ldFile.plist = "/Library/LaunchDaemons/x.plist"
	rc := svc("openrc")
	rc.levels = []string{"boot", "default"}
	for _, c := range []struct {
		s      nixSvc
		action string
		want   [][]string
	}{
		{svc("systemd"), "restart", [][]string{{"systemctl", "restart", "x"}}},
		{svc("systemd"), "enable", [][]string{{"systemctl", "enable", "x"}}},
		{ld, "start", [][]string{{"launchctl", "kickstart", "system/x"}}},
		{ld, "restart", [][]string{{"launchctl", "kickstart", "-k", "system/x"}}},
		{ld, "stop", [][]string{{"launchctl", "bootout", "system/x"}}},
		{ld, "disable", [][]string{{"launchctl", "disable", "system/x"}}},
		{ldFile, "start", [][]string{{"launchctl", "bootstrap", "system", "/Library/LaunchDaemons/x.plist"}, {"launchctl", "kickstart", "system/x"}}},
		{rc, "stop", [][]string{{"rc-service", "x", "stop"}}},
		{rc, "enable", [][]string{{"rc-update", "add", "x", "default"}}},
		{rc, "disable", [][]string{{"rc-update", "del", "x", "boot"}, {"rc-update", "del", "x", "default"}}},
	} {
		if got := svcActionArgv(c.s, c.action); !reflect.DeepEqual(got, c.want) {
			t.Fatal(c.s.Init, c.action, got)
		}
	}
	if err := PosixSvcAction("ssh.service", "mask"); err == nil || err.Error() != "unknown action" {
		t.Fatal(err)
	}
	if err := PosixSvcAction("--now", "stop"); err == nil || err.Error() != "invalid service name" {
		t.Fatal(err)
	}
}

// an init script that leaves a child holding stderr must not block the reply
func TestNixAction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := nixAction(ctx, "sh", "-c", "sleep 10 & echo started"); err != nil || time.Since(start) > 5*time.Second {
		t.Fatal(err, time.Since(start))
	}
	if err := nixAction(ctx, "sh", "-c", "echo out; echo ' * ERROR: x failed to start' >&2; exit 1"); err == nil || err.Error() != "* ERROR: x failed to start" {
		t.Fatal(err)
	}
	if err := nixAction(ctx, "false"); err == nil || err.Error() != "false: exit status 1" {
		t.Fatal(err)
	}
}

// recorded on Debian 13, trimmed. the last three are journalctl's
// binary, oversized and repeated forms
const sampleJournal = `{"__REALTIME_TIMESTAMP":"1791357421302064","_SYSTEMD_UNIT":"cron.service","SYSLOG_IDENTIFIER":"CRON","PRIORITY":"6","MESSAGE":"(root) CMD (cd / && run-parts --report /etc/cron.hourly)","_TRANSPORT":"syslog"}
{"__REALTIME_TIMESTAMP":"1791357133592646","_TRANSPORT":"kernel","PRIORITY":"4","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"overlayfs: upperdir is in-use as upperdir/workdir of another mount"}
{"__REALTIME_TIMESTAMP":"1791357133592700","SYSLOG_IDENTIFIER":"app","MESSAGE":[104,105,255,10]}
{"__REALTIME_TIMESTAMP":"1791357133592800","SYSLOG_IDENTIFIER":"app","PRIORITY":"3","MESSAGE":null}
{"__REALTIME_TIMESTAMP":"1791357133592900","SYSLOG_IDENTIFIER":["a","b"],"MESSAGE":"two"}
`

func TestParseJournal(t *testing.T) {
	lines, err := parseJournal(strings.NewReader(sampleJournal))
	if err != nil || len(lines) != 5 {
		t.Fatal(err, lines)
	}
	l := lines[0]
	if l.TS != "2026-10-07T07:17:01.302064Z" || l.Unit != "cron.service" || l.Priority == nil || *l.Priority != 6 || !strings.HasPrefix(l.Text, "(root) CMD") {
		t.Fatalf("%+v", l)
	}
	if lines[1].Unit != "kernel" || *lines[1].Priority != 4 {
		t.Fatalf("%+v", lines[1])
	}
	if lines[2].Text != "hi�" || lines[2].Priority != nil {
		t.Fatalf("%q", lines[2].Text)
	}
	if lines[3].Text != "[message over 4096 bytes]" || lines[4].Unit != "a" {
		t.Fatalf("%+v", lines[3:])
	}
	if want := []string{"-o", "json", "--no-pager", "-q", "-n", "201", "-u", "ssh.service", "-p", "3", "--since=-30min"}; !reflect.DeepEqual(journalArgs(logQuery{unit: "ssh.service", priority: 3, lines: 200, since: 30}), want) {
		t.Fatal(journalArgs(logQuery{unit: "ssh.service", priority: 3, lines: 200, since: 30}))
	}
}

// log show --style json as macOS 14 prints it (slashes escaped), with a stray header line
// and a trailing object that is not an event
const sampleUnified = `Filtering the log data using "process == \"sshd\""
[{
  "traceID" : 4523,
  "eventMessage" : "Accepted publickey for admin from 10.0.0.5 port 50122 ssh2",
  "eventType" : "logEvent",
  "source" : null,
  "subsystem" : "",
  "category" : "",
  "processImagePath" : "\/usr\/sbin\/sshd",
  "timestamp" : "2026-10-07 11:17:01.301435+0200",
  "messageType" : "Default",
  "processID" : 412
},{
  "eventMessage" : "",
  "eventType" : "activityCreateEvent",
  "processImagePath" : "\/usr\/sbin\/sshd",
  "timestamp" : "2026-10-07 11:17:01.400000+0200",
  "messageType" : ""
},{
  "eventMessage" : "connection invalidated",
  "eventType" : "logEvent",
  "subsystem" : "com.apple.xpc",
  "processImagePath" : "\/usr\/libexec\/trustd",
  "timestamp" : "2026-10-07 11:18:00.000001+0200",
  "messageType" : "Error"
},{
  "eventMessage" : "verbose detail",
  "eventType" : "logEvent",
  "subsystem" : "com.apple.xpc",
  "processImagePath" : "\/usr\/libexec\/trustd",
  "timestamp" : "2026-10-07 11:18:01.000001+0200",
  "messageType" : "Info"
},{
  "finished" : 1
}]
`

func TestParseUnified(t *testing.T) {
	lines, err := parseUnified(strings.NewReader(sampleUnified), 10, -1)
	if err != nil || len(lines) != 3 {
		t.Fatal(err, lines)
	}
	l := lines[0]
	if l.TS != "2026-10-07T09:17:01.301435Z" || l.Unit != "sshd" || *l.Priority != 5 || !strings.HasPrefix(l.Text, "Accepted publickey") {
		t.Fatalf("%+v", l)
	}
	if lines[1].Unit != "com.apple.xpc" || *lines[1].Priority != 3 {
		t.Fatalf("%+v", lines[1])
	}
	// priority filter and newest-only window
	if lines, _ := parseUnified(strings.NewReader(sampleUnified), 10, 3); len(lines) != 1 || lines[0].Text != "connection invalidated" {
		t.Fatal(lines)
	}
	if lines, _ := parseUnified(strings.NewReader(sampleUnified), 1, -1); len(lines) != 1 || lines[0].Text != "verbose detail" {
		t.Fatal(lines)
	}
	if lines, err := parseUnified(strings.NewReader(""), 10, -1); err != nil || lines != nil {
		t.Fatal(lines, err)
	}
	want := []string{"show", "--style", "json", "--last", "10m", "--info", "--debug", "--predicate", `subsystem == "sshd" OR process == "sshd"`}
	if got := unifiedArgs(logQuery{unit: "sshd", priority: 7}); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestTailLines(t *testing.T) {
	buf := []byte("cut line\nl1\nl2\r\nl3\n\n")
	if got := tailLines(buf, true, 2); !reflect.DeepEqual(got, []string{"l2", "l3"}) {
		t.Fatal(got)
	}
	if got := tailLines(buf, true, 10); !reflect.DeepEqual(got, []string{"l1", "l2", "l3"}) {
		t.Fatal(got)
	}
	if got := tailLines(buf, false, 10); len(got) != 4 || got[0] != "cut line" {
		t.Fatal(got)
	}
	if got := tailLines(nil, false, 10); got != nil {
		t.Fatal(got)
	}
	if got := tailLines([]byte("no newline at all"), true, 10); got != nil {
		t.Fatal(got)
	}
}

func TestResolveLogPath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "a.log"), []byte("x\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "sub", "b.log"), []byte("x\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("x\n"), 0o644))
	must(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape.log")))
	must(t, os.Symlink(outside, filepath.Join(root, "dirlink")))
	must(t, os.Symlink(filepath.Join(root, "a.log"), filepath.Join(root, "inside.log")))

	for _, ok := range []string{"a.log", "sub/b.log", "inside.log"} {
		if _, err := resolveLogPath(root, filepath.Join(root, ok)); err != nil {
			t.Fatal(ok, err)
		}
	}
	// macOS: /var/log is /private/var/log behind a symlink
	link := filepath.Join(outside, "varlog")
	must(t, os.Symlink(root, link))
	if _, err := resolveLogPath(link, link+"/sub/b.log"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		root, root + "/", root + "/sub", root + "/escape.log", root + "/dirlink/secret",
		root + "/../" + filepath.Base(outside) + "/secret", root + "/./a.log", "a.log", root + "/missing.log",
	} {
		if _, err := resolveLogPath(root, bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

// a directory swapped for a symlink after resolveLogPath must not be followed
func TestOpenBeneathRefusesSwappedDir(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sub", "b.log"), []byte("in\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(outside, "b.log"), []byte("secret\n"), 0o644))
	p, err := resolveLogPath(root, filepath.Join(root, "sub", "b.log"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := openBeneath(root, p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	must(t, os.RemoveAll(filepath.Join(root, "sub")))
	must(t, os.Symlink(outside, filepath.Join(root, "sub")))
	if f, err := openBeneath(root, p); err == nil || !strings.Contains(err.Error(), "path must be a file under") {
		if f != nil {
			f.Close()
		}
		t.Fatal("followed the swapped directory:", err)
	}
}

func TestParseLogQuery(t *testing.T) {
	q, err := parseLogQuery(map[string]string{"source": "journal", "unit": "ssh.service", "priority": "3", "lines": "500", "since": "30"})
	if err != nil || q != (logQuery{source: "journal", unit: "ssh.service", priority: 3, lines: 500, since: 30}) {
		t.Fatal(q, err)
	}
	if q, err := parseLogQuery(map[string]string{"source": "file", "path": "/var/log/syslog"}); err != nil || q.lines != 200 || q.priority != -1 {
		t.Fatal(q, err)
	}
	// the server allows a year; systemd escapes stay valid for the journal
	if _, err := parseLogQuery(map[string]string{"source": "journal", "since": "525600", "unit": `systemd-fsck@dev-disk-by\x2duuid-316C\x2dC52A.service`}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]string{
		{"source": "journal", "lines": "49"},
		{"source": "journal", "lines": "2001"},
		{"source": "journal", "lines": "x"},
		{"source": "journal", "priority": "8"},
		{"source": "journal", "priority": "-1"},
		{"source": "journal", "since": "0"},
		{"source": "journal", "since": "525601"},
		{"source": "unified", "unit": `a\`},
		{"source": "journal", "unit": "--all"},
		{"source": "unified", "unit": `x" OR 1 == 1 OR "`},
		{"source": "file", "path": "/var/log/\xff"},
		{"source": "shell"},
		{},
	} {
		if _, err := parseLogQuery(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if _, err := PosixLogs(map[string]string{"source": "file", "path": "/etc/passwd"}); err == nil {
		t.Fatal("read outside /var/log")
	}
}

func TestCapLogs(t *testing.T) {
	var lines []rmm.PosixLogLine
	for i := 0; i < 2001; i++ {
		lines = append(lines, logLine("", "", nil, strings.Repeat("ä", 3000)))
	}
	if len(lines[0].Text) > nixMaxMsg || !utf8.ValidString(lines[0].Text) {
		t.Fatal(len(lines[0].Text))
	}
	r := capLogs(lines, 2000, false)
	size := 0
	for _, l := range r.Lines {
		size += len(l.Text) + 48
	}
	if !r.Truncated || len(r.Lines) >= 2000 || size > nixMaxReply {
		t.Fatal(r.Truncated, len(r.Lines), size)
	}
	if r := capLogs(lines[:50], 50, false); r.Truncated || len(r.Lines) != 50 {
		t.Fatal(r.Truncated, len(r.Lines))
	}
	if r := capLogs(nil, 50, false); r.Lines == nil {
		t.Fatal("nil lines")
	}
	if s := clipUTF8("ok\xff\xfe", 100); s != "ok�" {
		t.Fatalf("%q", s)
	}
}

// the server reads these with msgpack; null stays null
func TestPosixWireShape(t *testing.T) {
	var b []byte
	svcs := []rmm.UnixService{{Unit: "ssh.service", State: "running", OnBoot: ptr(true), MainPID: ptr(1106), Init: "systemd"}, {Unit: "x", State: "stopped", Init: "launchd"}}
	logs := capLogs([]rmm.PosixLogLine{logLine("2026-10-07T09:17:01.302064Z", "cron.service", ptr(6), "hello")}, 50, false)
	must(t, codec.NewEncoderBytes(&b, new(codec.MsgpackHandle)).Encode([]interface{}{svcs, logs}))
	var got []interface{}
	mh := codec.MsgpackHandle{}
	mh.RawToString = true
	must(t, codec.NewDecoderBytes(b, &mh).Decode(&got))
	s := got[0].([]interface{})[1].(map[interface{}]interface{})
	if len(s) != 6 || s["enabled"] != nil || s["pid"] != nil || s["name"] != "x" || s["description"] != "" {
		t.Fatal(s)
	}
	l := got[1].(map[interface{}]interface{})
	line := l["lines"].([]interface{})[0].(map[interface{}]interface{})
	if l["truncated"] != false || len(line) != 4 || line["unit"] != "cron.service" || line["message"] != "hello" {
		t.Fatal(l)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
