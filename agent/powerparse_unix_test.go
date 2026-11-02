// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"testing"
	"time"
)

func TestParseNotifyLine(t *testing.T) {
	// a pty ends lines with \r\n
	k, st, ok := parseNotifyLine("1793541910.123 com.apple.powermanagement.systempowerstate 25 port\r")
	if k != keyPowerState || st != 25 || !ok {
		t.Fatal(k, st, ok)
	}
	k, _, ok = parseNotifyLine("1793541910.123 com.apple.loginwindow.restartinitiated : Failed with code 1 port")
	if loginwindowKinds[k] != "restart" || ok {
		t.Fatal(k, ok)
	}
	if k, _, _ := parseNotifyLine("1793541910.123"); k != "" {
		t.Fatal(k)
	}
}

func TestPowerStateKind(t *testing.T) {
	for st, want := range map[uint64]string{0x0: "sleep", 0x18: "sleep", 0x19: "darkwake", 0x1f: "wake"} {
		if got := powerStateKind(st); got != want {
			t.Errorf("%#x: %s, want %s", st, got, want)
		}
	}
}

func TestParseShutdownLog(t *testing.T) {
	for _, c := range []struct{ in, kind, ini string }{
		{`{"eventMessage":"System shutdown initiated by: shutdown.45074<-sshd.12"}
{"eventMessage":"reboot by hoakley: patch night"}`, "restart", "hoakley: patch night"},
		{`{"eventMessage":"System shutdown initiated by: loginwindow.155<-loginwindow.155"}`, "shutdown_or_restart", "loginwindow.155<-loginwindow.155"},
		{`Filtering the log data using "eventMessage CONTAINS[c] ..."
{"eventMessage":"halt by root: "}`, "shutdown", "root"},
		{`{"eventMessage":"shutdown by admin: disk swap"}`, "shutdown", "admin: disk swap"},
	} {
		kind, ini, ok := parseShutdownLog(c.in)
		if !ok || kind != c.kind || ini != c.ini {
			t.Errorf("%q: %q %q %v", c.in, kind, ini, ok)
		}
	}
	for _, in := range []string{"", `{"eventMessage":"rebooting soon"}`, "not json"} {
		if _, _, ok := parseShutdownLog(in); ok {
			t.Errorf("%q matched", in)
		}
	}
}

func TestDarwinStopKind(t *testing.T) {
	oldWS, oldLog := willShutdown, shutdownLog
	defer func() {
		willShutdown, shutdownLog = oldWS, oldLog
		setLoginNotice("", "", false)
	}()
	reboot := `{"eventMessage":"reboot by maxi: update"}`
	for _, c := range []struct {
		name       string
		ws         bool
		lwKind     string
		lwTrusted  bool
		lwAge      time.Duration
		log        string
		kind, ini  string
		wantLogRun bool
	}{
		{"loginwindow first", true, "restart", false, time.Minute, reboot, "restart", "anna", false},
		{"trusted loginwindow", false, "restart", true, time.Minute, reboot, "restart", "anna", false},
		{"untrusted loginwindow alone", false, "restart", false, time.Minute, "", "", "", true},
		{"old loginwindow", false, "shutdown", true, 11 * time.Minute, reboot, "restart", "maxi: update", true},
		{"cancelled", false, "cancel", true, time.Minute, "", "", "", true},
		{"sysctl skips the log", true, "", false, 0, reboot, "shutdown_or_restart", "", false},
		{"log without sysctl", false, "", false, 0, reboot, "restart", "maxi: update", true},
		{"service stop", false, "", false, 0, "", "", "", true},
	} {
		ran := false
		willShutdown = func() bool { return c.ws }
		shutdownLog = func() string { ran = true; return c.log }
		setLoginNotice(c.lwKind, "anna", c.lwTrusted)
		loginNotice.at = time.Now().Add(-c.lwAge)
		kind, ini := darwinStopKind()
		if kind != c.kind || ini != c.ini || ran != c.wantLogRun {
			t.Errorf("%s: %q %q log=%v", c.name, kind, ini, ran)
		}
	}
}
