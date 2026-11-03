// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestKeepAwakeSpan(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, until := range []int64{0, -5, now.Unix() - 1, now.Unix()} {
		if d, err := keepAwakeSpan(until, now); err != nil || d != 0 {
			t.Fatalf("%d: %v %v, want cancel", until, d, err)
		}
	}
	if d, err := keepAwakeSpan(now.Unix()+3600, now); err != nil || d != time.Hour {
		t.Fatalf("%v %v", d, err)
	}
	if d, err := keepAwakeSpan(now.Unix()+6*3600, now); err != nil || d != 6*time.Hour {
		t.Fatalf("6h is allowed: %v %v", d, err)
	}
	if _, err := keepAwakeSpan(now.Unix()+6*3600+1, now); err == nil {
		t.Fatal("more than 6 h accepted")
	}
}

func TestKeepAwakeCancelWithoutHold(t *testing.T) {
	// until <= now only releases, it never starts a hold
	if err := KeepAwake(time.Now().Unix() - 10); err != nil {
		t.Fatal(err)
	}
	awake.Lock()
	defer awake.Unlock()
	if awake.release != nil || awake.timer != nil {
		t.Fatal("hold started")
	}
}

func TestKeepAwakeArgv(t *testing.T) {
	mac := keepAwakeArgv("darwin", time.Hour, 4242)
	if strings.Join(mac, " ") != "/usr/bin/caffeinate -i -s -t 3601 -w 4242" {
		t.Fatalf("%q", mac)
	}
	lin := keepAwakeArgv("linux", time.Hour, 4242)
	if lin[0] != "systemd-inhibit" || lin[1] != "--what=sleep:idle:handle-lid-switch" || lin[4] != "--mode=block" ||
		strings.Join(lin[5:], " ") != "timeout 3601 tail --pid=4242 -f /dev/null" {
		t.Fatalf("%q", lin)
	}
}

// the logind hold must end with the agent, KillMode=process leaves children alive
func TestKeepAwakeHoldEndsWithAgent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GNU tail --pid")
	}
	agent := exec.Command("sleep", "60")
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	argv := keepAwakeArgv("linux", time.Minute, agent.Process.Pid)[5:]
	hold := exec.Command(argv[0], argv[1:]...)
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- hold.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("hold ended while the agent runs: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	agent.Process.Kill()
	agent.Wait()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		hold.Process.Kill()
		t.Fatal("hold survived the agent")
	}
}

func TestParseLoginctl(t *testing.T) {
	ids := parseLoginctlSessions("  2 1000 riddix - 2286   manager - no -\n561 1000 riddix - 359843 user - no -\n\n$(x) 0 root\n")
	if len(ids) != 2 || ids[0] != "2" || ids[1] != "561" {
		t.Fatalf("%v", ids)
	}

	now := time.Unix(1_800_000_000, 0)
	// ssh and tty logins count: active without a timestamp, else the tty's last input
	for props, want := range map[string]int64{
		"Type=unspecified\nClass=user\nState=active\nIdleHint=no\nIdleSinceHint=0\n": 0,
		"Type=tty\nClass=user-early\nState=online\nIdleHint=no\nIdleSinceHint=" +
			strconv.FormatInt((now.Unix()-300)*1_000_000, 10) + "\n": 300,
	} {
		if idle, u, err := parseLoginctlIdle(props, now); !u || idle != want || err != nil {
			t.Fatalf("%q: %d %v %v", props, idle, u, err)
		}
	}
	if _, _, err := parseLoginctlIdle("Type=tty\nClass=user\nIdleHint=no\nIdleSinceHint=0\n", now); err == nil {
		t.Fatal("tty without an input time must be unknown")
	}
	nopty := "Type=tty\nTTY=\nClass=user\nState=active\nIdleHint=no\nIdleSinceHint=0\n"
	if idle, u, err := parseLoginctlIdle(nopty, now); !u || idle != 0 || err != nil {
		t.Fatalf("ssh without a pty: %d %v %v", idle, u, err)
	}
	active := "Type=wayland\nClass=user\nIdleHint=no\nIdleSinceHint=0\n"
	if idle, u, err := parseLoginctlIdle(active, now); !u || idle != 0 || err != nil {
		t.Fatalf("%d %v %v", idle, u, err)
	}
	idleSince := (now.Unix() - 1200) * 1_000_000
	idle := "Type=x11\nClass=user\nIdleHint=yes\nIdleSinceHint=" + strconv.FormatInt(idleSince, 10) + "\n"
	if s, u, err := parseLoginctlIdle(idle, now); !u || s != 1200 || err != nil {
		t.Fatalf("%d %v %v", s, u, err)
	}
	if _, _, err := parseLoginctlIdle("Type=x11\nClass=user\nIdleHint=yes\n", now); err == nil {
		t.Fatal("idle without a timestamp must be unknown")
	}
	for _, skip := range []string{
		"Type=x11\nClass=greeter\nIdleHint=yes\nIdleSinceHint=1\n",
		"Type=unspecified\nClass=manager\nIdleHint=no\n",
		"Type=unspecified\nClass=background\nIdleHint=no\n",
		"Type=tty\nClass=user\nState=closing\nIdleHint=no\nIdleSinceHint=0\n",
	} {
		if _, u, err := parseLoginctlIdle(skip, now); u || err != nil {
			t.Fatalf("%q counted", skip)
		}
	}
}

func TestParseWhoTTYs(t *testing.T) {
	out := "riddix   console      Sep 24 08:00 \nriddix   ttys000      Sep 24 09:00 \nadmin    ttys001      Sep  4 09:01 (192.168.178.20)\n\n"
	if ttys, err := parseWhoTTYs(out); err != nil || strings.Join(ttys, ",") != "ttys000,ttys001" {
		t.Fatalf("%v %v", ttys, err)
	}
	if ttys, err := parseWhoTTYs(""); err != nil || len(ttys) != 0 {
		t.Fatalf("%v %v", ttys, err)
	}
	for _, bad := range []string{"x ../etc/passwd Sep 24", "x ttys0/../a", "lonely"} {
		if _, err := parseWhoTTYs(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseIdle(t *testing.T) {
	if s, err := parseHIDIdle("+-o IOHIDSystem\n    {\n      \"HIDIdleTime\" = 24667871625\n    }\n"); err != nil || s != 24 {
		t.Fatalf("%d %v", s, err)
	}
	if _, err := parseHIDIdle("nothing"); err == nil {
		t.Fatal("missing HIDIdleTime accepted")
	}
	if s, err := parseIdleMillis("368250\r\n"); err != nil || s != 368 {
		t.Fatalf("%d %v", s, err)
	}
	for _, bad := range []string{"", "-5", "abc", "1 2"} {
		if _, err := parseIdleMillis(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseLidIndexes(t *testing.T) {
	out := "Subgroup GUID: 4f971e89-eebd-4455-a8de-9e59040e7347  (Power buttons and lid)\n" +
		"    Power Setting GUID: 5ca83367-6e45-459f-a27b-476b1d01c936  (Lid close action)\n" +
		"      Possible Setting Index: 000\n" +
		"    Current AC Power Setting Index: 0x00000001\n" +
		"    Current DC Power Setting Index: 0x00000003\n"
	ac, dc, err := parseLidIndexes(out)
	if err != nil || ac != "0x00000001" || dc != "0x00000003" {
		t.Fatalf("%q %q %v", ac, dc, err)
	}
	if lidIndexArg(ac) != "1" || lidIndexArg(dc) != "3" || lidIndexArg("junk") != "1" {
		t.Fatal(lidIndexArg(ac), lidIndexArg(dc))
	}
	if _, _, err := parseLidIndexes("nothing"); err == nil {
		t.Fatal("expected an error")
	}
}

// expired keepawake.json is removed at start. a live hold needs logind;
// this checks the save/load round trip
func TestAwakeStateRestoreExpired(t *testing.T) {
	dir := t.TempDir()
	old := awakeStateDir
	awakeStateDir = func() string { return dir }
	defer func() { awakeStateDir = old }()

	if err := saveAwakeState(awakeState{Until: time.Now().Unix() - 60}); err != nil {
		t.Fatal(err)
	}
	st, ok := loadAwakeState()
	if !ok || st.Until == 0 {
		t.Fatal("state not read back")
	}
	if err := RestoreKeepAwake(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(awakeStateFile()); !os.IsNotExist(err) {
		t.Fatal("expired state file still there")
	}
	if err := RestoreKeepAwake(); err != nil {
		t.Fatal("no state must be fine:", err)
	}
}

func TestDisableSleepKept(t *testing.T) {
	for out, want := range map[string]string{
		"System-wide power settings:\n SleepDisabled\t\t1\nCurrently in use:\n sleep                1\n": "1",
		"System-wide power settings:\n SleepDisabled\t\t0\nCurrently in use:\n sleep                1\n": "0",
		"System-wide power settings:\nCurrently in use:\n sleep                0\n":                      "0",
	} {
		if got := parseSleepDisabled(out); got != want {
			t.Fatalf("%q: %s, want %s", out, got, want)
		}
	}

	dir := t.TempDir()
	old := awakeStateDir
	awakeStateDir = func() string { return dir }
	defer func() { awakeStateDir = old }()
	// a file from an older agent has no value, its hold ended with 0
	for st, want := range map[awakeState]string{{Until: 1}: "0", {Until: 1, DisableSleep: "1"}: "1"} {
		if err := saveAwakeState(st); err != nil {
			t.Fatal(err)
		}
		if got, ok := loadAwakeState(); !ok || got.DisableSleep != want {
			t.Fatalf("%+v read back as %+v", st, got)
		}
	}
}
