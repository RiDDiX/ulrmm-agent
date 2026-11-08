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
	dir := t.TempDir()
	old := awakeStateDir
	awakeStateDir = func() string { return dir }
	defer func() { awakeStateDir = old }()
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
	// German Windows 11, powercfg /qh
	de := "GUID des Energieschemas: e9a42b02-d5df-448d-aa00-03f14749eb61  (Ultimative Leistung)\r\n" +
		"  GUID der Untergruppe: 4f971e89-eebd-4455-a8de-9e59040e7347  (Netzschalter und Zuklappen)\r\n" +
		"    GUID-Alias: SUB_BUTTONS\r\n" +
		"    GUID der Energieeinstellung: 5ca83367-6e45-459f-a27b-476b1d01c936  (Zuklappen)\r\n" +
		"      GUID-Alias: LIDACTION\r\n" +
		"      Index der möglichen Einstellung: 000\r\n" +
		"      Anzeigename der möglichen Einstellung: Nichts unternehmen\r\n" +
		"      Index der möglichen Einstellung: 003\r\n" +
		"      Anzeigename der möglichen Einstellung: Herunterfahren\r\n" +
		"    Index der aktuellen Wechselstromeinstellung: 0x00000000\r\n" +
		"    Index der aktuellen Gleichstromeinstellung: 0x00000001\r\n\r\n"
	if ac, dc, err := parseLidIndexes(de); err != nil || ac != "0x00000000" || dc != "0x00000001" {
		t.Fatalf("german: %q %q %v", ac, dc, err)
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

func TestParseOnAC(t *testing.T) {
	for out, want := range map[string]bool{
		"Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged; 0:00 remaining present: true\n": true,
		"Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t80%; discharging\n":                       false,
		"Now drawing from 'UPS Power'\n":   false,
		"":                                 false,
		" -InternalBattery-0 'AC Power'\n": false,
	} {
		if got := parseOnAC(out); got != want {
			t.Fatalf("%q: %v, want %v", out, got, want)
		}
	}
}

func TestParseLidClosed(t *testing.T) {
	ioreg := func(state, sleeps string) string {
		return "+-o IOPMrootDomain  <class IOPMrootDomain>\n    {\n      \"AppleClamshellState\" = " + state +
			"\n      \"AppleClamshellCausesSleep\" = " + sleeps + "\n    }\n"
	}
	for out, want := range map[string]bool{
		ioreg("Yes", "Yes"): true,
		ioreg("Yes", "No"):  false,
		ioreg("No", "Yes"):  false,
		ioreg("No", "No"):   false,
		"":                  false,
	} {
		if got := parseLidClosed(out); got != want {
			t.Fatalf("%q: %v, want %v", out, got, want)
		}
	}
}

func TestAwakeWanted(t *testing.T) {
	const now = 1_800_000_000
	for _, c := range []struct {
		until int64
		ac    bool
		onAC  bool
		pause int64
		want  bool
	}{
		{0, false, false, 0, false},
		{0, false, true, 0, false},
		{now + 60, false, false, 0, true},
		{now, false, true, 0, false},
		{0, true, true, 0, true},
		{0, true, false, 0, false},
		{0, true, true, now + 60, false},
		{0, true, true, now, true},
		{now + 60, true, false, now + 60, true},
	} {
		st := awakeState{Until: c.until, AC: c.ac}
		if got := awakeWanted(st, c.onAC, c.pause, now); got != c.want {
			t.Fatalf("%+v: %v", c, got)
		}
	}
}

// ac stays in the file while nothing holds; without a hold it has no old value
func TestAwakeStateWithAC(t *testing.T) {
	dir := t.TempDir()
	old := awakeStateDir
	awakeStateDir = func() string { return dir }
	defer func() { awakeStateDir = old }()

	for st, want := range map[awakeState]string{
		{AC: true}:                    "",
		{AC: true, DisableSleep: "1"}: "1",
		{AC: true, DisableSleep: "0"}: "0",
	} {
		if err := saveAwakeState(st); err != nil {
			t.Fatal(err)
		}
		if got, ok := loadAwakeState(); !ok || !got.AC || got.DisableSleep != want {
			t.Fatalf("%+v read back as %+v", st, got)
		}
	}

	if runtime.GOOS == "darwin" {
		t.Skip("would change pmset")
	}
	// off macOS nothing reads AC power: ac alone holds nothing and stays
	// saved, an ended timed hold leaves it, turning it off drops the file
	awake.Lock()
	defer awake.Unlock()
	// no 15 s check left behind for the real state dir
	awake.watching = true
	defer func() { awake.watching = false }()
	if err := applyAwakeLocked(func(st *awakeState) { *st = awakeState{AC: true, Until: 1} }); err != nil {
		t.Fatal(err)
	}
	if got, ok := loadAwakeState(); !ok || !got.AC || got.Until != 1 || got.DisableSleep != "" {
		t.Fatalf("ac state %+v %v", got, ok)
	}
	if err := applyAwakeLocked(func(st *awakeState) { st.AC = false }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(awakeStateFile()); !os.IsNotExist(err) {
		t.Fatal("state file kept without ac or hold")
	}
	if err := KeepAwakeAC(true); err == nil {
		t.Fatal("stay awake on power accepted off macOS")
	}
}

// the lid on a fake Mac: who holds first keeps the old disablesleep, it goes
// back only when nothing holds, sleepnow only after an unplug
func TestAwakeTransitions(t *testing.T) {
	dir := t.TempDir()
	disable, ac, sleeps := "0", true, 0
	oldDir, oldHold, oldUndo, oldAC, oldSleep := awakeStateDir, holdLid, undoLid, onACPower, sleepIfLidClosed
	awakeStateDir = func() string { return dir }
	holdLid = func(st *awakeState) error {
		if st.DisableSleep == "" {
			st.DisableSleep = disable
		}
		disable = "1"
		return nil
	}
	undoLid = func(st awakeState) error {
		disable = st.DisableSleep
		return nil
	}
	onACPower = func() bool { return ac }
	sleepIfLidClosed = func() { sleeps++ }
	awake.Lock()
	awake.watching = true
	defer func() {
		awake.watching, awake.onAC, awake.pause = false, false, 0
		awake.Unlock()
		awakeStateDir, holdLid, undoLid, onACPower, sleepIfLidClosed = oldDir, oldHold, oldUndo, oldAC, oldSleep
	}()
	now := time.Now().Unix()
	step := func(name string, change func(*awakeState), wantDisable string, wantSleeps int) {
		t.Helper()
		if err := applyAwakeLocked(change); err != nil {
			t.Fatal(name, err)
		}
		if disable != wantDisable || sleeps != wantSleeps {
			t.Fatalf("%s: disablesleep %s sleeps %d, want %s %d", name, disable, sleeps, wantDisable, wantSleeps)
		}
	}
	setAC := func(v bool) func(*awakeState) { return func(st *awakeState) { st.AC = v } }
	until := func(v int64) func(*awakeState) { return func(st *awakeState) { st.Until = v } }

	step("ac on, on AC", setAC(true), "1", 0)
	if st, _ := loadAwakeState(); st.DisableSleep != "0" {
		t.Fatalf("old value %q", st.DisableSleep)
	}
	step("tick", nil, "1", 0)
	step("timed hold too", until(now+3600), "1", 0)
	ac = false
	step("unplugged, timed hold runs", nil, "1", 0)
	step("timed hold ends on battery", until(0), "0", 0)
	ac = true
	step("plugged in", nil, "1", 0)
	ac = false
	step("unplugged", nil, "0", 1)
	step("tick on battery", nil, "0", 1)
	ac = true
	step("plugged in again", nil, "1", 1)
	step("ac off", setAC(false), "0", 1)
	if _, err := os.Stat(awakeStateFile()); !os.IsNotExist(err) {
		t.Fatal("state file kept without ac or hold")
	}

	// a Mac set to never sleep stays that way
	disable = "1"
	step("ac on, never sleep before", setAC(true), "1", 1)
	step("ac off, never sleep before", setAC(false), "1", 1)

	disable = "0"
	step("ac on", setAC(true), "1", 1)
	awake.pause = now + 120
	step("suspend pause", nil, "0", 1)
	awake.pause = now
	step("pause over", nil, "1", 1)

	// restart on battery after the ac rule held: counts as an unplug
	awake.onAC = false
	ac = false
	st, ok := loadAwakeState()
	awake.onAC = st.AC && awakeHeld(st, ok)
	step("restart on battery", until(0), "0", 2)
	if err := ReleaseKeepAwakeFile(); err != nil || disable != "0" {
		t.Fatal("release of a free state changed the lid", err, disable)
	}
}
