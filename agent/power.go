// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const keepAwakeMax = 6 * time.Hour

// keepawake RPC: until is a unix epoch. until <= now cancels, more than
// 6 h ahead is refused. Returns how long to hold.
func keepAwakeSpan(until int64, now time.Time) (time.Duration, error) {
	if until <= now.Unix() {
		return 0, nil
	}
	d := time.Unix(until, 0).Sub(now)
	if d > keepAwakeMax {
		return 0, fmt.Errorf("until is more than %s ahead", keepAwakeMax)
	}
	return d, nil
}

// macOS: caffeinate -i (idle sleep, also on battery) -s (system sleep on AC),
// released when the agent exits (-w). A closed lid needs holdLid.
// Linux: a logind block inhibitor for sleep, idle and the lid switch, held by
// systemd-inhibit around `tail --pid`, so it also ends with the agent under
// KillMode=process (self-update, crash restart); timeout keeps the hard limit.
func keepAwakeArgv(goos string, d time.Duration, pid int) []string {
	secs := strconv.FormatInt(int64(d/time.Second)+1, 10)
	p := strconv.Itoa(pid)
	if goos == "darwin" {
		return []string{"/usr/bin/caffeinate", "-i", "-s", "-t", secs, "-w", p}
	}
	return []string{"systemd-inhibit", "--what=sleep:idle:handle-lid-switch", "--who=" + BrandAgentName, "--why=maintenance window", "--mode=block",
		"timeout", secs, "tail", "--pid=" + p, "-f", "/dev/null"}
}

// keepawake.json next to the agent: until, ac (macOS: stay awake on power),
// and the settings the hold changes as they were before it: the lid indexes
// on Windows, disablesleep on macOS. A restart puts a live hold back; the old
// values are written back when nothing holds any more.
type awakeState struct {
	Until        int64  `json:"until"`
	AC           bool   `json:"ac,omitempty"`
	LidAC        string `json:"lid_ac,omitempty"`
	LidDC        string `json:"lid_dc,omitempty"`
	DisableSleep string `json:"disablesleep,omitempty"`
}

// The one rule: hold while the timed hold runs, or with ac on AC power
// outside a suspend pause.
func awakeWanted(st awakeState, onAC bool, pause, now int64) bool {
	return st.Until > now || (st.AC && onAC && pause <= now)
}

func awakeStateFile() string { return filepath.Join(awakeStateDir(), "keepawake.json") }

// a file without ac is always a held one; with ac the old value marks it
func awakeHeld(st awakeState, ok bool) bool {
	return ok && (!st.AC || st.DisableSleep != "")
}

func loadAwakeState() (awakeState, bool) {
	var st awakeState
	b, err := os.ReadFile(awakeStateFile())
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	// older agents did not keep it, they always ended a hold with 0. With ac
	// the file stays while nothing holds, then without a value.
	if st.DisableSleep == "" && !st.AC {
		st.DisableSleep = "0"
	}
	return st, true
}

// the file is the only record of the old values: a failed write must not
// leave it empty
func saveAwakeState(st awakeState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := awakeStateFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, awakeStateFile())
}

// powercfg /q SCHEME_CURRENT SUB_BUTTONS LIDACTION lines look like
// "Current AC Power Setting Index: 0x00000001"
var lidIndexRe = regexp.MustCompile(`Current (AC|DC) Power Setting Index: (0x[0-9A-Fa-f]+)`)

func parseLidIndexes(out string) (ac, dc string, err error) {
	for _, m := range lidIndexRe.FindAllStringSubmatch(out, -1) {
		if m[1] == "AC" {
			ac = m[2]
		} else {
			dc = m[2]
		}
	}
	if ac == "" || dc == "" {
		return "", "", errors.New("lid action not found in powercfg output")
	}
	return ac, dc, nil
}

// pmset -g lists " SleepDisabled\t\t1" under the system-wide settings while
// disablesleep is on, 0 or no line at all when it is off
func parseSleepDisabled(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "SleepDisabled" && f[1] == "1" {
			return "1"
		}
	}
	return "0"
}

// pmset -g batt starts with "Now drawing from 'AC Power'"; Battery Power,
// UPS Power or anything else counts as battery
func parseOnAC(out string) bool {
	first, _, _ := strings.Cut(out, "\n")
	return strings.TrimSpace(first) == "Now drawing from 'AC Power'"
}

// ioreg -r -k AppleClamshellState -d 4: closed and set to sleep the Mac when
// both are Yes
func parseLidClosed(out string) bool {
	closed, sleeps := false, false
	for _, l := range strings.Split(out, "\n") {
		if _, v, ok := strings.Cut(l, `"AppleClamshellState" = `); ok {
			closed = strings.TrimSpace(v) == "Yes"
		}
		if _, v, ok := strings.Cut(l, `"AppleClamshellCausesSleep" = `); ok {
			sleeps = strings.TrimSpace(v) == "Yes"
		}
	}
	return closed && sleeps
}

// powercfg wants this index in decimal
func lidIndexArg(hex string) string {
	v, err := strconv.ParseInt(strings.TrimPrefix(hex, "0x"), 16, 64)
	if err != nil {
		return "1"
	}
	return strconv.FormatInt(v, 10)
}

// one timed hold per agent; a new keepawake replaces the old one. pause
// keeps the ac rule off until then (unix seconds), onAC is the power source
// seen last, watching while the 15 s check is planned.
var awake struct {
	sync.Mutex
	gen      int
	release  func()
	timer    *time.Timer
	pause    int64
	onAC     bool
	watching bool
}

func stopTimedLocked() {
	if awake.timer != nil {
		awake.timer.Stop()
		awake.timer = nil
	}
	if awake.release != nil {
		awake.release()
		awake.release = nil
	}
}

// applyAwakeLocked changes keepawake.json and holds or frees the lid by
// awakeWanted. The first holder keeps the old values in the file, they go
// back when nothing holds. Nothing is saved when the lid cannot be held.
func applyAwakeLocked(change func(*awakeState)) error {
	st, ok := loadAwakeState()
	held := awakeHeld(st, ok)
	loaded := st
	if change != nil {
		change(&st)
	}
	if st.AC && !awake.watching {
		awake.watching = true
		time.AfterFunc(15*time.Second, func() {
			awake.Lock()
			defer awake.Unlock()
			awake.watching = false
			_ = applyAwakeLocked(nil)
		})
	}
	now := time.Now().Unix()
	onAC := st.AC && onACPower()
	unplugged := st.AC && awake.onAC && !onAC
	awake.onAC = onAC
	var err error
	switch want := awakeWanted(st, onAC, awake.pause, now); {
	case want && !held:
		if err := holdLid(&st); err != nil {
			return err
		}
		if err := saveAwakeState(st); err != nil {
			undoLid(st)
			return err
		}
		return nil
	case !want && held:
		err = undoLid(st)
		st.LidAC, st.LidDC, st.DisableSleep = "", "", ""
		held = false
		// unplugged with the lid closed: whether the Mac sleeps by itself
		// once disablesleep is off is not known, so it is told to
		if unplugged {
			sleepIfLidClosed()
		}
	}
	if !held && !st.AC {
		os.Remove(awakeStateFile())
		return err
	}
	// the 15 s check mostly finds nothing to change
	if ok && st == loaded {
		return err
	}
	if serr := saveAwakeState(st); err == nil {
		err = serr
	}
	return err
}

func KeepAwake(until int64) error {
	d, err := keepAwakeSpan(until, time.Now())
	if err != nil {
		return err
	}
	awake.Lock()
	defer awake.Unlock()
	stopTimedLocked()
	if d == 0 {
		return applyAwakeLocked(func(st *awakeState) { st.Until = 0 })
	}
	release, err := holdAwake(d)
	if err == nil {
		if err = applyAwakeLocked(func(st *awakeState) { st.Until = until }); err != nil {
			release()
		}
	}
	if err != nil {
		_ = applyAwakeLocked(func(st *awakeState) { st.Until = 0 })
		return err
	}
	awake.gen++
	gen := awake.gen
	awake.release = release
	awake.timer = time.AfterFunc(d, func() {
		awake.Lock()
		defer awake.Unlock()
		if awake.gen == gen {
			stopTimedLocked()
			_ = applyAwakeLocked(func(st *awakeState) { st.Until = 0 })
		}
	})
	return nil
}

// keepawakeac RPC: macOS never sleeps on AC power, lid closed included
func KeepAwakeAC(ac bool) error {
	if runtime.GOOS != "darwin" {
		return errors.New("stay awake on power is only available on macOS")
	}
	awake.Lock()
	defer awake.Unlock()
	return applyAwakeLocked(func(st *awakeState) { st.AC = ac })
}

// suspend and uninstall: the timed hold ends and the ac rule rests for d,
// so nothing holds the Mac awake. 0 applies the rule again at once.
func PauseKeepAwake(d time.Duration) error {
	awake.Lock()
	defer awake.Unlock()
	stopTimedLocked()
	awake.pause = time.Now().Add(d).Unix()
	return applyAwakeLocked(func(st *awakeState) { st.Until = 0 })
}

// idle RPC: seconds since the last user input, -1 without a user session. Any error means unknown and the caller keeps the device awake.
func UserIdle() (int64, error) {
	return userIdleSeconds()
}

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// first column of `loginctl list-sessions --no-legend`
func parseLoginctlSessions(out string) []string {
	ret := make([]string, 0)
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && sessionIDRe.MatchString(f[0]) && len(ret) < 64 {
			ret = append(ret, f[0])
		}
	}
	return ret
}

// `loginctl show-session ID -p Type -p Class -p State -p IdleHint -p IdleSinceHint`.
// Every user session counts (root's are user-early), a closing one has lost
// its login. Graphical sessions carry an idle hint, IdleHint=no reads as
// active now. For tty sessions (ssh with a pty too) logind reports the tty's
// last input as IdleSinceHint. Anything else, like ssh without a pty, is active.
func parseLoginctlIdle(props string, now time.Time) (idle int64, user bool, err error) {
	kv := make(map[string]string)
	for _, l := range strings.Split(props, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			kv[k] = v
		}
	}
	if !strings.HasPrefix(kv["Class"], "user") || kv["State"] == "closing" {
		return 0, false, nil
	}
	switch kv["Type"] {
	case "x11", "wayland", "mir":
		if kv["IdleHint"] != "yes" {
			return 0, true, nil
		}
	case "tty":
		// ssh without a pty: tty session, empty TTY, no idle time
		if tty, ok := kv["TTY"]; ok && tty == "" {
			return 0, true, nil
		}
	default:
		return 0, true, nil
	}
	since, perr := strconv.ParseInt(kv["IdleSinceHint"], 10, 64)
	if perr != nil || since <= 0 {
		return 0, true, errors.New("IdleSinceHint missing")
	}
	return secondsSince(now, since/1e6), true, nil
}

func secondsSince(now time.Time, sec int64) int64 {
	if d := now.Unix() - sec; d > 0 {
		return d
	}
	return 0
}

var whoTTYRe = regexp.MustCompile(`^(tty[A-Za-z0-9]{1,8}|pts/[0-9]{1,4})$`)

// `who`: the ttys of ssh and Terminal logins, the macOS GUI one is console.
// FreeBSD names ssh ttys pts/N.
func parseWhoTTYs(out string) ([]string, error) {
	ret := make([]string, 0)
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 0 || (len(f) > 1 && f[1] == "console"):
		case len(f) > 1 && whoTTYRe.MatchString(f[1]) && len(ret) < 64:
			ret = append(ret, f[1])
		default:
			return nil, fmt.Errorf("unexpected who line %q", clip(l, 64))
		}
	}
	return ret, nil
}

// ioreg -c IOHIDSystem: "HIDIdleTime" = <nanoseconds>
func parseHIDIdle(out string) (int64, error) {
	best := int64(-1)
	for _, l := range strings.Split(out, "\n") {
		_, v, ok := strings.Cut(l, `"HIDIdleTime" = `)
		if !ok {
			continue
		}
		ns, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || ns < 0 {
			continue
		}
		if s := ns / 1e9; best < 0 || s < best {
			best = s
		}
	}
	if best < 0 {
		return 0, errors.New("HIDIdleTime not found")
	}
	return best, nil
}

// output of `-m idle` in a user session: milliseconds
func parseIdleMillis(out string) (int64, error) {
	ms, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil || ms < 0 {
		return 0, fmt.Errorf("bad idle helper output %q", clip(out, 32))
	}
	return ms / 1000, nil
}

// `-m idle`, started by the service inside a user session (Windows only)
func PrintUserIdle() {
	ms, err := lastInputMillis()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(ms)
}

// start: until still ahead, hold again; otherwise the rule decides, so ac
// holds on AC power and a stale lid hold goes back
func RestoreKeepAwake() error {
	st, ok := loadAwakeState()
	if !ok {
		return nil
	}
	if st.Until > time.Now().Unix()+5 {
		return KeepAwake(st.Until)
	}
	awake.Lock()
	defer awake.Unlock()
	// a hold of the ac rule means the agent before saw AC power, so an
	// unplug during the restart still counts
	awake.onAC = st.AC && awakeHeld(st, ok)
	return applyAwakeLocked(func(st *awakeState) { st.Until = 0 })
}

// local uninstall, after the service stopped: put back what keepawake.json
// still holds, the file goes with the agent folder
func ReleaseKeepAwakeFile() error {
	st, ok := loadAwakeState()
	if !awakeHeld(st, ok) {
		return nil
	}
	return undoLid(st)
}
