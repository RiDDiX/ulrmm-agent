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

// keepawake.json next to the agent: until, and on Windows the lid indexes
// taken before the hold. A restart puts a live hold back; the indexes are
// written back when the hold ends.
type awakeState struct {
	Until int64  `json:"until"`
	LidAC string `json:"lid_ac,omitempty"`
	LidDC string `json:"lid_dc,omitempty"`
}

func awakeStateFile() string { return filepath.Join(awakeStateDir(), "keepawake.json") }

func loadAwakeState() (awakeState, bool) {
	var st awakeState
	b, err := os.ReadFile(awakeStateFile())
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

func saveAwakeState(st awakeState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(awakeStateFile(), b, 0600)
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

// powercfg wants this index in decimal
func lidIndexArg(hex string) string {
	v, err := strconv.ParseInt(strings.TrimPrefix(hex, "0x"), 16, 64)
	if err != nil {
		return "1"
	}
	return strconv.FormatInt(v, 10)
}

// one hold per agent; a new keepawake replaces the old one
var awake struct {
	sync.Mutex
	gen     int
	release func()
	timer   *time.Timer
}

func stopKeepAwakeLocked() {
	if awake.timer != nil {
		awake.timer.Stop()
		awake.timer = nil
	}
	if awake.release != nil {
		awake.release()
		awake.release = nil
	}
}

func StopKeepAwake() {
	awake.Lock()
	defer awake.Unlock()
	stopKeepAwakeLocked()
}

func KeepAwake(until int64) error {
	d, err := keepAwakeSpan(until, time.Now())
	if err != nil {
		return err
	}
	awake.Lock()
	defer awake.Unlock()
	stopKeepAwakeLocked()
	if d == 0 {
		return nil
	}
	release, err := holdAwake(d)
	if err != nil {
		return err
	}
	// lid indexes in the file are the pre-hold values
	st, _ := loadAwakeState()
	st.Until = until
	if err := holdLid(&st); err != nil {
		release()
		return err
	}
	if err := saveAwakeState(st); err != nil {
		release()
		undoLid(st)
		return err
	}
	awake.gen++
	gen := awake.gen
	awake.release = func() {
		release()
		undoLid(st)
		os.Remove(awakeStateFile())
	}
	awake.timer = time.AfterFunc(d, func() {
		awake.Lock()
		defer awake.Unlock()
		if awake.gen == gen {
			stopKeepAwakeLocked()
		}
	})
	return nil
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

// start: until still ahead, hold again; otherwise put the lid back
func RestoreKeepAwake() error {
	st, ok := loadAwakeState()
	if !ok {
		return nil
	}
	if st.Until > time.Now().Unix()+5 {
		return KeepAwake(st.Until)
	}
	os.Remove(awakeStateFile())
	return undoLid(st)
}
