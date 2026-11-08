// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bufio"
	"context"
	"os/exec"
	"time"

	"github.com/creack/pty"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

func init() {
	willShutdown = func() bool {
		v, err := unix.SysctlUint32("kern.willshutdown")
		return err == nil && v != 0
	}
	shutdownLog = darwinShutdownLog
}

// After an RMM shutdown, restart or sleep the probes are skipped.
func classifyStop() (string, string) {
	powerMu.Lock()
	st := loadPowerState()
	powerMu.Unlock()
	if st.Source == "rmm" && st.live(darwinBoot().Unix(), time.Now()) {
		return "", ""
	}
	return darwinStopKind()
}

func darwinBoot() time.Time {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}
	}
	return time.Unix(tv.Unix())
}

// launchd and shutdown(8) lines since boot, at most the last 3 minutes
func darwinShutdownLog() string {
	since := time.Now().Add(-3 * time.Minute)
	if b := darwinBoot(); b.After(since) {
		since = b
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := runOut(ctx, "/usr/bin/log", "show", "--style", "ndjson", "--start", since.Format("2006-01-02 15:04:05"),
		// launchd and the root-only shutdown tools: logger(1) lines of a
		// user must not count
		"--predicate", `(processID == 1 AND eventMessage CONTAINS[c] "shutdown initiated by") OR (processImagePath IN {"/sbin/shutdown", "/sbin/reboot", "/sbin/halt"} AND (eventMessage BEGINSWITH "reboot by" OR eventMessage BEGINSWITH "halt by" OR eventMessage BEGINSWITH "shutdown by"))`)
	return out
}

// watchPower follows loginwindow and powerd. Restart and shutdown from the
// Apple menu are announced while apps still quit and the network is up; the
// sleep notice races the system, a notify observer gets no grace period.
func (a *Agent) watchPower(nc *nats.Conn) {
	keys := []string{keyPowerState}
	for k := range loginwindowKinds {
		keys = append(keys, k)
	}
	prev := ""
	pause := 5 * time.Second
	for {
		start := time.Now()
		err := watchNotify(keys, func(key string, state uint64, stateOK bool) {
			a.onPowerNotice(nc, key, state, stateOK, &prev)
		})
		if time.Since(start) > time.Hour {
			pause = 5 * time.Second
		}
		a.Logger.Debugln("watchPower(): notifyutil ended:", err)
		time.Sleep(pause)
		if pause < 10*time.Minute {
			pause *= 2
		}
	}
}

func (a *Agent) onPowerNotice(nc *nats.Conn, key string, state uint64, stateOK bool, prev *string) {
	if key == keyPowerState {
		kind := powerStateKind(state)
		if !stateOK || kind == *prev {
			return
		}
		*prev = kind
		if kind == "sleep" {
			// a restart or shutdown under way is no sleep
			if k, _, trusted := freshLoginNotice(); k != "" && (trusted || willShutdown()) {
				return
			}
			a.announcePower(nc, "sleep", "os", "", 2*time.Second)
			return
		}
		// a check-in can go out in a dark wake too, the next sleep needs its own message
		if kind == "wake" {
			a.powerBack(nc)
		} else {
			a.SelfHealHeartbeat()
			powerResumed()
		}
		return
	}
	kind, ok := loginwindowKinds[key]
	if !ok {
		return
	}
	user := a.LoggedOnUser()
	if user == noUser {
		user = ""
	}
	trusted := trustedNotice(key)
	setLoginNotice(kind, user, trusted)
	// an untrusted cancel only makes things louder, so it may go out
	if trusted || kind == "cancel" {
		_ = a.announcePower(nc, kind, "os", user, 5*time.Second)
	}
}

// notifyutil printf()s without fflush: through a pipe its lines stay in the
// buffer, a pty makes stdout line buffered.
func watchNotify(keys []string, on func(key string, state uint64, stateOK bool)) error {
	args := []string{"-v"}
	for _, k := range keys {
		args = append(args, "-w", k)
	}
	cmd := exec.Command("/usr/bin/notifyutil", args...)
	f, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, st, ok := parseNotifyLine(sc.Text()); k != "" {
			on(k, st, ok)
		}
	}
	_ = cmd.Process.Kill()
	return cmd.Wait()
}
