// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	nats "github.com/nats-io/nats.go"
)

// power.json next to keepawake.json: the last announcement, so one boot sends
// a kind once even when the service restarts on the way down.
type powerState struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Boot   int64  `json:"boot"`
	At     int64  `json:"at"`
}

var powerMu sync.Mutex

// an announcement older than this no longer holds back the next one. The
// server takes an event only while it is at most 2 minutes older than the
// last check-in, so a shutdown that waits longer (an app asking to save) is
// announced again at the stop signal.
const powerAnnounceFor = 90 * time.Second

func powerStateFile() string { return filepath.Join(awakeStateDir(), "power.json") }

func loadPowerState() (st powerState) {
	if b, err := os.ReadFile(powerStateFile()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func savePowerState(st powerState) {
	if b, err := json.Marshal(st); err == nil {
		_ = os.WriteFile(powerStateFile(), b, 0o600)
	}
}

func clearPowerState() { _ = os.Remove(powerStateFile()) }

// live: announced in this boot (the boot time some systems derive from the
// uptime drifts by a second) and not long ago by the wall clock, which also
// runs during sleep.
func (st powerState) live(boot int64, now time.Time) bool {
	d := st.Boot - boot
	age := now.Sub(time.Unix(st.At, 0))
	return st.Kind != "" && d >= -2 && d <= 2 && age >= -time.Minute && age < powerAnnounceFor
}

// powerSkip drops a kind already sent in this boot, a vaguer kind after a
// precise one and what the OS reports after an RMM command announced the
// same; sleep and going down are kept apart. A cancel always goes out.
func powerSkip(st powerState, kind, source string, boot int64, now time.Time) bool {
	// the late cancel after a wake must not take back a newer announcement
	if kind == "cancel" {
		return source == "wake" && st.Kind != ""
	}
	if !st.live(boot, now) || (st.Kind == "sleep") != (kind == "sleep") {
		return false
	}
	return st.Kind == kind || kind == "shutdown_or_restart" || (st.Source == "rmm" && source == "os")
}

// powerAnnounced: a shutdown, restart or sleep went out in this boot lately.
func (a *Agent) powerAnnounced() bool {
	powerMu.Lock()
	defer powerMu.Unlock()
	return loadPowerState().live(a.BootTime(), time.Now())
}

// powerAnnouncedPrecise: as powerAnnounced, with a kind better than
// shutdown_or_restart
func (a *Agent) powerAnnouncedPrecise() bool {
	powerMu.Lock()
	defer powerMu.Unlock()
	st := loadPowerState()
	return st.Kind != "shutdown_or_restart" && st.live(a.BootTime(), time.Now())
}

// powerResumed forgets the last announcement after a wake; the next sleep
// needs its own message.
func powerResumed() {
	powerMu.Lock()
	clearPowerState()
	powerMu.Unlock()
}

// powerBack: awake again. The cancel ends the planned gap on the server at
// once, so a crash right after the wake alerts. After a long sleep the
// connection is still reconnecting and drops what is published (no reconnect
// buffer), so the cancel waits for it, off the watcher, which must be back for
// the next sleep notice.
func (a *Agent) powerBack(nc *nats.Conn) {
	powerResumed()
	go func() {
		for end := time.Now().Add(time.Minute); !nc.IsConnected() && time.Now().Before(end); {
			time.Sleep(500 * time.Millisecond)
		}
		_ = a.announcePower(nc, "cancel", "wake", "", 2*time.Second)
		a.NatsMessage(nc, "agent-hello")
		a.NatsMessage(nc, "agent-agentinfo")
	}()
}

// powerStartup: an announcement left from an earlier boot means the machine
// is back; the server also clears it from the new boot time.
func (a *Agent) powerStartup(nc *nats.Conn) {
	powerMu.Lock()
	st := loadPowerState()
	powerMu.Unlock()
	if st.Kind != "" && !st.live(a.BootTime(), time.Now()) {
		_ = a.announcePower(nc, "cancel", "os", "", 2*time.Second)
	}
}

// at most 200 bytes of valid UTF-8, cut on a rune boundary
func powerInitiator(s string) string {
	s = strings.TrimSpace(CleanString(s))
	n := 200
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
