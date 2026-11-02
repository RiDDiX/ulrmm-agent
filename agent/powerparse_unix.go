// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Parsers for the macOS power watcher (powerwatch_darwin.go); no darwin
// calls here, so the tests run on every unix.

const (
	keyPowerState  = "com.apple.powermanagement.systempowerstate"
	capCPU         = 0x1
	capVideo       = 0x2
	powerNoticeFor = 10 * time.Minute
)

// SIGTERM probes, set in powerwatch_darwin.go; the tests swap them
var (
	willShutdown = func() bool { return false }
	shutdownLog  = func() string { return "" }
)

// last loginwindow notice, read when launchd stops the agent
var loginNotice struct {
	sync.Mutex
	kind, user string
	trusted    bool
	at         time.Time
}

// only root posts com.apple.system.* names; any local user can post the
// others with notifyutil -p
func trustedNotice(key string) bool { return strings.HasPrefix(key, "com.apple.system.") }

func setLoginNotice(kind, user string, trusted bool) {
	if kind == "cancel" {
		kind = ""
	}
	loginNotice.Lock()
	loginNotice.kind, loginNotice.user, loginNotice.trusted, loginNotice.at = kind, user, trusted, time.Now()
	loginNotice.Unlock()
}

// a restart or shutdown loginwindow announced in the last 10 minutes
func freshLoginNotice() (kind, user string, trusted bool) {
	loginNotice.Lock()
	defer loginNotice.Unlock()
	if loginNotice.kind == "" || time.Since(loginNotice.at) >= powerNoticeFor {
		return "", "", false
	}
	return loginNotice.kind, loginNotice.user, loginNotice.trusted
}

// loginwindow notify names are private and their casing differs between
// releases, so every known spelling is registered.
var loginwindowKinds = map[string]string{
	"com.apple.loginwindow.restartinitiated":         "restart",
	"com.apple.system.loginwindow.restartinitiated":  "restart",
	"com.apple.loginwindow.likelyShutdown":           "shutdown_or_restart",
	"com.apple.loginwindow.likelyshutdown":           "shutdown_or_restart",
	"com.apple.system.loginwindow.shutdownInitiated": "shutdown",
	"com.apple.system.loginwindow.shutdowninitiated": "shutdown",
	"com.apple.loginwindow.logoutcancelled":          "cancel",
	"com.apple.system.loginwindow.logoutcancelled":   "cancel",
}

// notifyutil -v prints "<sec.msec> <key> <state> <type>"; the state is not a
// number when notifyd could not read it.
func parseNotifyLine(l string) (key string, state uint64, stateOK bool) {
	f := strings.Fields(l)
	if len(f) < 3 {
		return "", 0, false
	}
	st, err := strconv.ParseUint(f[2], 10, 64)
	return f[1], st, err == nil
}

// systempowerstate carries the IOPMCapability bits: CPU clear is sleep, CPU
// without video a dark wake.
func powerStateKind(state uint64) string {
	switch {
	case state&capCPU == 0:
		return "sleep"
	case state&capVideo == 0:
		return "darkwake"
	}
	return "wake"
}

var (
	launchdInitRe = regexp.MustCompile(`(?i)shutdown initiated by:\s*(\S+)`)
	shutdownByRe  = regexp.MustCompile(`^(reboot|halt|shutdown|power-down) by ([^:]*):\s*(.*)$`)
)

// parseShutdownLog reads log show --style ndjson lines of launchd ("System
// shutdown initiated by: shutdown.45074<-sshd.12") and shutdown(8)
// ("reboot by <user>: <message>").
func parseShutdownLog(ndjson string) (kind, initiator string, ok bool) {
	var proc, user, reason string
	for _, l := range strings.Split(ndjson, "\n") {
		var e struct {
			EventMessage string `json:"eventMessage"`
		}
		if json.Unmarshal([]byte(l), &e) != nil {
			continue
		}
		if m := launchdInitRe.FindStringSubmatch(e.EventMessage); m != nil {
			proc, ok = m[1], true
		}
		if m := shutdownByRe.FindStringSubmatch(strings.TrimSpace(e.EventMessage)); m != nil {
			kind, user, reason, ok = "shutdown", strings.TrimSpace(m[2]), m[3], true
			if m[1] == "reboot" {
				kind = "restart"
			}
		}
	}
	if !ok {
		return "", "", false
	}
	if kind == "" {
		kind = "shutdown_or_restart"
	}
	initiator = proc
	if user != "" {
		initiator = user
		if reason != "" {
			initiator += ": " + reason
		}
	}
	return kind, initiator, true
}

// darwinStopKind tells a shutdown from launchctl bootout or kill when launchd
// sends SIGTERM. kern.willshutdown only says the system goes down, so the
// kind and initiator come from a fresh loginwindow notice or the unified log
// lines of launchd and shutdown(8)
// (at most 5 s) when they have one. Nothing found is a plain service stop.
func darwinStopKind() (string, string) {
	ws := willShutdown()
	// a notice anyone could post counts only while the kernel confirms
	if kind, user, trusted := freshLoginNotice(); kind != "" && (trusted || ws) {
		return kind, user
	}
	// launchd stops the network daemons at the same time: no time for the
	// log when the kernel already says the system goes down
	if ws {
		return "shutdown_or_restart", ""
	}
	if kind, ini, ok := parseShutdownLog(shutdownLog()); ok {
		return kind, ini
	}
	return "", ""
}
