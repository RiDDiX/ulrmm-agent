// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"regexp"
	"strings"
)

// Parsers for the FreeBSD stop signal (powerwatch_freebsd.go); no FreeBSD
// calls here, so the tests run on every unix.

var freebsdShutdownByRe = regexp.MustCompile(`(reboot|halt|power-down) by ([^:]*):?\s*(.*)$`)

func rcShutdownRunning(ps string) bool {
	for _, l := range strings.Split(ps, "\n") {
		if strings.Contains(l, "/etc/rc.shutdown") {
			return true
		}
	}
	return false
}

// the last shutdown(8) line of /var/log/messages, at most 50 lines back
func freebsdStopKind(messages string) (kind, initiator string) {
	lines := strings.Split(strings.TrimRight(messages, "\n"), "\n")
	if len(lines) > 50 {
		lines = lines[len(lines)-50:]
	}
	for i := len(lines) - 1; i >= 0; i-- {
		m := freebsdShutdownByRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		initiator = strings.TrimSpace(m[2])
		if r := strings.TrimSpace(m[3]); r != "" {
			initiator += ": " + r
		}
		if m[1] == "reboot" {
			return "restart", initiator
		}
		return "shutdown", initiator
	}
	return "shutdown_or_restart", ""
}
