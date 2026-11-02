// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"slices"
	"strings"
)

// 1074 shutdown types are localized; other languages stay shutdown_or_restart
var (
	restartWords  = []string{"restart", "neu starten", "neustart"}
	powerOffWords = []string{"power off", "ausschalten"}
)

// classify1074 reads the inserts of User32 1074: 0 process "(HOST)",
// 1 computer, 2 reason, 3 reason code, 4 shutdown type, 5 comment, 6 user.
func classify1074(ins []string) (kind, initiator string) {
	if len(ins) < 7 {
		return "shutdown_or_restart", ""
	}
	switch t := strings.ToLower(strings.TrimSpace(ins[4])); {
	case slices.Contains(restartWords, t):
		kind = "restart"
	case slices.Contains(powerOffWords, t):
		kind = "shutdown"
	default:
		kind = "shutdown_or_restart"
	}
	proc, _, _ := strings.Cut(ins[0], " (")
	proc = proc[strings.LastIndexByte(proc, '\\')+1:]
	var by []string
	for _, s := range []string{ins[6], proc, ins[2], ins[5]} {
		if s = strings.TrimSpace(s); s != "" {
			by = append(by, s)
		}
	}
	return kind, strings.Join(by, ", ")
}
