// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "testing"

func ins1074(typ string) []string {
	return []string{`C:\Windows\system32\shutdown.exe (PC1)`, "PC1", "Other (Planned)", "0x80000000", typ, "patch day", `NT AUTHORITY\SYSTEM`}
}

func TestClassify1074(t *testing.T) {
	by := `NT AUTHORITY\SYSTEM, shutdown.exe, Other (Planned), patch day`
	for _, c := range []struct {
		name     string
		ins      []string
		kind, by string
	}{
		{"en restart", ins1074("restart"), "restart", by},
		{"en power off", ins1074("power off"), "shutdown", by},
		{"de restart", ins1074("Neu starten"), "restart", by},
		{"de power off", ins1074(" Ausschalten "), "shutdown", by},
		{"unknown language", ins1074("redémarrer"), "shutdown_or_restart", by},
		{"short", []string{"explorer.exe (PC1)", "PC1", "x"}, "shutdown_or_restart", ""},
		{"none", nil, "shutdown_or_restart", ""},
		{"empty fields", []string{"", "", "", "", "restart", "", ""}, "restart", ""},
	} {
		kind, initiator := classify1074(c.ins)
		if kind != c.kind || initiator != c.by {
			t.Errorf("%s: got %q %q, want %q %q", c.name, kind, initiator, c.kind, c.by)
		}
	}
}
