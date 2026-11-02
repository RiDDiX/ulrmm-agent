// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"testing"
	"time"
)

func TestHomeEdition(t *testing.T) {
	for id, want := range map[string]bool{
		"Core":               true,
		"CoreSingleLanguage": true,
		"Professional":       false,
		"Enterprise":         false,
		"":                   false,
	} {
		if got := homeEdition(id); got != want {
			t.Errorf("homeEdition(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestPauseWindow(t *testing.T) {
	now := time.Date(2026, 10, 26, 13, 4, 5, 0, time.FixedZone("CET", 3600))
	start, end := pauseWindow(now)
	if start != "2026-10-26T12:04:05Z" || end != "2026-11-30T12:04:05Z" {
		t.Fatalf("got %s %s", start, end)
	}
}
