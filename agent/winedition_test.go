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

func TestAgentAUOption(t *testing.T) {
	for v, want := range map[uint64]bool{0: true, 1: true, 2: false, 3: false, 4: false, 5: false, 7: false} {
		if got := agentAUOption(v); got != want {
			t.Errorf("agentAUOption(%d) = %v, want %v", v, got, want)
		}
	}
}

// Only a pause in the shape the agent writes is removed.
func TestAgentPause(t *testing.T) {
	start, end := pauseWindow(time.Date(2026, 10, 26, 12, 4, 5, 0, time.UTC))
	own := map[string]string{}
	for _, n := range pauseStartValues {
		own[n] = start
	}
	for _, n := range pauseEndValues {
		own[n] = end
	}
	with := func(name, value string) map[string]string {
		m := map[string]string{}
		for k, v := range own {
			m[k] = v
		}
		if value == "" {
			delete(m, name)
		} else {
			m[name] = value
		}
		return m
	}
	for _, c := range []struct {
		name  string
		found map[string]string
		want  bool
	}{
		{"as written", own, true},
		{"one end already gone", with("PauseQualityUpdatesEndTime", ""), true},
		{"user paused one week", with("PauseUpdatesExpiryTime", "2026-11-02T12:04:05Z"), false},
		{"user paused again later", with("PauseFeatureUpdatesStartTime", "2026-10-27T08:00:00Z"), false},
		{"no start", with("PauseUpdatesStartTime", ""), false},
		{"other format", with("PauseUpdatesStartTime", "26.10.2026"), false},
		{"nothing", map[string]string{}, false},
	} {
		if got := agentPause(c.found); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
