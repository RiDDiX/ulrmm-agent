// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The download's -selftest decides whether it replaces the running build.
func TestProbeAgentBinary(t *testing.T) {
	dir := t.TempDir()
	a := testUpdateAgent()
	for name, tc := range map[string]struct {
		script, want string
		transient    bool
	}{
		"ok":      {"#!/bin/sh\n[ \"$1\" = -selftest ] && echo selftest ok 1.0\n", "", false},
		"failed":  {"#!/bin/sh\necho 'selftest failed: tls handshake' >&2\nexit 1\n", "selftest", false},
		"missing": {"", "selftest", false},
		// exit 2: the RMM was not reachable, the update is retried, not refused
		"down": {"#!/bin/sh\necho 'selftest failed: transient failure: health: connection refused' >&2\nexit 2\n", "selftest", true},
	} {
		path := filepath.Join(dir, name)
		if tc.script != "" {
			if err := os.WriteFile(path, []byte(tc.script), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		err := a.probeAgentBinary(path)
		if tc.want == "" && err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tc.want != "" {
			var bd badDownload
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.As(err, &bd) == tc.transient {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
}
