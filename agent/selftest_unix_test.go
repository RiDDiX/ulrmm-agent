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
	"time"
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

// without a NATS connection the rollback copy comes back once the time is
// up; keepNew drops it instead
func TestArmRevert(t *testing.T) {
	dir := t.TempDir()
	oldCopy, oldAfter, oldTarget, oldRestart, oldDir := rollbackCopy, revertAfter, revertTarget, revertRestart, nixAgentDir
	t.Cleanup(func() {
		rollbackCopy, revertAfter, revertTarget, revertRestart, nixAgentDir = oldCopy, oldAfter, oldTarget, oldRestart, oldDir
	})
	self := filepath.Join(dir, "agent")
	rollbackCopy, nixAgentDir, revertAfter = self+".previous", dir, 50*time.Millisecond
	revertTarget = func() (string, error) { return self, nil }
	restarted := make(chan struct{}, 2)
	revertRestart = func(*Agent) error { restarted <- struct{}{}; return nil }
	arm := func() func() {
		t.Helper()
		if os.WriteFile(self, []byte("new"), 0o755) != nil || os.WriteFile(rollbackCopy, []byte("old"), 0o755) != nil {
			t.Fatal("setup")
		}
		return testUpdateAgent().armRevert()
	}
	check := func(name, want string) {
		t.Helper()
		if b, _ := os.ReadFile(self); string(b) != want {
			t.Fatalf("%s: binary is %q, want %q", name, b, want)
		}
		if _, err := os.Stat(rollbackCopy); !os.IsNotExist(err) {
			t.Fatalf("%s: rollback copy still there: %v", name, err)
		}
	}

	arm()
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("no revert")
	}
	check("never connected", "old")

	arm()()
	time.Sleep(4 * revertAfter)
	select {
	case <-restarted:
		t.Fatal("reverted after keepNew")
	default:
	}
	check("kept", "new")
}
