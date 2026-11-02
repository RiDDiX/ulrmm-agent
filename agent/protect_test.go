// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestNewUninstallCode(t *testing.T) {
	a, b := newUninstallCode(), newUninstallCode()
	if !regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(a) || a == b {
		t.Fatalf("codes %q %q", a, b)
	}
}

func TestManualStopIsReportedOnce(t *testing.T) {
	dir := t.TempDir()
	boot := time.Now().Add(-time.Hour)

	recordStop(dir, time.Now())
	if r := stopReason(dir, boot); r != "manual" {
		t.Fatalf("reason %q", r)
	}
	if r := stopReason(dir, boot); r != "manual" {
		t.Fatalf("marker gone before the server took it: %q", r)
	}
	ackStop(dir)
	if r := stopReason(dir, boot); r != "" {
		t.Fatalf("reported twice: %q", r)
	}
}

func TestExpectedStopIsNoTamper(t *testing.T) {
	dir := t.TempDir()
	boot := time.Now().Add(-time.Hour)

	expectStop(dir)
	recordStop(dir, time.Now())
	if r := stopReason(dir, boot); r != "" {
		t.Fatalf("update/uninstall stop reported as %q", r)
	}
	if _, err := os.Stat(filepath.Join(dir, stopExpectedFile)); err == nil {
		t.Fatal("expected marker not used up")
	}

	// a stale expectation does not cover a later stop
	expectStop(dir)
	old := time.Now().Add(-stopExpectedFor - time.Minute)
	os.Chtimes(filepath.Join(dir, stopExpectedFile), old, old)
	recordStop(dir, time.Now())
	if r := stopReason(dir, boot); r != "manual" {
		t.Fatalf("stale expectation hid a manual stop: %q", r)
	}
}

func TestStopBeforeBootIsShutdown(t *testing.T) {
	dir := t.TempDir()
	stopped := time.Now().Add(-2 * time.Hour)
	recordStop(dir, stopped)
	os.Chtimes(filepath.Join(dir, stopManualFile), stopped, stopped)
	if r := stopReason(dir, time.Now().Add(-time.Hour)); r != "" {
		t.Fatalf("shutdown reported as %q", r)
	}
	if _, err := os.Stat(filepath.Join(dir, stopManualFile)); err == nil {
		t.Fatal("stale marker kept")
	}
}
