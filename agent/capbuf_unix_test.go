// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Output past healthMaxOut is dropped and reported, the child still runs to its end.
func TestCapBufCapsChildOutput(t *testing.T) {
	ctx := context.Background()
	done := filepath.Join(t.TempDir(), "done")
	out, err := runOut(ctx, "sh", "-c", "head -c 6000000 /dev/zero && touch "+done)
	if len(out) != healthMaxOut || !errors.Is(err, errOutputTooLarge) {
		t.Fatalf("runOut kept %d bytes, err %v", len(out), err)
	}
	if _, err := os.Stat(done); err != nil {
		t.Fatal("child was cut off:", err)
	}
	// a run that ended keeps its exit code, the cut is noted in the stream
	so, se, code, err := runAppWith(ctx, func(*exec.Cmd) {}, "", "sh", "-c", "head -c 6000000 /dev/zero >&2; echo ok; exit 3")
	if so != "ok\n" || len(se) != healthMaxOut+len("\n[output truncated]") || !strings.HasSuffix(se, "\n[output truncated]") || code != 3 || err != nil {
		t.Fatalf("runAppWith: %q, %d stderr bytes, code %d, err %v", so, len(se), code, err)
	}
	// one that did not end still fails
	if _, _, code, err := runAppWith(ctx, func(*exec.Cmd) {}, "", "sh", "-c", "head -c 6000000 /dev/zero; kill -9 $$"); code != -1 || !errors.Is(err, errOutputTooLarge) {
		t.Fatalf("killed run: code %d, err %v", code, err)
	}
	if out, err := runOut(ctx, "sh", "-c", "echo hi; exit 3"); out != "hi\n" || errors.Is(err, errOutputTooLarge) || err == nil {
		t.Fatalf("small output: %q %v", out, err)
	}
}

// A child left holding stdout does not fail a run that exited 0.
func TestRunsIgnoreLingeringChild(t *testing.T) {
	old := pipeDrain
	defer func() { pipeDrain = old }()
	pipeDrain = 100 * time.Millisecond
	ctx := context.Background()
	if out, err := runOut(ctx, "sh", "-c", "echo hi; sleep 3 &"); out != "hi\n" || err != nil {
		t.Fatalf("runOut: %q %v", out, err)
	}
	if out, err := healCmd(time.Minute, "sh", "-c", "echo hi; sleep 3 &"); out != "hi\n" || err != nil {
		t.Fatalf("healCmd: %q %v", out, err)
	}
	if out, _, code, err := runAppWith(ctx, func(*exec.Cmd) {}, "/", "sh", "-c", "echo hi; sleep 3 &"); out != "hi\n" || code != 0 || err != nil {
		t.Fatalf("runAppWith: %q %d %v", out, code, err)
	}
}
