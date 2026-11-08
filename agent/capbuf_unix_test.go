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
	"testing"
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
	so, se, code, err := runAppWith(ctx, func(*exec.Cmd) {}, "", "sh", "-c", "head -c 6000000 /dev/zero >&2; echo ok")
	if so != "ok\n" || len(se) != healthMaxOut || code != 0 || !errors.Is(err, errOutputTooLarge) {
		t.Fatalf("runAppWith: %q, %d stderr bytes, code %d, err %v", so, len(se), code, err)
	}
	if out, err := runOut(ctx, "sh", "-c", "echo hi; exit 3"); out != "hi\n" || errors.Is(err, errOutputTooLarge) || err == nil {
		t.Fatalf("small output: %q %v", out, err)
	}
}
