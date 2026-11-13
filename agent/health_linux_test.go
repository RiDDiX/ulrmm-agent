// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An LXC guest lists the host's controllers in sysfs without their nodes.
func TestNvmeDisksSkipsMissingNode(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	for _, n := range []string{"nvme0", "nvme1"} {
		if err := os.MkdirAll(filepath.Join(sys, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h := &Health{}
	nvmeDisks(h, sys, dev)
	if len(h.Errors) != 0 || len(h.Disks) != 0 {
		t.Fatalf("errors %q disks %+v", h.Errors, h.Disks)
	}
	// a node that is there but answers no ioctl is still reported
	if err := os.WriteFile(filepath.Join(dev, "nvme1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	nvmeDisks(h, sys, dev)
	if len(h.Errors) != 1 || !strings.HasPrefix(h.Errors[0], "nvme1: ") || len(h.Disks) != 0 {
		t.Fatalf("errors %q disks %+v", h.Errors, h.Disks)
	}
}
