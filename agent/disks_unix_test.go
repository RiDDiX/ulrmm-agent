// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"sync/atomic"
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/sirupsen/logrus"
)

func TestGetDisksBounded(t *testing.T) {
	var calls atomic.Int32
	old := diskUsage
	diskUsage = func(string) (*disk.UsageStat, error) { calls.Add(1); return &disk.UsageStat{Total: 12345}, nil }
	defer func() { diskUsage = old }()

	a := &Agent{Logger: logrus.New()}
	got := a.GetDisks()
	if len(got) == 0 {
		t.Skip("no partitions here")
	}
	if int(calls.Load()) != len(got) {
		t.Fatalf("calls %d for %d disks", calls.Load(), len(got))
	}
	for _, d := range got {
		if d.TotalText != "12.1 kB" {
			t.Fatalf("%+v", d)
		}
	}
}
