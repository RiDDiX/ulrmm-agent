// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"context"
	"runtime"
	"time"
)

// imagingOnAC tells whether the device runs on AC; unknown counts as AC.
// Tests replace it.
var imagingOnAC = func() (onAC, known bool) {
	switch runtime.GOOS {
	case "darwin":
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return imagingPmsetAC(runOut(ctx, "/usr/bin/pmset", "-g", "batt"))
	case "linux":
		return imagingSysfsOnAC("/sys/class/power_supply")
	}
	return false, false
}
