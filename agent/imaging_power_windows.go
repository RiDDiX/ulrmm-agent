// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "unsafe"

var procGetSystemPowerStatus = modkernel32.NewProc("GetSystemPowerStatus")

// SYSTEM_POWER_STATUS
type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

// imagingOnAC tells whether the device runs on AC; unknown counts as AC.
// Tests replace it.
var imagingOnAC = func() (onAC, known bool) {
	var s systemPowerStatus
	if r, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s))); r == 0 {
		return false, false
	}
	return imagingACLine(s.ACLineStatus)
}
