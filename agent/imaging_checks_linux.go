// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os/exec"
	"slices"
)

func imagingOSChecks(_ string, _ int64, probe func() ImagingCapability) (ImagingCapability, []imagingCheck) {
	capability := probe()
	ext4 := slices.ContainsFunc(capability.Volumes, func(v ImagingVolume) bool { return v.FS == "ext4" })
	return capability, []imagingCheck{imagingToolsCheck(func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	}, ext4)}
}
