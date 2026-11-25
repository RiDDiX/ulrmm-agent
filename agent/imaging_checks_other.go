// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows && !linux

package agent

func imagingOSChecks(_ string, _ int64, probe func() ImagingCapability) (ImagingCapability, []imagingCheck) {
	return probe(), nil
}
