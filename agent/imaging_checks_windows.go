// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"runtime"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// The service fixes run first, so the capability sees their result.
func imagingOSChecks(autoSetup string, now int64, probe func() ImagingCapability) (ImagingCapability, []imagingCheck) {
	run := func(argv []string) error {
		_, err := CMD(argv[0], argv[1:], 60)
		return err
	}
	var list []imagingCheck
	for _, s := range [][2]string{{"win.vss_service", "VSS"}, {"win.swprv_service", "swprv"}} {
		var disabled bool
		err := withService(s[1], windows.SERVICE_QUERY_CONFIG, func(svc *mgr.Service) error {
			c, err := svc.Config()
			disabled = c.StartType == windows.SERVICE_DISABLED
			return err
		})
		list = append(list, imagingServiceCheck(s[0], s[1], disabled, err, autoSetup, run, now))
	}
	return probe(), append(list, imagingArchCheck(runtime.GOARCH, windowsAppxArch()))
}
