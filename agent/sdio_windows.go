// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package agent

import (
	"strconv"

	"golang.org/x/sys/windows"
)

const sdioSupported = true

func (a *Agent) sdioHost() sdioHost {
	return sdioHost{
		root: func() (string, error) {
			if err := createWinTempDir(); err != nil {
				return "", err
			}
			work, _ := winWorkDirs()
			return work, nil
		},
		free: sdioFreeSpace,
		install: func(script, dir string, timeout int) (string, string) {
			env := []string{"PKG_DIR=" + dir, "PKG_KIND=driver", "PKG_MODE=system", "PKG_TIMEOUT=" + strconv.Itoa(timeout-60)}
			stdout, stderr, _, _ := a.RunScript(script, "powershell", nil, timeout, false, env, false, "")
			return stdout, stderr
		},
	}
}

// free bytes for this account on the volume of dir
func sdioFreeSpace(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}
