// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package agent

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/StackExchange/wmi"
)

const driversSupported = true

// wmiTyped is wmiFixed into the class struct itself; a property older
// Windows lacks (PNPClass) leaves that field empty.
func wmiTyped[T any](where string) ([]T, error) {
	return wmiBounded(wmiClassTimeout, func() ([]T, error) {
		var dst []T
		err := wmi.Query(wmi.CreateQuery(&dst, where), &dst)
		var mismatch *wmi.ErrFieldMismatch
		if err != nil && !errors.As(err, &mismatch) {
			return nil, err
		}
		return dst, nil
	})
}

func pnpSignedDrivers() ([]Win32_PnPSignedDriver, error) {
	d, err := wmiTyped[Win32_PnPSignedDriver]("")
	if err != nil {
		return d, err
	}
	return dropDeleted(d, filepath.Join(os.Getenv("SystemRoot"), "INF")), nil
}

func pnpProblemDevices() ([]Win32_PnPEntity, error) {
	return wmiTyped[Win32_PnPEntity]("WHERE ConfigManagerErrorCode <> 0")
}
