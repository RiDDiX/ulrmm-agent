// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import "errors"

const driversSupported = false

var errNoDrivers = errors.New("driver inventory is only collected on Windows")

func pnpSignedDrivers() ([]Win32_PnPSignedDriver, error) { return nil, errNoDrivers }
func pnpProblemDevices() ([]Win32_PnPEntity, error)      { return nil, errNoDrivers }
