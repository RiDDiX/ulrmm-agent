// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// Linux/macOS only, see nixservices.go and nixlogs.go
var errNixOnly = errors.New("not available on Windows")

func PosixServices() ([]rmm.UnixService, error) { return nil, errNixOnly }

func PosixSvcAction(name, action string) error { return errNixOnly }

func PosixLogs(p map[string]string) (*rmm.PosixLogs, error) { return nil, errNixOnly }

// script dirs are a unix concern
func ownDir(string) error { return nil }
