// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import "errors"

// sdiodriver answers "not supported on this OS" here.
const sdioSupported = false

func (a *Agent) sdioHost() sdioHost {
	return sdioHost{root: func() (string, error) { return "", errors.New("not supported on this OS") }}
}
