// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"encoding/base64"
	"fmt"
)

func legacyWrap(b []byte) (string, error) {
	return wrapRaw + base64.StdEncoding.EncodeToString(b), nil
}

func unprotectDPAPI([]byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: a DPAPI secret cannot be opened on this system", errUnwrap)
}
