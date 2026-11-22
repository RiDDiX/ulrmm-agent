// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package agent

import (
	"context"
	"errors"
)

func imagingRecoveryCapability(context.Context, string) (ImagingCapability, error) {
	return ImagingCapability{}, errors.New("offline native capture requires Linux rescue")
}
