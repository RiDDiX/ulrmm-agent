// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !windows && !darwin

package agent

import (
	"context"
	"errors"
	"io"
	"net"
)

func nativeImagingCapability(context.Context) ImagingCapability {
	return ImagingCapability{Reason: "Native backup unavailable on this operating system"}
}
func nativeImagingCapture(context.Context, ImagingCapability) (io.ReadCloser, error) {
	return nil, errors.New("native backup unavailable")
}
func imagingDialContext(string) (func(context.Context, string, string) (net.Conn, error), error) {
	return nil, errors.New("internal imaging unavailable")
}
