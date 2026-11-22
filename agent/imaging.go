// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "context"

// ImagingCapability describes the local backup source and the procedure needed
// to recover it. Size describes the recovery disk and can differ from the stream.
type ImagingCapability struct {
	PriorCaptureFinished func(context.Context, string) (bool, error) `json:"-"`
	JobID                string                                      `json:"-"`
	Method               string                                      `json:"method"`
	Scope                string                                      `json:"scope"`
	Recovery             string                                      `json:"recovery"`
	Reason               string                                      `json:"reason"`
	SourceID             string                                      `json:"source_id"`
	Encryption           string                                      `json:"encryption"`
	Ready                bool                                        `json:"ready"`
	Size                 int64                                       `json:"size"`
	SectorSize           int                                         `json:"sector_size"`
	DeviceUUID           string                                      `json:"device_uuid"`
	BootMode             string                                      `json:"boot_mode"`
}
