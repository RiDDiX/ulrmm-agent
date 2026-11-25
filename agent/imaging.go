// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "context"

const linuxFilesMethod = "linux-files-v1"

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
	Volumes              []ImagingVolume                             `json:"volumes,omitempty"`
	MinTargetSize        int64                                       `json:"min_target_size,omitempty"`
	// Set by the server in a grant manifest (image.native), never reported.
	Include []string `json:"include,omitempty"`
	Missing []string `json:"missing,omitempty"`
	// Set by the agent from the run settings before the capture, never reported.
	Priority string `json:"priority,omitempty"`
}

type ImagingVolume struct {
	ID          string `json:"id"`
	Mount       string `json:"mount"`
	FS          string `json:"fs"`
	Kind        string `json:"kind"`
	Disk        string `json:"disk"`
	Size        int64  `json:"size"`
	Used        int64  `json:"used"`
	Consistency string `json:"consistency"`
	Reason      string `json:"reason"`
}

// imagingStreamError ends a capture whose stream source failed, so the point
// is reported as a capture failure and never sealed.
type imagingStreamError struct{ reason string }

func (e *imagingStreamError) Error() string { return "imaging stream failed: " + e.reason }
