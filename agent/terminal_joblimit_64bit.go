// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows && (amd64 || arm64)

package agent

import "unsafe"

// jobObjectBasicLimitInfo is JOBOBJECT_BASIC_LIMIT_INFORMATION, embedded in
// the extended limit struct a terminal's job object gets. Go's natural
// layout matches the kernel's 64 bytes here.
type jobObjectBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// SetInformationJobObject refuses any other size.
var _ [0]struct{} = [unsafe.Sizeof(jobObjectBasicLimitInfo{}) - 64]struct{}{}
