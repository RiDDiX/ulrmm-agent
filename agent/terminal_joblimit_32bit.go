// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows && (386 || arm)

package agent

import "unsafe"

// jobObjectBasicLimitInfo is JOBOBJECT_BASIC_LIMIT_INFORMATION, embedded in
// the extended limit struct a terminal's job object gets. The kernel aligns
// it to 8 bytes, 48 in total; Go on 32 bit would stop at 44, hence the tail.
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
	_                       uint32
}

// SetInformationJobObject refuses any other size.
var _ [0]struct{} = [unsafe.Sizeof(jobObjectBasicLimitInfo{}) - 48]struct{}{}
