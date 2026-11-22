// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"testing"
	"time"
)

func TestMacImagingValidateExternalDisk(t *testing.T) {
	config := macBackupConfig{PartitionUUID: "c4457720-4ca7-4b0a-b45f-23d03e8bd251"}
	external := false
	whole := macDiskInfo{
		DeviceIdentifier: "disk3", Content: "GUID_partition_scheme", WholeDisk: true,
		Internal: &external, VirtualOrPhysical: "Physical", TotalSize: 1 << 30, DeviceBlockSize: 4096,
	}
	store := macDiskInfo{DiskUUID: config.PartitionUUID, Content: "Apple_APFS", ParentWholeDisk: "disk3"}
	partitions := []string{"EFI", "Apple_APFS"}
	if !macImagingValidateDisk(config, whole, store, partitions) {
		t.Fatal("rejected pinned dedicated external disk")
	}
	if macImagingValidateDisk(config, whole, store, append(partitions, "Apple_APFS")) {
		t.Fatal("accepted a disk with unrelated partitions")
	}
	if macImagingValidateDisk(macBackupConfig{PartitionUUID: "different"}, whole, store, partitions) {
		t.Fatal("accepted a different Time Machine disk")
	}
	isInternal := true
	whole.Internal = &isInternal
	if macImagingValidateDisk(config, whole, store, partitions) {
		t.Fatal("accepted an internal disk")
	}
	whole.Internal = nil
	if macImagingValidateDisk(config, whole, store, partitions) {
		t.Fatal("accepted a disk with unknown location")
	}
}

func TestMacImagingNewBackup(t *testing.T) {
	first, second, third := "2026-11-22-010000", "2026-11-22-020000", "2026-11-22-030000"
	before := map[string]bool{second: true}
	if !macImagingNewBackup(before, map[string]bool{third: true}) {
		t.Fatal("rejected a new completed backup when the old one was pruned")
	}
	if macImagingNewBackup(before, before) ||
		macImagingNewBackup(before, map[string]bool{first: true, second: true}) ||
		macImagingNewBackup(nil, map[string]bool{first: true, third: true}) {
		t.Fatal("accepted an unchanged, out-of-order or ambiguous backup")
	}
	if !macImagingNewBackup(nil, map[string]bool{first: true}) {
		t.Fatal("rejected the first completed backup")
	}
}

func TestMacImagingReceiptStartsFreshAfterNewerBackup(t *testing.T) {
	config := macBackupConfig{DestinationID: "c4457720-4ca7-4b0a-b45f-23d03e8bd251"}
	job, first, second := "6917640e-87bd-4587-982e-d1942e26f2cf", "2026-11-22-010000", "2026-11-22-020000"
	receipt := macImagingReceipt{JobID: job, Config: config, Date: first}
	if !macImagingReceiptCurrent(receipt, job, config, map[string]bool{first: true}) {
		t.Fatal("did not resume the unchanged Time Machine history")
	}
	if macImagingReceiptCurrent(receipt, job, config, map[string]bool{first: true, second: true}) ||
		macImagingReceiptCurrent(receipt, "55d58fa9-50e5-482e-82a4-4a5f51fd353a", config, map[string]bool{first: true}) ||
		macImagingReceiptCurrent(macImagingReceipt{JobID: job, Config: config}, job, config, nil) {
		t.Fatal("reused a stale, foreign or empty receipt")
	}
}

func TestMacImagingSuperblockXID(t *testing.T) {
	block := make([]byte, 4096)
	copy(block[32:], "NXSB")
	block[16], block[17] = 0x34, 0x12
	if xid, err := macImagingSuperblockXID(block); err != nil || xid != 0x1234 {
		t.Fatalf("xid %x: %v", xid, err)
	}
	if _, err := macImagingSuperblockXID(make([]byte, 4096)); err == nil {
		t.Fatal("accepted a block without an APFS container superblock")
	}
}

func TestMacImagingCommandTimesOut(t *testing.T) {
	defer func(limit time.Duration) { macImagingCommandTimeout = limit }(macImagingCommandTimeout)
	macImagingCommandTimeout = 100 * time.Millisecond
	start := time.Now()
	if _, err := macImagingCommand(context.Background(), "/bin/sleep", "5"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("hung disk tool ran %v: %v", time.Since(start), err)
	}
}
