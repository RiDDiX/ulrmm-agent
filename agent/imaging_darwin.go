// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"howett.net/plist"
)

const (
	macImagingConfig      = "/etc/ulrmm-imaging.json"
	macImagingReceiptPath = "/var/db/ulrmm-imaging.json"
	macImagingMethod      = "macos-timemachine-disk-v1"
)

// macImagingCommandTimeout bounds local disk tools; tmutil startbackup brings its own longer deadline.
var macImagingCommandTimeout = 10 * time.Minute

var (
	macImagingUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)
	macWholeDisk   = regexp.MustCompile(`^disk[0-9]+$`)
	macPartition   = regexp.MustCompile(`^disk[0-9]+s[0-9]+$`)
	macBackupDate  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}$`)
)

type macBackupConfig struct {
	// These are distinct UUIDs. The Time Machine destination ID selects the job.
	// The APFS volume and GPT partition UUIDs pin the media that may be exported.
	DestinationID string `json:"destination_id"`
	VolumeUUID    string `json:"volume_uuid"`
	PartitionUUID string `json:"partition_uuid"`
}

type macDiskInfo struct {
	DeviceIdentifier       string
	ParentWholeDisk        string
	APFSContainerReference string
	DiskUUID               string
	VolumeUUID             string
	Content                string
	MountPoint             string
	WholeDisk              bool
	Internal               *bool
	VirtualOrPhysical      string
	TotalSize              int64
	DeviceBlockSize        int
}

type macAPFSVolume struct {
	APFSVolumeUUID    string
	DeviceIdentifier  string
	Roles             []string
	Encryption        *bool
	Locked            bool
	CryptoMigrationOn bool
}

type macAPFSContainer struct {
	ContainerReference string
	Fusion             bool
	PhysicalStores     []struct {
		DeviceIdentifier string
		DiskUUID         string
	}
	Volumes      []macAPFSVolume
	VolumeGroups []struct {
		Volumes []struct {
			Role             string
			DeviceIdentifier string
		}
	}
}

type macBackupMedia struct {
	config    macBackupConfig
	disk      macDiskInfo
	store     string
	mount     string
	encrypted bool
}

func macReadBackupConfig() (macBackupConfig, error) {
	var config macBackupConfig
	if os.Geteuid() != 0 {
		return config, errors.New("Time Machine imaging requires the root ULRMM service")
	}
	fd, err := syscall.Open(macImagingConfig, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return config, errors.New("configure a dedicated local Time Machine disk in " + macImagingConfig)
	}
	file := os.NewFile(uintptr(fd), macImagingConfig)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return config, err
	}
	if s, ok := info.Sys().(*syscall.Stat_t); !ok || s.Uid != 0 || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() || info.Size() > 4096 {
		return config, errors.New("Time Machine configuration must be a regular root-owned 0600 file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(raw, &config); err != nil || !macImagingUUID.MatchString(config.DestinationID) ||
		!macImagingUUID.MatchString(config.VolumeUUID) || !macImagingUUID.MatchString(config.PartitionUUID) {
		return config, errors.New("configure valid destination_id, volume_uuid and partition_uuid values")
	}
	return config, nil
}

func macImagingCommand(ctx context.Context, command string, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		// A disk tool hung on a failing USB bridge would stop the imaging loop.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, macImagingCommandTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) && strings.Contains(strings.ToLower(string(failure.Stderr)), "full disk access") {
			return nil, errors.New("grant Full Disk Access to the signed ULRMM service")
		}
		return out, fmt.Errorf("%s %s failed: %w", command, args[0], err)
	}
	return out, nil
}

func macImagingPlist(ctx context.Context, result any, command string, args ...string) error {
	out, err := macImagingCommand(ctx, command, args...)
	if err != nil {
		return err
	}
	if _, err = plist.Unmarshal(out, result); err != nil {
		return fmt.Errorf("cannot read %s %s metadata: %w", command, args[0], err)
	}
	return nil
}

func macImagingDiskInfo(ctx context.Context, disk string) (macDiskInfo, error) {
	var info macDiskInfo
	err := macImagingPlist(ctx, &info, "/usr/sbin/diskutil", "info", "-plist", disk)
	return info, err
}

func macImagingContainer(ctx context.Context, reference string) (macAPFSContainer, error) {
	var list struct{ Containers []macAPFSContainer }
	if !macWholeDisk.MatchString(reference) {
		return macAPFSContainer{}, errors.New("expected an APFS container")
	}
	if err := macImagingPlist(ctx, &list, "/usr/sbin/diskutil", "apfs", "list", "-plist", reference); err != nil {
		return macAPFSContainer{}, err
	}
	for _, container := range list.Containers {
		if container.ContainerReference == reference {
			return container, nil
		}
	}
	return macAPFSContainer{}, errors.New("cannot identify APFS container")
}

func macImagingBootVolumeGroup(system, data macDiskInfo, container macAPFSContainer) bool {
	for _, group := range container.VolumeGroups {
		var dataFound, systemFound bool
		for _, member := range group.Volumes {
			dataFound = dataFound || member.Role == "Data" && member.DeviceIdentifier == data.DeviceIdentifier
			// diskutil reports a child disk identifier when / is an active signed APFS snapshot.
			systemFound = systemFound || member.Role == "System" && (member.DeviceIdentifier == system.DeviceIdentifier ||
				strings.HasPrefix(system.DeviceIdentifier, member.DeviceIdentifier+"s"))
		}
		if dataFound && systemFound {
			return true
		}
	}
	return false
}

func macImagingValidateDisk(config macBackupConfig, whole, store macDiskInfo, partitions []string) bool {
	if whole.Internal == nil || *whole.Internal || !whole.WholeDisk || whole.VirtualOrPhysical != "Physical" ||
		whole.Content != "GUID_partition_scheme" || !macWholeDisk.MatchString(whole.DeviceIdentifier) ||
		whole.TotalSize < 1 || (whole.DeviceBlockSize != 512 && whole.DeviceBlockSize != 4096) ||
		whole.TotalSize%int64(whole.DeviceBlockSize) != 0 ||
		!strings.EqualFold(config.PartitionUUID, store.DiskUUID) || store.ParentWholeDisk != whole.DeviceIdentifier ||
		store.Content != "Apple_APFS" || len(partitions) != 2 {
		return false
	}
	gptCount := 0
	for _, partition := range partitions {
		if partition == "EFI" || partition == "Apple_APFS" {
			gptCount++
		}
	}
	return gptCount == 2 && partitions[0] != partitions[1]
}

func macImagingMedia(ctx context.Context, config macBackupConfig) (macBackupMedia, error) {
	media := macBackupMedia{config: config}
	volume, err := macImagingDiskInfo(ctx, config.VolumeUUID)
	if err == nil && strings.EqualFold(volume.VolumeUUID, config.VolumeUUID) && volume.MountPoint == "" {
		// A capture stopped before its remount leaves the attached volume unmounted.
		if _, err = macImagingCommand(ctx, "/usr/sbin/diskutil", "mount", config.VolumeUUID); err == nil {
			volume, err = macImagingDiskInfo(ctx, config.VolumeUUID)
		}
	}
	if err != nil || !strings.EqualFold(volume.VolumeUUID, config.VolumeUUID) || !strings.HasPrefix(volume.MountPoint, "/Volumes/") {
		return media, errors.New("connect and unlock the dedicated Time Machine APFS disk")
	}
	container, err := macImagingContainer(ctx, volume.APFSContainerReference)
	if err != nil {
		return media, err
	}
	if container.Fusion || len(container.PhysicalStores) != 1 || len(container.Volumes) != 1 {
		return media, errors.New("Time Machine media requires one dedicated APFS container and volume")
	}
	backup := container.Volumes[0]
	if backup.DeviceIdentifier != volume.DeviceIdentifier || !strings.EqualFold(backup.APFSVolumeUUID, config.VolumeUUID) ||
		len(backup.Roles) != 1 || backup.Roles[0] != "Backup" || backup.Encryption == nil || backup.Locked || backup.CryptoMigrationOn {
		return media, errors.New("expected one unlocked APFS Time Machine Backup volume with known encryption state")
	}
	store, err := macImagingDiskInfo(ctx, container.PhysicalStores[0].DeviceIdentifier)
	if err != nil {
		return media, err
	}
	if !macWholeDisk.MatchString(store.ParentWholeDisk) || !macPartition.MatchString(store.DeviceIdentifier) ||
		!strings.EqualFold(store.DiskUUID, container.PhysicalStores[0].DiskUUID) {
		return media, errors.New("cannot identify the dedicated Time Machine physical store")
	}
	whole, err := macImagingDiskInfo(ctx, store.ParentWholeDisk)
	if err != nil {
		return media, err
	}
	var list struct {
		AllDisksAndPartitions []struct {
			DeviceIdentifier string
			Partitions       []struct {
				Content string
			}
		}
	}
	if err := macImagingPlist(ctx, &list, "/usr/sbin/diskutil", "list", "-plist", whole.DeviceIdentifier); err != nil {
		return media, err
	}
	var partitions []string
	for _, disk := range list.AllDisksAndPartitions {
		if disk.DeviceIdentifier == whole.DeviceIdentifier {
			for _, partition := range disk.Partitions {
				partitions = append(partitions, partition.Content)
			}
		}
	}
	if !macImagingValidateDisk(config, whole, store, partitions) {
		return media, errors.New("Time Machine media must be the pinned external physical GPT disk with only EFI and one APFS partition")
	}
	media.disk, media.store, media.mount, media.encrypted = whole, store.DeviceIdentifier, volume.MountPoint, *backup.Encryption
	return media, nil
}

func macImagingDestination(ctx context.Context, media macBackupMedia) error {
	var result struct {
		Destinations []struct {
			ID               string
			Kind             string
			MountPoint       string
			SpacedMountPoint string `plist:"Mount Point"`
		}
	}
	if err := macImagingPlist(ctx, &result, "/usr/bin/tmutil", "destinationinfo", "-X"); err != nil {
		return err
	}
	for _, dest := range result.Destinations {
		if strings.EqualFold(dest.ID, media.config.DestinationID) && dest.Kind == "Local" &&
			(dest.MountPoint == media.mount || dest.SpacedMountPoint == media.mount) {
			return nil
		}
	}
	return errors.New("configure the pinned APFS volume as a local Time Machine destination")
}

func nativeImagingCapability(ctx context.Context) ImagingCapability {
	capability, _, err := macImagingPreflight(ctx)
	if err != nil {
		capability.Reason = err.Error()
	}
	return capability
}

func macImagingPreflight(ctx context.Context) (ImagingCapability, macBackupMedia, error) {
	capability := ImagingCapability{
		Method:   macImagingMethod,
		Scope:    "Time Machine-covered apps, accounts, settings and data. Review exclusions. The signed macOS system is reinstalled.",
		BootMode: "apple-silicon",
	}
	startup := "Hold the power button, then choose Options for macOS Recovery."
	if arm, _ := syscall.SysctlUint32("hw.optional.arm64"); runtime.GOARCH == "amd64" && arm != 1 {
		capability.BootMode = "uefi"
		startup = "Start with Command-R, or Option-Command-R for Internet Recovery if local Recovery is unavailable."
	}
	capability.Recovery = startup + " Install compatible macOS on the replacement storage. " +
		"Recreate the selected point's external Time Machine disk on separate media, unlock it if encrypted, " +
		"then migrate accounts, apps and data with Setup or Migration Assistant."
	config, err := macReadBackupConfig()
	if err != nil {
		return capability, macBackupMedia{}, err
	}
	data, err := macImagingDiskInfo(ctx, "/System/Volumes/Data")
	if err != nil {
		return capability, macBackupMedia{}, err
	}
	system, err := macImagingDiskInfo(ctx, "/")
	if err != nil {
		return capability, macBackupMedia{}, err
	}
	container, err := macImagingContainer(ctx, data.APFSContainerReference)
	if err != nil {
		return capability, macBackupMedia{}, err
	}
	if !macImagingBootVolumeGroup(system, data, container) {
		return capability, macBackupMedia{}, errors.New("this macOS startup disk has no recognized APFS System/Data volume group")
	}
	fileVault, err := macImagingCommand(ctx, "/usr/bin/fdesetup", "status")
	if err != nil {
		return capability, macBackupMedia{}, err
	}
	media, err := macImagingMedia(ctx, config)
	if err != nil {
		return capability, media, err
	}
	if err := macImagingDestination(ctx, media); err != nil {
		return capability, media, err
	}
	if _, err := macImagingBackupDates(ctx, media.mount); err != nil {
		return capability, media, err
	}
	var platform []struct{ IOPlatformUUID string }
	if err := macImagingPlist(ctx, &platform, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice", "-a"); err != nil {
		return capability, media, err
	}
	if len(platform) != 1 || !macImagingUUID.MatchString(platform[0].IOPlatformUUID) {
		return capability, media, errors.New("cannot identify this Mac's platform UUID")
	}
	capability.DeviceUUID = strings.ToLower(platform[0].IOPlatformUUID)
	capability.SourceID = strings.ToLower(config.PartitionUUID)
	capability.Size, capability.SectorSize = media.disk.TotalSize, media.disk.DeviceBlockSize
	capability.Encryption = strings.TrimSpace(strings.SplitN(string(fileVault), "\n", 2)[0]) + " Time Machine media: unencrypted."
	if media.encrypted {
		capability.Encryption = strings.TrimSpace(strings.SplitN(string(fileVault), "\n", 2)[0]) + " Time Machine media: APFS encrypted."
	}
	capability.Ready = true
	capability.Reason = "Requires Full Disk Access and a dedicated unlocked Time Machine disk. Recovery requires Apple's installers and Migration Assistant."
	return capability, media, nil
}

func macImagingBackupDates(ctx context.Context, mount string) (map[string]bool, error) {
	out, err := macImagingCommand(ctx, "/usr/bin/tmutil", "listbackups", "-d", mount, "-t")
	dates := make(map[string]bool)
	if err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			message := string(out) + string(failure.Stderr)
			if strings.Contains(message, "No machine directory found for host.") || strings.Contains(message, "No backups found for host.") {
				return dates, nil
			}
		}
		return nil, err
	}
	for _, date := range strings.Fields(string(out)) {
		if !macBackupDate.MatchString(date) {
			return nil, errors.New("Time Machine returned an unsupported backup timestamp")
		}
		dates[date] = true
	}
	return dates, nil
}

func nativeImagingCapture(ctx context.Context, expected ImagingCapability) (io.ReadCloser, error) {
	current, media, err := macImagingPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if current.Method != expected.Method || current.DeviceUUID != expected.DeviceUUID || current.SourceID != expected.SourceID ||
		current.Size != expected.Size || current.SectorSize != expected.SectorSize || current.BootMode != expected.BootMode || current.Encryption != expected.Encryption || current.Scope != expected.Scope {
		return nil, errors.New("Time Machine media or Mac identity changed after the imaging request")
	}
	before, err := macImagingBackupDates(ctx, media.mount)
	if err != nil {
		return nil, err
	}
	if !macImagingUUID.MatchString(expected.JobID) {
		return nil, errors.New("missing native backup job identity")
	}
	var receipt macImagingReceipt
	if raw, err := os.ReadFile(macImagingReceiptPath); err == nil {
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return nil, errors.New("cannot read the local Time Machine backup receipt")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if macImagingReceiptCurrent(receipt, expected.JobID, media.config, before) {
		return macImagingOpenArchive(ctx, media)
	}
	backup, cancel := context.WithTimeout(ctx, 24*time.Hour)
	_, err = macImagingCommand(backup, "/usr/bin/tmutil", "startbackup", "--block", "--destination", media.config.DestinationID)
	cancel()
	if err != nil {
		return nil, err
	}
	after, err := macImagingBackupDates(ctx, media.mount)
	if err != nil {
		return nil, err
	}
	if !macImagingNewBackup(before, after) {
		return nil, errors.New("Time Machine did not produce exactly one new latest completed backup")
	}
	if err := macImagingWriteReceipt(macImagingReceipt{JobID: expected.JobID, Config: media.config, Date: macImagingNewest(after)}); err != nil {
		return nil, err
	}
	return macImagingOpenArchive(ctx, media)
}

// macImagingReceiptCurrent tells whether an interrupted capture of this job can
// reuse its Time Machine backup. A later backup on the disk starts a new one.
func macImagingReceiptCurrent(receipt macImagingReceipt, job string, config macBackupConfig, before map[string]bool) bool {
	return receipt.JobID == job && receipt.Config == config && receipt.Date != "" && receipt.Date == macImagingNewest(before)
}

func macImagingNewest(dates map[string]bool) string {
	var newest string
	for date := range dates {
		if date > newest {
			newest = date
		}
	}
	return newest
}

func macImagingNewBackup(before, after map[string]bool) bool {
	added := 0
	for date := range after {
		if !before[date] {
			added++
		}
	}
	return added == 1 && !before[macImagingNewest(after)]
}

type macImagingReceipt struct {
	JobID  string
	Config macBackupConfig
	Date   string
}

func macImagingWriteReceipt(receipt macImagingReceipt) error {
	file, err := os.CreateTemp("/var/db", ".ulrmm-imaging-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(receipt); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), macImagingReceiptPath)
}

func macImagingOpenArchive(ctx context.Context, media macBackupMedia) (io.ReadCloser, error) {
	fresh, err := macImagingMedia(ctx, media.config)
	if err != nil || fresh.disk.DeviceIdentifier != media.disk.DeviceIdentifier || fresh.store != media.store || fresh.disk.TotalSize != media.disk.TotalSize ||
		fresh.disk.DeviceBlockSize != media.disk.DeviceBlockSize || fresh.mount != media.mount || fresh.encrypted != media.encrypted {
		return nil, errors.New("Time Machine disk changed before archive capture")
	}
	remount := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := macImagingCommand(cleanup, "/usr/sbin/diskutil", "mount", media.config.VolumeUUID)
		return err
	}
	if _, err := macImagingCommand(ctx, "/usr/sbin/diskutil", "unmountDisk", media.disk.DeviceIdentifier); err != nil {
		return nil, errors.Join(err, remount())
	}
	if err := macImagingCheckUnmounted(ctx, media); err != nil {
		return nil, errors.Join(err, remount())
	}
	// The raw device skips the buffer cache for the sequential read.
	file, err := os.Open("/dev/r" + media.disk.DeviceIdentifier)
	if err != nil {
		return nil, errors.Join(err, remount())
	}
	if err := macImagingCheckUnmounted(ctx, media); err != nil {
		return nil, errors.Join(err, file.Close(), remount())
	}
	xid, err := macImagingContainerXID(media.store)
	if err != nil {
		return nil, errors.Join(err, file.Close(), remount())
	}
	return &macImagingArchive{file: file, reader: io.NewSectionReader(file, 0, media.disk.TotalSize), ctx: ctx, media: media, remount: remount, xid: xid}, nil
}

// macImagingContainerXID reads the transaction ID of the APFS container
// superblock in the first block of the Time Machine partition.
func macImagingContainerXID(store string) (uint64, error) {
	file, err := os.Open("/dev/r" + store)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	block := make([]byte, 4096)
	if _, err := io.ReadFull(file, block); err != nil {
		return 0, err
	}
	return macImagingSuperblockXID(block)
}

func macImagingSuperblockXID(block []byte) (uint64, error) {
	// obj_phys_t keeps o_xid at byte 16; nx_magic follows the object header.
	if len(block) < 36 || string(block[32:36]) != "NXSB" {
		return 0, errors.New("the Time Machine partition has no APFS container superblock")
	}
	return binary.LittleEndian.Uint64(block[16:24]), nil
}

func macImagingCheckUnmounted(ctx context.Context, media macBackupMedia) error {
	volume, err := macImagingDiskInfo(ctx, media.config.VolumeUUID)
	if err != nil || !strings.EqualFold(volume.VolumeUUID, media.config.VolumeUUID) || volume.MountPoint != "" {
		return errors.New("Time Machine archive volume is mounted or was removed")
	}
	store, err := macImagingDiskInfo(ctx, media.config.PartitionUUID)
	if err != nil || store.ParentWholeDisk != media.disk.DeviceIdentifier || !strings.EqualFold(store.DiskUUID, media.config.PartitionUUID) {
		return errors.New("Time Machine physical store changed during archival")
	}
	return nil
}

type macImagingArchive struct {
	file    *os.File
	reader  *io.SectionReader
	ctx     context.Context
	media   macBackupMedia
	remount func() error
	read    int64
	xid     uint64
}

func (archive *macImagingArchive) Read(p []byte) (int, error) {
	if err := archive.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := archive.reader.Read(p)
	archive.read += int64(n)
	if errors.Is(err, io.EOF) && archive.read < archive.media.disk.TotalSize {
		return n, fmt.Errorf("Time Machine disk ended before the expected archive size: %w", io.ErrUnexpectedEOF)
	}
	if n > 0 && archive.read == archive.media.disk.TotalSize {
		if check := macImagingCheckUnmounted(archive.ctx, archive.media); check != nil {
			return 0, check
		}
		// shortcut: only the superblock copy in block 0 is compared, which APFS can
		// update later than its checkpoint area; a mount, write and crash during the
		// read can go unseen. Compare the newest checkpoint superblock if that matters.
		if xid, err := macImagingContainerXID(archive.media.store); err != nil || xid != archive.xid {
			return 0, errors.New("the Time Machine disk was written during archival")
		}
	}
	return n, err
}

func (archive *macImagingArchive) Finish() error {
	return os.Remove(macImagingReceiptPath)
}

func (archive *macImagingArchive) Close() error {
	return errors.Join(archive.file.Close(), archive.remount())
}
