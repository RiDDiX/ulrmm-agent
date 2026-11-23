// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const linuxImagingMethod = "linux-offline-disk-v1"
const linuxImagingHelper = "/usr/lib/ulrmm/ulrmm_image_recovery.py"
const linuxDiskIDs = "/dev/disk/by-id"

var linuxDiskIDPattern = regexp.MustCompile(`^(ata|nvme|scsi|usb|virtio|wwn)-[A-Za-z0-9_.:+-]+$`)
var linuxUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var linuxImagingRequired = []string{"/", "/boot", "/boot/efi", "/efi"}

func linuxImagingHost() (ImagingCapability, bool, error) {
	capability := ImagingCapability{
		Method: linuxImagingMethod, Encryption: "unknown",
		Scope:    "Whole system disk, including the partition table, ext4 root, bootloader and EFI partition",
		Recovery: "Boot trusted ULRMM Linux recovery media. Restore on a blank disk of equal capacity and sector size, in the original UEFI mode. Mounts on other disks are not in the image; on other hardware attach those disks or mark their fstab entries nofail.",
	}
	if runtime.GOARCH != "amd64" {
		return capability, false, errors.New("Linux disk imaging requires x86-64")
	}
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		capability.BootMode = "bios"
		return capability, false, errors.New("Linux disk imaging requires UEFI")
	}
	capability.BootMode = "uefi"
	uuid, _ := os.ReadFile("/sys/class/dmi/id/product_uuid")
	capability.DeviceUUID = strings.ToLower(strings.TrimSpace(string(uuid)))
	if !linuxUUIDPattern.MatchString(capability.DeviceUUID) ||
		capability.DeviceUUID == "00000000-0000-0000-0000-000000000000" ||
		capability.DeviceUUID == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		return capability, false, errors.New("Linux disk imaging requires a valid DMI product UUID")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return capability, false, err
	}
	for _, argument := range strings.Fields(string(cmdline)) {
		if argument == "ulrmm.recovery=1" {
			return capability, true, nil
		}
	}
	return capability, false, nil
}

type linuxImagingBlock struct {
	Name       string
	Type       string
	FSType     string
	PartType   string
	PTType     string
	UUID       string
	PartUUID   string
	Label      string
	PartLabel  string
	Size       int64
	SectorSize int      `json:"log-sec"`
	Mounts     []string `json:"mountpoints"`
	Children   []linuxImagingBlock
}

func linuxImagingBlocks(ctx context.Context, paths ...string) ([]linuxImagingBlock, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"--json", "--bytes", "--paths", "--output", "NAME,TYPE,FSTYPE,PARTTYPE,PTTYPE,UUID,PARTUUID,LABEL,PARTLABEL,SIZE,LOG-SEC,MOUNTPOINTS"}
	output, err := exec.CommandContext(ctx, "lsblk", append(args, paths...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("inspect Linux disk layout: %w", err)
	}
	var data struct {
		BlockDevices []linuxImagingBlock
	}
	err = json.Unmarshal(output, &data)
	return data.BlockDevices, err
}

func linuxImagingLayout(disk linuxImagingBlock) error {
	if disk.Type != "disk" || disk.PTType != "gpt" || disk.FSType != "" {
		return errors.New("Linux imaging requires a whole GPT disk")
	}
	if disk.Size <= 0 || (disk.SectorSize != 512 && disk.SectorSize != 4096) || disk.Size%int64(disk.SectorSize) != 0 {
		return errors.New("Unsupported Linux disk geometry")
	}
	var root, esp bool
	for _, part := range disk.Children {
		if part.Type != "part" || len(part.Children) != 0 {
			return errors.New("LVM, LUKS, RAID and multi-device volumes require a different recovery method")
		}
		switch part.FSType {
		case "ext4":
			root = true
		case "vfat":
			esp = esp || part.PartType == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
		case "", "swap":
		default:
			return fmt.Errorf("Linux disk imaging does not support %s partitions", part.FSType)
		}
	}
	if !root || !esp {
		return errors.New("Linux imaging requires an ext4 root and a FAT EFI system partition")
	}
	return nil
}

func nativeImagingCapability(ctx context.Context) ImagingCapability {
	capability, recovery, err := linuxImagingHost()
	if err == nil && recovery {
		err = errors.New("Select the authorized source disk in the ULRMM recovery command")
	} else if err == nil {
		err = linuxRunningImagingInventory(ctx, &capability)
	}
	if err != nil {
		capability.Reason = err.Error()
	}
	return capability
}

func linuxRunningImagingInventory(ctx context.Context, capability *ImagingCapability) error {
	disks, err := linuxImagingBlocks(ctx)
	if err != nil {
		return err
	}
	var source *linuxImagingBlock
	var sourceRoot *linuxImagingBlock
	for i := range disks {
		disk := &disks[i]
		if root := linuxImagingRoot(disk); root != nil {
			if root.Type != "part" {
				if root.Type == "crypt" {
					capability.Encryption = "encrypted source"
				}
				if root.Type == "lvm" {
					return errors.New("Detected an LVM root. Capturing a coordinated LVM snapshot, EFI and boot volumes is unsupported.")
				}
				return fmt.Errorf("Linux root uses %s storage. The offline method requires a direct disk partition", root.Type)
			}
			if root.FSType == "btrfs" {
				return errors.New("The root supports Btrfs subvolume snapshots. ULRMM has no coordinated recovery method for this Btrfs root and its boot partitions.")
			}
			if root.FSType != "ext4" {
				return fmt.Errorf("The offline Linux method requires an ext4 root. This root uses %s", root.FSType)
			}
			if source != nil {
				return errors.New("Linux root is present on more than one disk")
			}
			source = disk
			sourceRoot = root
		}
	}
	if source == nil {
		return errors.New("No mounted Linux root could be associated with a local disk")
	}
	if err := linuxImagingLayout(*source); err != nil {
		return err
	}
	fstab, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return fmt.Errorf("read the source system's fstab: %w", err)
	}
	excluded, err := linuxImagingFstab(source.Children, sourceRoot.Name, string(fstab))
	if err != nil {
		return err
	}
	for _, disk := range disks {
		// A loop device holds a file whose own mount decides whether it is in the
		// image, and compressed RAM swap holds no disk.
		if disk.Name == source.Name || disk.Type == "loop" || strings.HasPrefix(disk.Name, "/dev/zram") {
			continue
		}
		if excluded, err = linuxImagingMounts(disk, excluded); err != nil {
			return err
		}
	}
	capability.Scope += linuxImagingNotIncluded(excluded)
	ids, err := os.ReadDir(linuxDiskIDs)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if !linuxDiskIDPattern.MatchString(id.Name()) {
			continue
		}
		path, err := filepath.EvalSymlinks(filepath.Join(linuxDiskIDs, id.Name()))
		if err == nil && path == source.Name {
			capability.SourceID, capability.Size, capability.SectorSize = id.Name(), source.Size, source.SectorSize
			capability.Encryption = "unencrypted source"
			if release, err := os.ReadFile("/etc/os-release"); err == nil {
				for _, line := range strings.Split(string(release), "\n") {
					if name, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
						capability.Scope = strings.Trim(name, "\"") + ". " + capability.Scope
						break
					}
				}
			}
			capability.Reason = "No supported whole-disk snapshot for this layout. Shut down Linux cleanly and boot ULRMM recovery media to capture the system disk."
			return nil
		}
	}
	return errors.New("The Linux system disk has no supported stable /dev/disk/by-id identifier")
}

// linuxImagingFstab returns the fstab mounts the system disk image does not hold.
func linuxImagingFstab(parts []linuxImagingBlock, root, fstab string) ([]string, error) {
	ids := make(map[string]linuxImagingBlock)
	for _, part := range parts {
		// Kernel names change on other hardware, so a system disk partition named that way is refused.
		ids[part.Name+"="] = linuxImagingBlock{}
		for prefix, value := range map[string]string{
			"UUID=": strings.ToLower(part.UUID), "PARTUUID=": strings.ToLower(part.PartUUID),
			"LABEL=": part.Label, "PARTLABEL=": part.PartLabel,
		} {
			if value == "" {
				continue
			}
			key := prefix + value
			if _, ok := ids[key]; ok {
				if strings.HasSuffix(prefix, "UUID=") {
					return nil, errors.New("Linux system disk has ambiguous partition identifiers")
				}
				// A label several partitions share is refused only where fstab uses it.
				ids[key] = linuxImagingBlock{}
				continue
			}
			ids[key] = part
		}
	}
	// a mount point a system disk partition holds right now is in the image,
	// whatever link fstab names it by
	system := make(map[string]bool)
	for _, part := range parts {
		for _, mount := range part.Mounts {
			system[mount] = true
		}
	}
	var excluded []string
	mounts := make(map[string]linuxImagingBlock)
	for _, line := range strings.Split(fstab, "\n") {
		entry, _, _ := strings.Cut(line, "#")
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 4 {
			return nil, errors.New("Linux system has an unsupported fstab entry")
		}
		switch fields[2] {
		case "proc", "sysfs", "devpts", "tmpfs":
			if fields[0] == fields[2] || fields[0] == "none" {
				continue
			}
		}
		// Boot skips noauto entries unless systemd automounts them, and a swap file
		// lives on a file system checked here.
		opts := strings.Split(fields[3], ",")
		if (slices.Contains(opts, "noauto") && !slices.Contains(opts, "x-systemd.automount")) ||
			(fields[2] == "swap" && strings.HasPrefix(fields[0], "/") && !strings.HasPrefix(fields[0], "/dev/")) {
			continue
		}
		// mount and systemd clean the path, so "/boot/" is /boot
		point := fields[1]
		if strings.HasPrefix(point, "/") {
			point = path.Clean(point)
		}
		required := slices.Contains(linuxImagingRequired, point)
		// bind mounts and pseudo file systems hold no disk of their own
		if !required && (slices.Contains(opts, "bind") || slices.Contains(opts, "rbind") ||
			!strings.ContainsAny(fields[0], "/=")) {
			continue
		}
		source := fields[0]
		if link, ok := strings.CutPrefix(source, "/dev/disk/by-"); ok {
			if kind, value, ok := strings.Cut(link, "/"); ok {
				source = strings.ToUpper(kind) + "=" + value
			}
		}
		prefix, value, _ := strings.Cut(source, "=")
		if strings.HasSuffix(prefix, "UUID") {
			value = strings.ToLower(value)
		}
		part, onDisk := ids[prefix+"="+value]
		if !onDisk && !required {
			if system[point] {
				continue
			}
			if fields[2] == "swap" {
				point = "swap"
			}
			excluded = linuxImagingExclude(excluded, point, fields[0])
			continue
		}
		if _, mounted := mounts[point]; part.Name == "" || mounted || part.FSType != fields[2] {
			return nil, fmt.Errorf("Linux fstab mount %s does not identify a supported partition on the system disk", point)
		}
		if fields[2] != "swap" {
			mounts[point] = part
		}
	}
	if mounts["/"].Name != root {
		return nil, errors.New("Linux fstab must identify the ext4 root partition")
	}
	if boot, ok := mounts["/boot"]; ok && boot.FSType != "ext4" {
		return nil, errors.New("A separate /boot must use ext4 on the Linux system disk")
	}
	efi, ok := mounts["/boot/efi"]
	if !ok {
		efi = mounts["/efi"]
	}
	if efi.FSType != "vfat" || efi.PartType != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {
		return nil, errors.New("Linux fstab must identify the FAT EFI system partition on the system disk")
	}
	return excluded, nil
}

func linuxImagingRoot(block *linuxImagingBlock) *linuxImagingBlock {
	for _, mount := range block.Mounts {
		if mount == "/" {
			return block
		}
	}
	for i := range block.Children {
		if root := linuxImagingRoot(&block.Children[i]); root != nil {
			return root
		}
	}
	return nil
}

// linuxImagingMounts adds the mounts of a disk other than the system disk to the excluded list.
func linuxImagingMounts(block linuxImagingBlock, excluded []string) ([]string, error) {
	for _, mount := range block.Mounts {
		if slices.Contains(linuxImagingRequired, mount) {
			return nil, fmt.Errorf("Linux mount %s is not on the system disk", mount)
		}
		if mount != "" {
			excluded = linuxImagingExclude(excluded, mount, block.Name)
		}
	}
	var err error
	for _, child := range block.Children {
		if excluded, err = linuxImagingMounts(child, excluded); err != nil {
			return nil, err
		}
	}
	return excluded, nil
}

func linuxImagingExclude(excluded []string, point, source string) []string {
	if point == "[SWAP]" {
		point = "swap"
	}
	if slices.ContainsFunc(excluded, func(entry string) bool { return strings.HasPrefix(entry, point+" (") }) {
		return excluded
	}
	return append(excluded, point+" ("+source+")")
}

func linuxImagingNotIncluded(excluded []string) string {
	if len(excluded) == 0 {
		return ""
	}
	// the server keeps at most 2048 characters of scope
	var shown []string
	length := 0
	for _, entry := range excluded {
		if runes := []rune(entry); len(runes) > 160 {
			entry = string(runes[:157]) + "..."
		}
		if len(shown) == 8 || length+len(entry) > 1200 {
			break
		}
		shown = append(shown, entry)
		length += len(entry) + 2
	}
	if more := len(excluded) - len(shown); more > 0 {
		shown = append(shown, fmt.Sprintf("and %d more", more))
	}
	return ". Not included: " + strings.Join(shown, ", ") + "."
}

func imagingRecoveryCapability(ctx context.Context, diskID string) (ImagingCapability, error) {
	capability, recovery, err := linuxImagingHost()
	if err != nil {
		return capability, err
	}
	if !recovery || os.Geteuid() != 0 {
		return capability, errors.New("capture requires a trusted recovery boot with ulrmm.recovery=1 and root access")
	}
	if !linuxDiskIDPattern.MatchString(diskID) {
		return capability, errors.New("select a whole disk by its stable /dev/disk/by-id name")
	}
	device, err := filepath.EvalSymlinks(filepath.Join(linuxDiskIDs, diskID))
	if err != nil {
		return capability, err
	}
	disks, err := linuxImagingBlocks(ctx, device)
	if err != nil {
		return capability, err
	}
	if len(disks) != 1 {
		return capability, errors.New("the selected Linux disk is ambiguous")
	}
	if err := linuxImagingLayout(disks[0]); err != nil {
		return capability, err
	}
	capability.SourceID, capability.Size, capability.SectorSize = diskID, disks[0].Size, disks[0].SectorSize
	capability.Encryption = "unencrypted source"
	return capability, nil
}

func nativeImagingCapture(ctx context.Context, expected ImagingCapability) (io.ReadCloser, error) {
	actual, err := imagingRecoveryCapability(ctx, expected.SourceID)
	if err != nil {
		return nil, err
	}
	if expected.Method != actual.Method || expected.DeviceUUID != actual.DeviceUUID || expected.BootMode != actual.BootMode ||
		expected.Size != actual.Size || expected.SectorSize != actual.SectorSize {
		return nil, errors.New("Linux source identity, firmware or disk geometry differs from the authorized capture")
	}
	link := filepath.Join(linuxDiskIDs, actual.SourceID)
	device, err := filepath.EvalSymlinks(link)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(device, os.O_RDONLY|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open Linux source disk exclusively: %w", err)
	}
	if err := verifyLinuxCapture(ctx, file, link, actual); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func verifyLinuxCapture(ctx context.Context, file *os.File, link string, actual ImagingCapability) error {
	var selected, opened unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
		return err
	}
	if err := unix.Stat(link, &selected); err != nil {
		return err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFBLK || opened.Rdev != selected.Rdev {
		return errors.New("selected Linux source changed while opening it")
	}
	sysfs := fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(opened.Rdev), unix.Minor(opened.Rdev))
	if _, err := os.Stat(filepath.Join(sysfs, "partition")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("selected Linux source is not a whole disk")
	}
	slaves, err := os.ReadDir(filepath.Join(sysfs, "slaves"))
	if err != nil || len(slaves) != 0 {
		return errors.New("selected Linux source is not a whole physical or virtual disk")
	}
	sectors, err := os.ReadFile(filepath.Join(sysfs, "size"))
	if err != nil || strings.TrimSpace(string(sectors)) != fmt.Sprint(actual.Size/512) {
		return errors.New("Linux source size changed while opening it")
	}
	sectorSize, err := unix.IoctlGetInt(int(file.Fd()), unix.BLKSSZGET)
	if err != nil || sectorSize != actual.SectorSize {
		return errors.New("Linux source sector size changed while opening it")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	verify := exec.CommandContext(ctx, "python3", "-I", linuxImagingHelper, "--check-capture-fd", "--disk-id", actual.SourceID)
	verify.ExtraFiles = []*os.File{file}
	if output, err := verify.CombinedOutput(); err != nil {
		return fmt.Errorf("offline Linux source validation failed: %s (%w)", strings.TrimSpace(string(output)), err)
	}
	return nil
}
