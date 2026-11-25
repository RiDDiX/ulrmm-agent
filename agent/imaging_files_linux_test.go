// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/unix"
)

// The owner's NVR: ESP and ext4 root on NVMe, recordings on a second disk, a CIFS share.
const frigateLsblk = `{"blockdevices": [
 {"name": "/dev/nvme0n1", "type": "disk", "pttype": "gpt", "ptuuid": "6F0F5A7E-3C2B-4D8E-9A51-0C6D1F2E3A4B", "size": 1000204886016, "log-sec": 512, "mountpoints": [null], "children": [
  {"name": "/dev/nvme0n1p1", "type": "part", "fstype": "vfat", "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "pttype": "gpt", "uuid": "ABCD-1234", "partuuid": "1C3E0000-0000-4000-8000-000000000001", "partlabel": "EFI System Partition", "size": 536870912, "log-sec": 512, "mountpoints": ["/boot/efi"], "start": 2048, "partn": 1, "partflags": null},
  {"name": "/dev/nvme0n1p2", "type": "part", "fstype": "ext4", "parttype": "0fc63daf-8483-4772-8e79-3d69d8477de4", "pttype": "gpt", "uuid": "0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f", "partuuid": "1C3E0000-0000-4000-8000-000000000002", "size": 999666221056, "log-sec": 512, "mountpoints": ["/"], "start": 1050624, "partn": 2}
 ]},
 {"name": "/dev/sda", "type": "disk", "pttype": "gpt", "size": 4000787030016, "log-sec": 512, "mountpoints": [null], "children": [
  {"name": "/dev/sda1", "type": "part", "fstype": "ext4", "uuid": "5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a", "label": "frigate", "size": 4000785960960, "log-sec": 512, "mountpoints": ["/media/frigate"], "start": 2048, "partn": 1}
 ]}
]}`

const frigateMountinfo = `24 1 0:22 / /sys rw,nosuid,nodev shared:6 - sysfs sysfs rw
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro
30 22 259:1 / /boot/efi rw,relatime shared:2 - vfat /dev/nvme0n1p1 rw,fmask=0077
31 22 8:1 / /media/frigate rw,relatime shared:3 - ext4 /dev/sda1 rw
32 22 0:50 / /mnt/backups rw,relatime shared:4 - cifs //nas/backups rw,vers=3.1.1
33 22 0:51 / /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw,lowerdir=/x
34 22 0:25 / /tmp rw,nosuid shared:5 - tmpfs tmpfs rw
`

const frigateFstab = `UUID=0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f / ext4 errors=remount-ro 0 1
UUID=ABCD-1234 /boot/efi vfat umask=0077 0 1
UUID=5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a /media/frigate ext4 defaults,nofail 0 2
//nas/backups /mnt/backups cifs credentials=/root/.smb 0 0
`

// The capability every lane uses (contract section 10).
const frigateCapability = `{
  "method": "linux-files-v1", "ready": true,
  "scope": "Debian GNU/Linux 13 (trixie). Live file backup of the system disk file systems: /, /boot/efi.",
  "recovery": "Boot ULRMM Linux recovery media in UEFI mode and restore onto a blank disk with the same logical sector size that holds the recorded partitions. Extra volumes are not part of the disk restore. Keep the original disk detached: the restored disk carries the same UUIDs.",
  "reason": "Ready for a live backup.", "encryption": "unencrypted source",
  "source_id": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456",
  "device_uuid": "90cb53c8-01ea-444d-b1f1-23abcd127ace", "boot_mode": "uefi",
  "size": 1000204886016, "sector_size": 512, "min_target_size": 1000204157440,
  "volumes": [
    {"id": "0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f", "mount": "/", "fs": "ext4", "kind": "system", "disk": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456", "size": 999666221056, "used": 41231686041, "consistency": "live", "reason": ""},
    {"id": "abcd-1234", "mount": "/boot/efi", "fs": "vfat", "kind": "system", "disk": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456", "size": 536870912, "used": 6291456, "consistency": "live", "reason": ""},
    {"id": "5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a", "mount": "/media/frigate", "fs": "ext4", "kind": "extra", "disk": "ata-WDC_WD40PURZ-85AKKY0_WD-WX12345678", "size": 4000785960960, "used": 2899102924800, "consistency": "live", "reason": ""},
    {"id": "", "mount": "/mnt/backups", "fs": "cifs", "kind": "network", "disk": "", "size": 0, "used": 0, "consistency": "", "reason": "Network storage is not backed up."}
  ]
}`

func frigateHost(t *testing.T) linuxFilesHost {
	t.Helper()
	var data struct{ BlockDevices []linuxImagingBlock }
	if err := json.Unmarshal([]byte(frigateLsblk), &data); err != nil {
		t.Fatal(err)
	}
	used := map[string]int64{"/": 41231686041, "/boot/efi": 6291456, "/media/frigate": 2899102924800}
	return linuxFilesHost{
		Disks: data.BlockDevices, MountInfo: frigateMountinfo, Fstab: frigateFstab,
		OSRelease: "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n",
		DiskIDs: map[string]string{
			"/dev/nvme0n1": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456", "/dev/nvme0n1p1": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456-part1",
			"/dev/sda": "ata-WDC_WD40PURZ-85AKKY0_WD-WX12345678",
		},
		UEFI: true, DMI: "90CB53C8-01EA-444D-B1F1-23ABCD127ACE\n", Arch: "amd64",
		Probe: func(device string) map[string]string {
			if device == "/dev/nvme0n1p1" {
				return map[string]string{"VERSION": "FAT32", "TYPE": "vfat"}
			}
			return map[string]string{}
		},
		Used: func(mount string) int64 { return used[mount] },
	}
}

func frigateWant(t *testing.T) ImagingCapability {
	t.Helper()
	var want ImagingCapability
	if err := json.Unmarshal([]byte(frigateCapability), &want); err != nil {
		t.Fatal(err)
	}
	return want
}

func TestLinuxFilesInventoryFrigate(t *testing.T) {
	got := linuxFilesInventory(frigateHost(t)).ImagingCapability
	if want := frigateWant(t); !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", " ")
		t.Fatalf("capability differs from the shared fixture:\n%s", g)
	}

	h := frigateHost(t)
	var more struct{ BlockDevices []linuxImagingBlock }
	if err := json.Unmarshal([]byte(`{"blockdevices": [
	 {"name": "/dev/loop0", "type": "loop", "fstype": "squashfs", "size": 1, "mountpoints": ["/snap/core/1"]},
	 {"name": "/dev/zram0", "type": "disk", "fstype": "ext4", "uuid": "77777777-0000-4000-8000-000000000000", "size": 1, "mountpoints": ["/var/log"]},
	 {"name": "/dev/sdb", "type": "disk", "children": [{"name": "/dev/sdb1", "type": "part", "fstype": "ext4", "uuid": "dddddddd-0000-4000-8000-000000000001", "size": 5, "mountpoints": ["/media/clone"]}]},
	 {"name": "/dev/sdc", "type": "disk", "children": [{"name": "/dev/sdc1", "type": "part", "fstype": "ext4", "uuid": "dddddddd-0000-4000-8000-000000000001", "size": 5, "mountpoints": [null]}]},
	 {"name": "/dev/sdd", "type": "disk", "children": [{"name": "/dev/sdd1", "type": "part", "fstype": "vfat", "uuid": "1234-ABCD", "size": 5, "mountpoints": ["/media/usb"]}]},
	 {"name": "/dev/sde", "type": "disk", "children": [{"name": "/dev/sde1", "type": "part", "fstype": "LVM2_member", "children": [
	   {"name": "/dev/mapper/data-lv", "type": "lvm", "fstype": "ext4", "uuid": "eeeeeeee-0000-4000-8000-000000000001", "size": 5, "mountpoints": ["/srv/data"]}]}]},
	 {"name": "/dev/sdf", "type": "disk", "children": [{"name": "/dev/sdf1", "type": "part", "fstype": "xfs", "size": 5, "mountpoints": ["/media/nouuid"]}]}
	]}`), &more); err != nil {
		t.Fatal(err)
	}
	h.Disks = append(h.Disks, more.BlockDevices...)
	h.Disks[1].Children[0].Mounts = append(h.Disks[1].Children[0].Mounts, "/srv/recordings")
	h.MountInfo += `35 22 7:0 / /snap/core/1 ro - squashfs /dev/loop0 ro
36 22 251:0 / /var/log rw - ext4 /dev/zram0 rw
37 22 8:17 / /media/clone rw - ext4 /dev/sdb1 rw
38 22 8:1 /recordings /srv/recordings rw - ext4 /dev/sda1 rw
39 22 8:49 / /media/usb rw - vfat /dev/sdd1 rw
40 22 253:0 / /srv/data rw - ext4 /dev/mapper/data-lv rw
41 22 8:81 / /media/nouuid rw - xfs /dev/sdf1 rw
42 22 0:52 / /mnt/my\040share rw - nfs4 nas:/x rw
43 22 0:53 / /mnt/ssh rw - fuse.sshfs host:/ rw
`
	h.Fstab += "UUID=11111111-2222-4333-8444-555555555555 /mnt/old ext4 defaults,nofail 0 2\n" +
		"LABEL=gone /mnt/gone xfs defaults,nofail 0 2\n" +
		"UUID=DDDDDDDD-0000-4000-8000-000000000001 /mnt/clone2 ext4 noauto 0 0\n" +
		"/dev/sdd1 /mnt/stick vfat noauto 0 0\n"
	plan := linuxFilesInventory(h)
	var rows []string
	for _, v := range plan.Volumes {
		rows = append(rows, strings.Join([]string{v.Mount, v.Kind, v.ID, v.Reason}, "|"))
	}
	want := []string{
		"/|system|0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f|",
		"/boot/efi|system|abcd-1234|",
		"/media/clone|unsupported|dddddddd-0000-4000-8000-000000000001|Another disk carries the same file system UUID.",
		"/media/frigate|extra|5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a|",
		"/media/nouuid|unsupported||The file system has no UUID.",
		"/media/usb|unsupported|1234-abcd|vfat volumes are not supported for live backup.",
		"/mnt/backups|network||Network storage is not backed up.",
		"/mnt/gone|unmounted|fstab:/mnt/gone|Not mounted.",
		"/mnt/my share|network||Network storage is not backed up.",
		"/mnt/old|unmounted|11111111-2222-4333-8444-555555555555|Not mounted.",
		"/mnt/ssh|network||Network storage is not backed up.",
		"/srv/data|unsupported|eeeeeeee-0000-4000-8000-000000000001|Volumes on LVM, RAID or encryption are not supported yet.",
	}
	if !plan.Ready || !reflect.DeepEqual(rows, want) {
		t.Fatalf("ready %v (%s), volumes:\n%s", plan.Ready, plan.Reason, strings.Join(rows, "\n"))
	}
	if plan.Scope != frigateWant(t).Scope || plan.MinTargetSize != 1000204157440 {
		t.Fatalf("scope %q, min target %d", plan.Scope, plan.MinTargetSize)
	}

	h = frigateHost(t)
	for i := range 70 {
		h.MountInfo += fmt.Sprintf("%d 22 0:9%d / /mnt/share%02d rw - cifs //nas/s%d rw\n", 100+i, i, i, i)
	}
	if plan := linuxFilesInventory(h); len(plan.Volumes) != 64 || plan.Volumes[0].Mount != "/" || plan.Volumes[1].Mount != "/boot/efi" {
		t.Fatalf("%d volumes, first %+v", len(plan.Volumes), plan.Volumes[:2])
	}

	// x-systemd.automount: an autofs line, and the file system on top once it is used
	plain := "31 22 8:1 / /media/frigate rw,relatime shared:3 - ext4 /dev/sda1 rw\n"
	automount := "31 22 0:45 / /media/frigate rw,relatime shared:3 - autofs systemd-1 rw,fd=52,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=2211\n"
	for _, tc := range []struct{ name, lines, kind string }{
		{"plain mount", plain, "extra"},
		{"triggered automount", automount + strings.Replace(plain, "31 22", "61 31", 1), "extra"},
		{"idle automount", automount, "unmounted"},
	} {
		h := frigateHost(t)
		h.MountInfo = strings.Replace(h.MountInfo, plain, tc.lines, 1)
		h.Fstab = strings.Replace(h.Fstab, "defaults,nofail", "defaults,nofail,x-systemd.automount", 1)
		if tc.kind == "unmounted" {
			h.Disks[1].Children[0].Mounts = nil
		}
		plan := linuxFilesInventory(h)
		i := slices.IndexFunc(plan.Volumes, func(v ImagingVolume) bool { return v.Mount == "/media/frigate" })
		if !plan.Ready || i < 0 || plan.Volumes[i].Kind != tc.kind || plan.Volumes[i].ID != "5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a" ||
			(tc.kind == "extra" && !reflect.DeepEqual(plan.ImagingCapability, frigateWant(t))) {
			t.Errorf("%s: ready %v (%s), volumes %+v", tc.name, plan.Ready, plan.Reason, plan.Volumes)
		}
	}
}

func TestLinuxFilesSysfs(t *testing.T) {
	// the columns lsblk of util-linux 2.37.2 (ubuntu 22.04) and 2.38.1 (debian 12) accept
	for _, column := range strings.Split(linuxFilesColumns, ",")[1:] {
		if column != "PTUUID" && column != "PARTFLAGS" {
			t.Fatalf("old lsblk refuses the column %s", column)
		}
	}
	dir := t.TempDir()
	for name, values := range map[string][2]string{"nvme0n1p1": {"2048", "1"}, "nvme0n1p2": {"1050624", "2"}, "sda1": {"2048", "1"}} {
		os.Mkdir(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "start"), []byte(values[0]+"\n"), 0o444)
		os.WriteFile(filepath.Join(dir, name, "partition"), []byte(values[1]+"\n"), 0o444)
	}
	// what lsblk without START and PARTN gives, filled from sysfs
	host := func() linuxFilesHost {
		h := frigateHost(t)
		for i := range h.Disks {
			for j := range h.Disks[i].Children {
				h.Disks[i].Children[j].Start, h.Disks[i].Children[j].PartN = 0, 0
			}
		}
		linuxFilesSysfs(dir, h.Disks)
		return h
	}
	if got := host(); !reflect.DeepEqual(got.Disks, frigateHost(t).Disks) {
		t.Fatalf("disks %+v", got.Disks)
	}
	os.RemoveAll(filepath.Join(dir, "nvme0n1p2"))
	if plan := linuxFilesInventory(host()); plan.Ready || plan.Reason != "Could not read the start and number of /dev/nvme0n1p2." {
		t.Fatalf("ready %v (%s)", plan.Ready, plan.Reason)
	}
}

func TestLinuxFilesNotReady(t *testing.T) {
	const gpt = "Live Linux backup needs an ext4 root on a GPT partition. This root uses "
	for _, tc := range []struct {
		name, reason string
		change       func(*linuxFilesHost)
	}{
		{"bios", "Live Linux backup requires UEFI.", func(h *linuxFilesHost) { h.UEFI = false }},
		{"pi", "Live Linux backup requires a valid DMI product UUID.", func(h *linuxFilesHost) { h.DMI = "" }},
		{"i386", "Live Linux backup requires x86-64 or arm64.", func(h *linuxFilesHost) { h.Arch = "386" }},
		{"lvm root", gpt + "LVM.", func(h *linuxFilesHost) {
			h.Disks[0].Children[1] = linuxImagingBlock{Name: "/dev/nvme0n1p2", Type: "part", FSType: "LVM2_member", Children: []linuxImagingBlock{
				{Name: "/dev/mapper/vg-root", Type: "lvm", FSType: "ext4", UUID: "0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f", Mounts: []string{"/"}}}}
		}},
		{"btrfs root", gpt + "btrfs.", func(h *linuxFilesHost) { h.Disks[0].Children[1].FSType = "btrfs" }},
		{"mbr", gpt + "a dos partition table.", func(h *linuxFilesHost) { h.Disks[0].PTType = "dos" }},
		{"unmounted ext4", "/dev/nvme0n1p3 on the system disk is not mounted.", func(h *linuxFilesHost) {
			h.Disks[0].Children = append(h.Disks[0].Children, linuxImagingBlock{Name: "/dev/nvme0n1p3", Type: "part", FSType: "ext4", UUID: "33333333-0000-4000-8000-000000000000"})
		}},
		{"xfs on system disk", "/dev/nvme0n1p3 on the system disk holds xfs, which live backup does not support.", func(h *linuxFilesHost) {
			h.Disks[0].Children = append(h.Disks[0].Children, linuxImagingBlock{Name: "/dev/nvme0n1p3", Type: "part", FSType: "xfs"})
		}},
		{"boot elsewhere", "System volumes span more than one disk.", func(h *linuxFilesHost) {
			h.Disks[1].Children[0].Mounts = []string{"/boot"}
			h.MountInfo += "50 22 8:1 / /boot rw - ext4 /dev/sda1 rw\n"
		}},
		{"no by-id", "The Linux system disk has no supported stable /dev/disk/by-id identifier", func(h *linuxFilesHost) { delete(h.DiskIDs, "/dev/nvme0n1") }},
		{"fat type", "Could not read the FAT type of the EFI system partition.", func(h *linuxFilesHost) {
			h.Probe = func(string) map[string]string { return map[string]string{} }
		}},
		{"cloned esp", "Another disk carries the same UUID as a system volume.", func(h *linuxFilesHost) {
			h.Disks[1].Children = append(h.Disks[1].Children, linuxImagingBlock{Name: "/dev/sda2", Type: "part", FSType: "vfat", UUID: "ABCD-1234"})
		}},
	} {
		h := frigateHost(t)
		tc.change(&h)
		plan := linuxFilesInventory(h)
		if plan.Ready || plan.Reason != tc.reason || plan.Method != linuxFilesMethod || plan.MinTargetSize != 0 {
			t.Errorf("%s: ready %v, reason %q", tc.name, plan.Ready, plan.Reason)
		}
	}
	h := frigateHost(t)
	h.Arch = "arm64"
	if plan := linuxFilesInventory(h); !plan.Ready || !strings.HasSuffix(plan.Recovery, " Disk restore of arm64 points needs arm64 recovery media, which is not available yet.") {
		t.Fatalf("arm64: %v %q", plan.Ready, plan.Recovery)
	}

	live := ImagingCapability{Method: linuxFilesMethod, Reason: gpt + "LVM."}
	offline := ImagingCapability{Method: linuxImagingMethod, Reason: "No supported whole-disk snapshot for this layout."}
	if got := linuxFilesChoice(live, offline, nil); got.Method != linuxImagingMethod || got.Reason != "Live backup unavailable: "+gpt+"LVM. No supported whole-disk snapshot for this layout." {
		t.Fatalf("fallback: %+v", got)
	}
	if got := linuxFilesChoice(live, offline, errors.New("Linux disk imaging requires x86-64")); got.Method != linuxFilesMethod || got.Reason != live.Reason {
		t.Fatalf("no offline fallback: %+v", got)
	}
}

func TestLinuxFilesPreflight(t *testing.T) {
	approved := frigateWant(t)
	approved.Include = []string{"0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f", "abcd-1234", "5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a"}
	volumes, err := linuxFilesPreflight(approved, linuxFilesInventory(frigateHost(t)))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, v := range volumes {
		keys = append(keys, v.key+"="+v.node.Name)
	}
	if want := []string{"root=/dev/nvme0n1p2", "esp=/dev/nvme0n1p1", "x-5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a=/dev/sda1"}; !reflect.DeepEqual(keys, want) {
		t.Fatal(keys)
	}
	moved := frigateHost(t)
	moved.Disks[1].Children[0].Mounts = []string{"/media/other"}
	moved.MountInfo = strings.Replace(moved.MountInfo, " /media/frigate ", " /media/other ", 1)
	gone := frigateHost(t)
	gone.Disks[1].Children[0].Mounts = nil
	gone.MountInfo = strings.Replace(gone.MountInfo, "/media/frigate", "/media/elsewhere-tmpfs", 1)
	for _, h := range []linuxFilesHost{moved, gone} {
		if _, err := linuxFilesPreflight(approved, linuxFilesInventory(h)); err == nil || err.Error() != "Selected volume /media/frigate is not mounted." {
			t.Fatalf("pinned volume away: %v", err)
		}
	}
	changed := approved
	changed.Scope += " "
	if _, err := linuxFilesPreflight(changed, linuxFilesInventory(frigateHost(t))); err == nil || err.Error() != "The backup source changed." {
		t.Fatal(err)
	}
	changed = approved
	changed.Include = approved.Include[:1]
	if _, err := linuxFilesPreflight(changed, linuxFilesInventory(frigateHost(t))); err == nil || err.Error() != "The backup source changed." {
		t.Fatal("captured without every system volume")
	}
}

func TestLinuxEFILoadOption(t *testing.T) {
	ucs := func(s string) []byte {
		var b []byte
		for _, c := range utf16.Encode([]rune(s + "\x00")) {
			b = binary.LittleEndian.AppendUint16(b, c)
		}
		return b
	}
	file := ucs(`\EFI\debian\shimx64.efi`)
	path := append([]byte{4, 1, 42, 0}, make([]byte, 38)...)
	path = append(append(path, 4, 4, byte(4+len(file)), 0), file...)
	path = append(path, 0x7f, 0xff, 4, 0)
	option := binary.LittleEndian.AppendUint32([]byte{7, 0, 0, 0}, 1)
	option = binary.LittleEndian.AppendUint16(option, uint16(len(path)))
	option = append(append(option, ucs("debian")...), path...)
	if got := linuxEFILoadOption(option); got == nil || got.Loader != `\EFI\debian\shimx64.efi` || got.Label != "debian" {
		t.Fatalf("%+v", got)
	}
	if linuxEFILoadOption(option[:len(option)-10]) != nil {
		t.Fatal("parsed a cut load option")
	}
}

type linuxFilesMember struct {
	header *tar.Header
	data   []byte
}

func writeLinuxFilesTree(t *testing.T, dir string) ([]byte, linuxFilesTrailer) {
	t.Helper()
	var out bytes.Buffer
	trailer, err := writeLinuxFiles(&out, []byte(`{"format":1}`), []linuxFilesView{{"root", dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), trailer
}

func readLinuxFiles(t *testing.T, stream []byte) ([]linuxFilesMember, []linuxFilesEntry) {
	t.Helper()
	var members []linuxFilesMember
	reader := tar.NewReader(bytes.NewReader(stream))
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, linuxFilesMember{h, data})
	}
	last := members[len(members)-2]
	if last.header.Name != ".ulrmm/index.jsonl.gz" {
		t.Fatalf("member before the report is %s", last.header.Name)
	}
	z, err := gzip.NewReader(bytes.NewReader(last.data))
	if err != nil {
		t.Fatal(err)
	}
	var lines []linuxFilesEntry
	for decoder := json.NewDecoder(z); decoder.More(); {
		var e linuxFilesEntry
		if err := decoder.Decode(&e); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, e)
	}
	return members, lines
}

func linuxBlockDigests(stream []byte) []string {
	var out []string
	for i := 0; i < len(stream); i += imagingBlock {
		end := i + imagingBlock
		if end > len(stream) {
			end = len(stream)
		}
		out = append(out, fmt.Sprintf("%x", sha256.Sum256(stream[i:end])))
	}
	return out
}

func TestLinuxFilesStreamDeterministic(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, 3<<20)
	rand.New(rand.NewSource(1)).Read(big)
	for name, data := range map[string][]byte{"a/x.txt": []byte("first"), "big.bin": big, "dir/c.txt": []byte("inner"), "z.txt": []byte("last")} {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := writeLinuxFilesTree(t, dir)
	second, _ := writeLinuxFilesTree(t, dir)
	if !reflect.DeepEqual(linuxBlockDigests(first), linuxBlockDigests(second)) {
		t.Fatal("the same tree gave other blocks")
	}
	// inside a/, so the volume root keeps its mtime
	if err := os.WriteFile(filepath.Join(dir, "a/0added"), []byte("a new small file"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, _ := writeLinuxFilesTree(t, dir)
	_, lines := readLinuxFiles(t, third)
	var data int64 = -1
	for _, e := range lines {
		if e.Path == "v/root/big.bin" {
			data = e.Data
		}
	}
	before, after := linuxBlockDigests(first), linuxBlockDigests(third)
	i := data / imagingBlock
	if data%imagingBlock != 0 || i < 2 || len(before) != len(after) {
		t.Fatalf("big.bin data at %d, %d and %d blocks", data, len(before), len(after))
	}
	// The anchored volume root keeps the layout block, the aligned file keeps
	// its own; only the block between them changes.
	if before[0] != after[0] || before[i-1] == after[i-1] || before[i] != after[i] {
		t.Fatal("a small file changed blocks outside its anchor span")
	}
}

func TestLinuxFilesStreamMembers(t *testing.T) {
	dir := t.TempDir()
	join := func(name string) string { return filepath.Join(dir, name) }
	if err := os.WriteFile(join("file"), []byte("content"), 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1700000000, 123456789)
	if err := os.Chtimes(join("file"), mtime, mtime); err != nil {
		t.Fatal(err)
	}
	root := os.Geteuid() == 0
	if root {
		if err := os.Chown(join("file"), 1234, 5678); err != nil {
			t.Fatal(err)
		}
	}
	xattr := "\x00\xffbin"
	hasXattr := unix.Setxattr(join("file"), "user.bin", []byte(xattr), 0) == nil
	if err := os.Link(join("file"), join("hard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", join("link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(join("fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", join("sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(join("bad\xff"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sparse, err := os.Create(join("sparse"))
	if err != nil {
		t.Fatal(err)
	}
	sparse.Truncate(3 << 20)
	sparse.WriteAt([]byte("tail"), 3<<20-4)
	sparse.Close()
	os.Mkdir(join("sub"), 0o750)
	os.WriteFile(join("sub/inner"), nil, 0o600)

	stream, trailer := writeLinuxFilesTree(t, dir)
	members, lines := readLinuxFiles(t, stream)
	var names []string
	byName := map[string]linuxFilesMember{}
	for _, m := range members {
		names = append(names, m.header.Name)
		byName[m.header.Name] = m
	}
	want := []string{".ulrmm/layout.json", "v/root/", "v/root/bad\xff", "v/root/fifo", "v/root/file", "v/root/hard", "v/root/link",
		"v/root/sparse", "v/root/sub/", "v/root/sub/inner", ".ulrmm/index.jsonl.gz", ".ulrmm/report.json"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("members %q", names)
	}
	file := byName["v/root/file"].header
	if !file.ModTime.Equal(mtime) || string(byName["v/root/file"].data) != "content" || file.Mode != 0o640 || file.Uname != "" {
		t.Fatalf("file header %+v", file)
	}
	if root && (file.Uid != 1234 || file.Gid != 5678) {
		t.Fatalf("ids %d:%d", file.Uid, file.Gid)
	}
	if hasXattr && file.PAXRecords["SCHILY.xattr.user.bin"] != xattr {
		t.Fatalf("xattr %q", file.PAXRecords["SCHILY.xattr.user.bin"])
	}
	if h := byName["v/root/hard"].header; h.Typeflag != tar.TypeLink || h.Linkname != "v/root/file" {
		t.Fatalf("hard link %+v", h)
	}
	if h := byName["v/root/link"].header; h.Typeflag != tar.TypeSymlink || h.Linkname != "file" {
		t.Fatalf("symlink %+v", h)
	}
	if byName["v/root/fifo"].header.Typeflag != tar.TypeFifo {
		t.Fatal("fifo")
	}
	if data := byName["v/root/sparse"].data; len(data) != 3<<20 || !bytes.Equal(data, append(make([]byte, 3<<20-4), "tail"...)) {
		t.Fatal("sparse file content")
	}
	if len(lines) != len(want)-3 {
		t.Fatalf("%d index lines", len(lines))
	}
	for _, e := range lines {
		name := e.Path
		if e.PathB64 != "" {
			raw, _ := base64.StdEncoding.DecodeString(e.PathB64)
			name = string(raw)
			if e.Path != "" || name != "v/root/bad\xff" {
				t.Fatalf("index name %+v", e)
			}
		}
		h, err := tar.NewReader(bytes.NewReader(stream[e.Offset:])).Next()
		if err != nil || h.Name != name {
			t.Fatalf("offset of %q holds %v (%v)", name, h, err)
		}
		if e.Type == "file" && hex.EncodeToString(sha256Of(stream[e.Data:e.Data+e.Size])) != e.SHA256 {
			t.Fatalf("data of %q", name)
		}
	}
	var report struct {
		linuxFilesCounts
		Format       int
		SkippedPaths []linuxFilesSkip `json:"skipped_paths"`
	}
	if err := json.Unmarshal(byName[".ulrmm/report.json"].data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Format != 1 || report.Entries != int64(len(lines)) || report.Skipped != 1 || report.linuxFilesCounts != trailer.Report ||
		!reflect.DeepEqual(report.SkippedPaths, []linuxFilesSkip{{"v/root/sock", "socket"}}) || report.Padding <= 0 {
		t.Fatalf("report %+v, trailer %+v", report, trailer.Report)
	}
	index := byName[".ulrmm/index.jsonl.gz"].data
	if trailer.Index.Size != int64(len(index)) || !bytes.Equal(stream[trailer.Index.Offset:trailer.Index.Offset+trailer.Index.Size], index) {
		t.Fatal("trailer does not locate the index")
	}
}

func sha256Of(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func TestLinuxFilesReappendsChangedLargeFile(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "big")
	if err := os.WriteFile(name, bytes.Repeat([]byte{'b'}, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, always := range []bool{false, true} {
		calls := 0
		linuxFilesReadHook = func(member string) {
			if member == "v/root/big" && (always || calls == 0) {
				calls++
				f, _ := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
				f.Write([]byte("more"))
				f.Close()
			}
		}
		stream, trailer := writeLinuxFilesTree(t, dir)
		linuxFilesReadHook = nil
		members, lines := readLinuxFiles(t, stream)
		var copies [][]byte
		for _, m := range members {
			if m.header.Name == "v/root/big" {
				copies = append(copies, m.data)
			}
		}
		var flags []bool
		for _, e := range lines {
			if e.Path == "v/root/big" {
				flags = append(flags, e.Changed)
			}
		}
		info, _ := os.Stat(name)
		if len(copies) != 2 || int64(len(copies[1])) != info.Size()-int64(4*calls-4) || len(copies[0]) >= len(copies[1]) ||
			!reflect.DeepEqual(flags, []bool{true, always}) || trailer.Report.Reappended != 1 || trailer.Report.Changed != map[bool]int64{false: 0, true: 1}[always] {
			t.Fatalf("always %v: %d copies, flags %v, report %+v", always, len(copies), flags, trailer.Report)
		}
	}
}

func TestLinuxFilesAnchors(t *testing.T) {
	dir := t.TempDir()
	anchor := ""
	for i := 0; anchor == ""; i++ {
		if sum := sha256.Sum256([]byte(fmt.Sprintf("v/root/n%d", i))); sum[0] == 0 {
			anchor = fmt.Sprintf("n%d", i)
		}
	}
	for _, name := range []string{"a", anchor, "zz"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stream, _ := writeLinuxFilesTree(t, dir)
	_, lines := readLinuxFiles(t, stream)
	aligned := map[string]bool{}
	for _, e := range lines {
		aligned[e.Path] = e.Data%imagingBlock == 0
	}
	if !aligned["v/root/"] || !aligned["v/root/"+anchor] || aligned["v/root/a"] || aligned["v/root/zz"] {
		t.Fatalf("aligned members %v", aligned)
	}
}

func TestLinuxFilesWalkErrors(t *testing.T) {
	w := &linuxFilesWriter{}
	for _, tc := range []struct {
		err        error
		dir, fails bool
	}{
		{unix.ENOENT, true, false}, {unix.ENOTDIR, true, false}, {unix.EIO, true, true}, {unix.EUCLEAN, true, true},
		{unix.EIO, false, false}, {unix.ENOMEM, false, true}, {unix.EMFILE, false, true}, {unix.ENFILE, false, true},
		{unix.ELOOP, true, false},
	} {
		if err := w.missing("v/root/x", tc.err, tc.dir); (err != nil) != tc.fails || (err != nil && !errors.Is(err, tc.err)) {
			t.Errorf("%v, directory %v: %v", tc.err, tc.dir, err)
		}
	}
	if w.counts.Vanished != 3 || w.counts.Skipped != 1 {
		t.Fatalf("counts %+v", w.counts)
	}
	// an xattr that grows, or goes away, while it is read is read again
	for _, race := range []error{unix.ERANGE, unix.ENODATA} {
		raced := false
		list := func(b []byte) (int, error) {
			if b == nil {
				return len("user.a\x00"), nil
			}
			return copy(b, "user.a\x00"), nil
		}
		get := func(_ string, b []byte) (int, error) {
			switch {
			case b == nil:
				return 1, nil
			case !raced:
				raced = true
				return 0, race
			}
			return copy(b, "v"), nil
		}
		if got, err := linuxXattrs(list, get); err != nil || got["SCHILY.xattr.user.a"] != "v" {
			t.Fatalf("%v: %v %v", race, got, err)
		}
	}

	// a directory the walk cannot open fails it instead of counting a skip
	dir := t.TempDir()
	deep := dir
	for range 64 {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	writeLinuxFilesTree(t, dir)
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	// a descriptor far above the others, as a connection left by another test
	null, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup3(null, 900, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	unix.Close(null)
	defer unix.Close(900)
	// new descriptors take the lowest free numbers, so the limit counts the open ones
	fds, _ := os.ReadDir("/proc/self/fd")
	low := limit
	low.Cur = uint64(len(fds) + 4)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &low); err != nil {
		t.Fatal(err)
	}
	_, err = writeLinuxFiles(io.Discard, []byte(`{}`), []linuxFilesView{{"root", dir}}, nil)
	unix.Setrlimit(unix.RLIMIT_NOFILE, &limit)
	if !errors.Is(err, unix.EMFILE) || !strings.HasPrefix(err.Error(), "read v/root/d/d/") {
		t.Fatalf("walk without file descriptors: %v", err)
	}
}

func TestImagingStreamFailureNeverSeals(t *testing.T) {
	var mu sync.Mutex
	var seals []map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/part/" && r.Method == "POST":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/seal/":
			var seal map[string]any
			json.NewDecoder(r.Body).Decode(&seal)
			seals = append(seals, seal)
			w.WriteHeader(http.StatusAccepted)
		default:
			// read the block like the server does; the client reuses its buffer
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	tr := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test", Mode: "internet", Image: "point"}, client: server.Client()}
	m := imagingManifest{Image: "point", Agent: "agent", Disk: "disk", Direction: "capture", Mode: "internet", Codec: "none", Native: ImagingCapability{Method: linuxFilesMethod}}
	run := func(script string) error {
		views := filepath.Join(t.TempDir(), "point")
		os.MkdirAll(filepath.Join(views, "root"), 0o700)
		s, err := startImagingStream(exec.Command("sh", "-c", script), []byte(`{}`), views)
		if err != nil {
			t.Fatal(err)
		}
		err = tr.upload(context.Background(), m, s)
		s.Close()
		if _, e := os.Stat(views); !os.IsNotExist(e) {
			t.Errorf("views left behind: %v", e)
		}
		return err
	}
	var failed *imagingStreamError
	if err := run("head -c 3000000 /dev/zero; echo walk broke >&2; exit 1"); !errors.As(err, &failed) || err.Error() != "imaging stream failed: walk broke" {
		t.Fatalf("failed child: %v", err)
	}
	if err := run("printf abc"); !errors.As(err, &failed) {
		t.Fatalf("child without trailer: %v", err)
	}
	mu.Lock()
	if len(seals) != 0 {
		t.Fatalf("sealed a failed stream: %v", seals)
	}
	mu.Unlock()
	if err := run(`printf abc; printf '{"index":{"offset":1,"size":2},"report":{"entries":1}}' >&3`); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	index, _ := seals[0]["index"].(map[string]any)
	if len(seals) != 1 || seals[0]["size"] != float64(3) || index["size"] != float64(2) {
		t.Fatalf("seal %v", seals)
	}
}

func TestChildPdeathsig(t *testing.T) {
	if os.Getenv("ULRMM_TEST_PDEATH_PARENT") == "1" {
		attr := linuxFilesAttr()
		cmd := exec.Command("sleep", "60")
		cmd.SysProcAttr = attr
		err := cmd.Start()
		if errors.Is(err, syscall.EPERM) {
			// a mount namespace needs CAP_SYS_ADMIN, the signal does not
			attr.Unshareflags = 0
			cmd = exec.Command("sleep", "60")
			cmd.SysProcAttr = attr
			err = cmd.Start()
		}
		if err != nil {
			os.Exit(2)
		}
		fmt.Println(cmd.Process.Pid)
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	var attr *syscall.SysProcAttr
	old := linuxFilesStart
	linuxFilesStart = func(cmd *exec.Cmd, _ []byte, _ string) (*imagingStream, error) {
		attr = cmd.SysProcAttr
		return nil, errors.New("not started")
	}
	startLinuxFiles(context.Background(), ImagingCapability{JobID: "0b6e1a8e-6d6a-4c3e-9f1e-2a1b3c4d5e6f"})
	linuxFilesStart = old
	if attr == nil || attr.Pdeathsig != syscall.SIGKILL || attr.Unshareflags != syscall.CLONE_NEWNS {
		t.Fatalf("the capture child starts with %+v", attr)
	}
	parent := exec.Command(os.Args[0], "-test.run=^TestChildPdeathsig$")
	parent.Env = append(os.Environ(), "ULRMM_TEST_PDEATH_PARENT=1")
	out, err := parent.StdoutPipe()
	if err == nil {
		err = parent.Start()
	}
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		parent.Process.Kill()
		t.Fatalf("child pid: %v", err)
	}
	parent.Process.Kill()
	parent.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil || strings.Contains(string(stat), ") Z ") {
			return
		}
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the capture child outlived the agent")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestChildBackgroundNice(t *testing.T) {
	var asked [][3]int
	old, oldStart := linuxSetpriority, linuxFilesStart
	linuxSetpriority = func(which, who, prio int) error {
		asked = append(asked, [3]int{which, who, prio})
		return nil
	}
	var stdin []byte
	linuxFilesStart = func(_ *exec.Cmd, in []byte, _ string) (*imagingStream, error) {
		stdin = in
		return nil, errors.New("not started")
	}
	t.Cleanup(func() { linuxSetpriority, linuxFilesStart = old, oldStart })
	linuxFilesNice("normal")
	linuxFilesNice("background")
	if !reflect.DeepEqual(asked, [][3]int{{unix.PRIO_PROCESS, 0, 10}}) {
		t.Fatalf("asked for %v", asked)
	}
	startLinuxFiles(context.Background(), ImagingCapability{JobID: "0b6e1a8e-6d6a-4c3e-9f1e-2a1b3c4d5e6f", Priority: "background"})
	var approved ImagingCapability
	if err := json.Unmarshal(stdin, &approved); err != nil || approved.Priority != "background" {
		t.Fatalf("the child gets %s: %v", stdin, err)
	}
}
