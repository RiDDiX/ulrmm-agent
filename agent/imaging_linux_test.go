// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestLinuxImagingLayout(t *testing.T) {
	layout := linuxImagingBlock{
		Type: "disk", PTType: "gpt", Size: 256 << 20, SectorSize: 512,
		Children: []linuxImagingBlock{
			{Type: "part", FSType: "ext4"},
			{Type: "part", FSType: "vfat", PartType: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"},
		},
	}
	if err := linuxImagingLayout(layout); err != nil {
		t.Fatal(err)
	}
	for _, fs := range []string{"btrfs", "xfs", "LVM2_member", "crypto_LUKS"} {
		layout.Children[0].FSType = fs
		if err := linuxImagingLayout(layout); err == nil {
			t.Errorf("accepted unsupported filesystem %s", fs)
		}
	}
}

func TestLinuxImagingFstab(t *testing.T) {
	parts := []linuxImagingBlock{
		{Name: "/dev/vda2", FSType: "ext4", UUID: "root"},
		{Name: "/dev/vda1", FSType: "vfat", UUID: "AB34", PartType: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"},
	}
	const fstab = "UUID=root / ext4 defaults 0 1\nUUID=ab34 /boot/efi vfat defaults 0 2\n"
	if excluded, err := linuxImagingFstab(parts, "/dev/vda2", fstab); err != nil || excluded != nil {
		t.Fatal(excluded, err)
	}
	for _, required := range []string{
		"UUID=elsewhere /boot ext4 defaults 0 2", "/dev/sdb1 /boot/efi vfat defaults 0 2",
		"nas:/export / nfs4 defaults 0 0", "/dev/vda1 /efi vfat defaults 0 2",
		"UUID=elsewhere /boot/ ext4 defaults 0 2", "UUID=elsewhere /./boot ext4 defaults 0 2",
		"UUID=elsewhere /boot/efi/ vfat defaults 0 2",
	} {
		if _, err := linuxImagingFstab(parts, "/dev/vda2", fstab+required); err == nil {
			t.Fatalf("accepted a required mount outside the system disk: %s", required)
		}
	}
	// Stock Debian and Ubuntu installs: by-uuid links, a swap file, a noauto optical drive.
	parts = append(parts, linuxImagingBlock{Name: "/dev/vda3", FSType: "swap", UUID: "sw", PartLabel: "swap"})
	const stock = "/dev/disk/by-uuid/root / ext4 errors=remount-ro 0 1\n" +
		"/dev/disk/by-uuid/AB34 /boot/efi vfat umask=0077 0 1\n" +
		"/swap.img none swap sw 0 0\nPARTLABEL=swap none swap sw 0 0\n" +
		"/dev/sr0 /media/cdrom0 udf,iso9660 user,noauto 0 0\n"
	if _, err := linuxImagingFstab(parts, "/dev/vda2", stock); err != nil {
		t.Fatal(err)
	}
	// Second disks, network shares and foreign swap stay out of the image instead of blocking it.
	parts = append(parts, linuxImagingBlock{Name: "/dev/vda4", FSType: "ext4", UUID: "fast", Mounts: []string{"/srv/fast"}})
	excluded, err := linuxImagingFstab(parts, "/dev/vda2", stock+
		"UUID=0f1e2d3c-aaaa-4bbb-8ccc-123456789abc /media/frigate ext4 defaults 0 2\n"+
		"/dev/disk/by-uuid/77aa /srv/media ext4 defaults 0 2\n/dev/sdb1 /data ext4 defaults 0 2\n"+
		"UUID=gone /backup ext4 defaults,nofail 0 2\nnas:/export /mnt/nas nfs4 defaults,_netdev 0 0\n"+
		"UUID=other none swap sw 0 0\nUUID=again /media/frigate ext4 defaults 0 2\n"+
		// no disk of their own, or on the system disk under another link name
		"/srv/data /export none bind 0 0\nnone /sys/fs/cgroup cgroup2 defaults 0 0\n"+
		"shm /dev/shm tmpfs defaults 0 0\noverlay /merged overlay defaults 0 0\n"+
		"/dev/disk/by-id/virtio-sys-part4 /srv/fast ext4 defaults 0 2\n")
	want := []string{
		"/media/frigate (UUID=0f1e2d3c-aaaa-4bbb-8ccc-123456789abc)", "/srv/media (/dev/disk/by-uuid/77aa)",
		"/data (/dev/sdb1)", "/backup (UUID=gone)", "/mnt/nas (nas:/export)", "swap (UUID=other)",
	}
	if err != nil || !slices.Equal(excluded, want) {
		t.Fatal(excluded, err)
	}
	if _, err := linuxImagingFstab(parts, "/dev/vda2", stock+"/dev/vda3 none swap sw 0 0\n"); err == nil {
		t.Fatal("accepted a system disk partition by its kernel name")
	}
	parts[2].PartLabel = ""
	parts[1].Label, parts[2].Label = "same", "same"
	if _, err := linuxImagingFstab(parts, "/dev/vda2", fstab+"LABEL=same none swap sw 0 0\n"); err == nil {
		t.Fatal("accepted a label several partitions share")
	}
	// parted names every partition "primary"; UUID mounts must not depend on map order.
	parts[0].PartLabel, parts[1].PartLabel = "primary", "primary"
	for range 200 {
		if _, err := linuxImagingFstab(parts, "/dev/vda2", fstab); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxImagingOtherDiskMounts(t *testing.T) {
	disk := linuxImagingBlock{Name: "/dev/sdb", Type: "disk", Children: []linuxImagingBlock{
		{Name: "/dev/sdb1", Type: "part", Mounts: []string{"/media/frigate"}},
		{Name: "/dev/sdb2", Type: "part", Mounts: []string{"[SWAP]"}},
		{Name: "/dev/sdb3", Type: "part", Mounts: []string{""}},
	}}
	excluded, err := linuxImagingMounts(disk, []string{"/media/frigate (UUID=abc)"})
	if want := []string{"/media/frigate (UUID=abc)", "swap (/dev/sdb2)"}; err != nil || !slices.Equal(excluded, want) {
		t.Fatal(excluded, err)
	}
	disk.Children[2].Mounts = []string{"/boot/efi"}
	if _, err := linuxImagingMounts(disk, nil); err == nil {
		t.Fatal("accepted an EFI partition mounted from another disk")
	}
	if got := linuxImagingNotIncluded(nil); got != "" {
		t.Fatal(got)
	}
	excluded = nil
	for i := range 10 {
		excluded = append(excluded, fmt.Sprintf("/m%d (/dev/sdc%d)", i, i))
	}
	if got := linuxImagingNotIncluded(excluded); !strings.HasPrefix(got, ". Not included: /m0 (/dev/sdc0), ") ||
		!strings.HasSuffix(got, "/m7 (/dev/sdc7), and 2 more.") || len(excluded) != 10 {
		t.Fatal(got)
	}
	// the server keeps 2048 characters of scope
	for i := range excluded {
		excluded[i] = "/" + strings.Repeat("x", 300) + fmt.Sprint(i)
	}
	if got := linuxImagingNotIncluded(excluded); len(got) > 1300 || !strings.HasSuffix(got, " more.") {
		t.Fatal(len(got), got[len(got)-30:])
	}
}

func TestLinuxCaptureRejectsUnboundSource(t *testing.T) {
	reader, err := nativeImagingCapture(context.Background(), ImagingCapability{
		Method: linuxImagingMethod, SourceID: "../../dev/sda",
	})
	if err == nil {
		reader.Close()
		t.Fatal("opened a source that was not authorized")
	}
}

func TestLinuxRecoveryCapture(t *testing.T) {
	disk := os.Getenv("ULRMM_QA_DISK_ID")
	want := os.Getenv("ULRMM_QA_DISK_SHA256")
	if disk == "" || want == "" {
		t.Skip("requires a disposable x86-64 UEFI ULRMM recovery VM with a clean ext4 source")
	}
	ctx := context.Background()
	capability, err := imagingRecoveryCapability(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := nativeImagingCapture(ctx, capability)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, reader)
	if got := hex.EncodeToString(hash.Sum(nil)); err != nil || size != capability.Size || got != want {
		t.Fatalf("size = %d, SHA-256 = %s, read error = %v", size, got, err)
	}
}

func TestLinuxImagingAgentReport(t *testing.T) {
	disk := os.Getenv("ULRMM_QA_REPORT_DISK")
	if disk == "" {
		t.Skip("requires a disposable installed Linux VM connected to a QA ULRMM server")
	}
	ctx := context.Background()
	capability := nativeImagingCapability(ctx)
	if capability.SourceID != disk || capability.Ready != (capability.Method == linuxFilesMethod) {
		t.Fatalf("unexpected installed-system backup capability: %+v", capability)
	}
	if err := New(logrus.New(), "qa").imagingPoll(ctx, capability); err != nil {
		t.Fatal(err)
	}
}

func TestImagingPartialRefusesForeignFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "image.partial")
	if err := os.WriteFile(name, []byte("planted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0662); err != nil {
		t.Fatal(err)
	}
	if out, err := openImagingPartial(name); err == nil {
		out.Close()
		t.Fatal("reused a partial download that others can write")
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(name, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if out, err := openImagingPartial(name); err == nil {
			out.Close()
			t.Fatal("reused a partial download of another user")
		}
	}
}

func TestLinuxImagingTunnel(t *testing.T) {
	url := os.Getenv("ULRMM_QA_TUNNEL_URL")
	if url == "" {
		t.Skip("requires a disposable WireGuard/TLS route-switch test network")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mode, payload := "internal", os.Getenv("ULRMM_QA_TUNNEL_STEP")
	if payload == "allowed-direct" {
		mode = "internet"
	}
	transfer, err := openImaging(imagingGrant{
		URL: url, Token: "temporary-test-token-value", Mode: mode,
	}, "wg0", &Agent{Logger: logrus.New(), Cert: os.Getenv("ULRMM_QA_TUNNEL_CA")})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = transfer.request(ctx, http.MethodPut, "data/?offset=0", []byte(payload), "application/octet-stream")
	if (err != nil) != (payload == "must-not-arrive") {
		t.Fatalf("%s transfer: %v", payload, err)
	}
}
