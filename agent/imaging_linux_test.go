// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	if err := linuxImagingFstab(parts, "/dev/vda2", fstab); err != nil {
		t.Fatal(err)
	}
	if err := linuxImagingFstab(parts, "/dev/vda2", fstab+"UUID=elsewhere /home ext4 defaults 0 2"); err == nil {
		t.Fatal("accepted an fstab reference to a different disk")
	}
	// Stock Debian and Ubuntu installs: by-uuid links, a swap file, a noauto optical drive.
	parts = append(parts, linuxImagingBlock{Name: "/dev/vda3", FSType: "swap", UUID: "sw", PartLabel: "swap"})
	const stock = "/dev/disk/by-uuid/root / ext4 errors=remount-ro 0 1\n" +
		"/dev/disk/by-uuid/AB34 /boot/efi vfat umask=0077 0 1\n" +
		"/swap.img none swap sw 0 0\nPARTLABEL=swap none swap sw 0 0\n" +
		"/dev/sr0 /media/cdrom0 udf,iso9660 user,noauto 0 0\n"
	if err := linuxImagingFstab(parts, "/dev/vda2", stock); err != nil {
		t.Fatal(err)
	}
	if err := linuxImagingFstab(parts, "/dev/vda2", stock+"/dev/sdb1 /data ext4 defaults 0 2\n"); err == nil {
		t.Fatal("accepted a device path outside the system disk")
	}
	parts[2].PartLabel = ""
	parts[1].Label, parts[2].Label = "same", "same"
	if err := linuxImagingFstab(parts, "/dev/vda2", fstab+"LABEL=same none swap sw 0 0\n"); err == nil {
		t.Fatal("accepted a label several partitions share")
	}
	// parted names every partition "primary"; UUID mounts must not depend on map order.
	parts[0].PartLabel, parts[1].PartLabel = "primary", "primary"
	for range 200 {
		if err := linuxImagingFstab(parts, "/dev/vda2", fstab); err != nil {
			t.Fatal(err)
		}
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
	if capability.SourceID != disk || capability.Ready {
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
	}, "wg0", os.Getenv("ULRMM_QA_TUNNEL_CA"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = transfer.request(ctx, http.MethodPut, "data/?offset=0", []byte(payload), "application/octet-stream")
	if (err != nil) != (payload == "must-not-arrive") {
		t.Fatalf("%s transfer: %v", payload, err)
	}
}
