// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsImagingPreflightParsers(t *testing.T) {
	guid := `\\?\Volume{ce65c12e-41df-4394-8068-e10eb09ba2f5}`
	for _, path := range []string{guid, guid + `\`} {
		if !imagingVolumeGUID.MatchString(path) {
			t.Fatalf("rejected Windows volume GUID %q", path)
		}
	}
	for _, path := range []string{`D:\`, `\\host\share`, guid + `\folder`, guid + " -quiet"} {
		if imagingVolumeGUID.MatchString(path) {
			t.Fatalf("accepted non-volume path %q", path)
		}
	}
	system := "\r\nWriter name: 'System Writer'\r\n    Writer Id: {" + vssSystemWriter +
		"}\r\n    Writer Instance Id: {7e631031-c695-4229-9da1-a7de057e64cb}\r\n    State: [1] Stable\r\n    Last error: No error\r\n"
	registry := "\r\nVerfassername: 'Registry Writer'\r\n    Verfasserkennung: {" + strings.ToUpper(vssRegistryWriter) +
		"}\r\n    Verfasserinstanzkennung: {e87ba7e3-f8d8-42d8-b2ee-c76ae26b98e8}\r\n    Status: [1] Stabil\r\n    Letzter Fehler: Kein Fehler\r\n"
	if err := validateWindowsVSSWriters([]byte(system + registry)); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"", system, registry, strings.Replace(system+registry, "[1]", "[8]", 1),
		system + strings.Replace(registry, "{"+strings.ToUpper(vssRegistryWriter)+"}", "{a87ba7e3-f8d8-42d8-b2ee-c76ae26b98e8}", 1),
		system + strings.Replace(registry, "Status: [1] Stabil", "Status:", 1),
	} {
		if err := validateWindowsVSSWriters([]byte(output)); err == nil {
			t.Fatalf("accepted incomplete or failed VSS writer output %q", output)
		}
	}
}

func TestWindowsImagingArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "WindowsImageBackup")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "catalog"), []byte("test image"), 0600); err != nil {
		t.Fatal(err)
	}
	var packed bytes.Buffer
	if err := archiveWindowsBackup(t.Context(), &packed, path); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(&packed)
	for _, expected := range []string{"WindowsImageBackup/", "WindowsImageBackup/catalog"} {
		header, err := reader.Next()
		if err != nil || header.Name != expected {
			t.Fatalf("read %q: %v %v", expected, header, err)
		}
	}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "test image" {
		t.Fatalf("archive content: %q, %v", body, err)
	}
}

func TestWindowsImagingRetainedOwnership(t *testing.T) {
	root := t.TempDir()
	if state, err := loadWindowsImagingStage(root); state != nil || err != nil {
		t.Fatalf("empty staging: %v, %v", state, err)
	}
	backup := filepath.Join(root, "WindowsImageBackup")
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(backup, "machine", "Catalog")
	if err := os.MkdirAll(catalog, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catalog, "GlobalCatalog"), []byte("catalog"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWindowsImagingStage(root); err == nil {
		t.Fatal("accepted unowned Windows Backup directory")
	}
	state := windowsImagingStage{
		JobID:      "6917640e-87bd-4587-982e-d1942e26f2cf",
		SourceID:   "cb2bfbf6-eff5-4331-8fc9-9316bd02f547",
		DeviceUUID: "f60ebdc4-497b-4e65-a9bd-0c8417694dd1",
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, windowsImagingStateFile), data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadWindowsImagingStage(root); err != nil || got == nil || *got != state {
		t.Fatalf("retained staging: %v, %v", got, err)
	}
	next := ImagingCapability{
		JobID:      "55d58fa9-50e5-482e-82a4-4a5f51fd353a",
		DeviceUUID: state.DeviceUUID,
		PriorCaptureFinished: func(_ context.Context, id string) (bool, error) {
			return false, nil
		},
	}
	if err := retireWindowsImagingStage(t.Context(), root, state, next); err == nil {
		t.Fatal("cleared a previous capture without positive server verification")
	}
	if got, err := loadWindowsImagingStage(root); err != nil || got == nil || *got != state {
		t.Fatalf("unconfirmed previous capture was lost: %v, %v", got, err)
	}
	next.PriorCaptureFinished = func(_ context.Context, id string) (bool, error) {
		return id == state.JobID, nil
	}
	moved := state
	moved.SourceID = "6050e9b4-17c5-4e63-bc2a-a576df8a7fb0"
	if err := clearWindowsImagingStage(root, moved); err == nil {
		t.Fatal("cleared a capture whose ownership record differed")
	}
	if _, err := os.Stat(filepath.Join(catalog, "GlobalCatalog")); err != nil {
		t.Fatalf("capture catalog was lost without matching ownership: %v", err)
	}
	if err := retireWindowsImagingStage(t.Context(), root, state, next); err != nil {
		t.Fatal(err)
	}
	if got, err := loadWindowsImagingStage(root); err != nil || got != nil {
		t.Fatalf("confirmed previous capture was retained: %v, %v", got, err)
	}
}

func TestWindowsImagingClearsInterruptedBackup(t *testing.T) {
	root := t.TempDir()
	state := windowsImagingStage{
		JobID:      "6917640e-87bd-4587-982e-d1942e26f2cf",
		SourceID:   "cb2bfbf6-eff5-4331-8fc9-9316bd02f547",
		DeviceUUID: "f60ebdc4-497b-4e65-a9bd-0c8417694dd1",
	}
	if err := writeWindowsImagingStage(root, state); err != nil {
		t.Fatal(err)
	}
	// A cleanup that stopped between the set and the record leaves this state.
	got, err := loadWindowsImagingStage(root)
	if err != nil || got == nil || !got.Pending {
		t.Fatalf("complete record without its Windows Backup set: %v, %v", got, err)
	}
	if err := clearWindowsImagingStage(root, *got); err != nil {
		t.Fatal(err)
	}
	state.Pending = true
	if err := writeWindowsImagingStage(root, state); err != nil {
		t.Fatal(err)
	}
	if got, err := loadWindowsImagingStage(root); err != nil || got == nil || *got != state {
		t.Fatalf("record written before Windows Backup started: %v, %v", got, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "WindowsImageBackup", "machine"), 0700); err != nil {
		t.Fatal(err)
	}
	next := ImagingCapability{
		JobID:      state.JobID,
		DeviceUUID: state.DeviceUUID,
		PriorCaptureFinished: func(context.Context, string) (bool, error) {
			t.Fatal("asked the server about an unfinished local set")
			return false, nil
		},
	}
	if err := retireWindowsImagingStage(t.Context(), root, state, next); err != nil {
		t.Fatal(err)
	}
	if got, err := loadWindowsImagingStage(root); err != nil || got != nil {
		t.Fatalf("interrupted set was retained: %v, %v", got, err)
	}
	state.Pending = false
	for _, status := range []string{"failed", "verified"} {
		if err := os.MkdirAll(filepath.Join(root, "WindowsImageBackup"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := writeWindowsImagingStage(root, state); err != nil {
			t.Fatal(err)
		}
		next := ImagingCapability{
			JobID:      "55d58fa9-50e5-482e-82a4-4a5f51fd353a",
			DeviceUUID: state.DeviceUUID,
			PriorCaptureFinished: func(context.Context, string) (bool, error) {
				return imagingPriorFinished(200, status)
			},
		}
		if err := retireWindowsImagingStage(t.Context(), root, state, next); err != nil {
			t.Fatalf("%s previous capture blocked staging: %v", status, err)
		}
	}
}
