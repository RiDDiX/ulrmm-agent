// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDriverDate(t *testing.T) {
	cases := map[string]string{
		"20230615000000.******+000": "2023-06-15",
		"20061231":                  "2006-12-31",
		"":                          "",
		"2023":                      "",
		"20231345000000.******+000": "",
		"garbage-text-here":         "",
		"6/21/2006":                 "",
	}
	for in, want := range cases {
		if got := driverDate(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestCleanDrivers(t *testing.T) {
	var r driverReport
	in := []Win32_PnPSignedDriver{
		{DeviceName: "Intel(R) Ethernet", DeviceClass: "NET", DriverProviderName: "Intel", DriverVersion: "12.19.2.45",
			DriverDate: "20230615000000.******+000", InfName: "oem12.inf", IsSigned: true, DeviceID: `PCI\VEN_8086&DEV_15B8`},
		{DeviceName: "No driver"},
		{DeviceName: "Disk\x00 drive", DeviceClass: "DiskDrive", InfName: "disk.inf", DriverDate: "x",
			Manufacturer: strings.Repeat("ä", 200)},
		{DeviceName: "Audio", DeviceClass: "Media", InfName: "oem3.inf"},
	}
	out := cleanDrivers(in, &r)
	if len(out) != 3 {
		t.Fatalf("rows without an INF kept: %+v", out)
	}
	if out[0].Class != "DiskDrive" || out[1].Class != "Media" || out[2].Class != "NET" {
		t.Fatalf("order: %+v", out)
	}
	if d := out[0]; d.Device != "Disk drive" || d.Date != "" || len(d.Manufacturer) != 254 {
		t.Fatalf("cleaning: %+v (%d)", d, len(d.Manufacturer))
	}
	if n := out[2]; n.Date != "2023-06-15" || !n.Signed || n.Provider != "Intel" || n.Inf != "oem12.inf" {
		t.Fatalf("row: %+v", n)
	}

	many := make([]Win32_PnPSignedDriver, maxDriverRows+10)
	for i := range many {
		many[i] = Win32_PnPSignedDriver{DeviceName: fmt.Sprint(i), InfName: "x.inf"}
	}
	r = driverReport{}
	if out := cleanDrivers(many, &r); len(out) != maxDriverRows || len(r.Errors) != 1 {
		t.Fatalf("cap: %d rows, errors %v", len(out), r.Errors)
	}
}

func TestCleanProblems(t *testing.T) {
	var r driverReport
	out := cleanProblems([]Win32_PnPEntity{
		{Name: "Unknown device", PNPDeviceID: `ACPI\VEN_X`, ConfigManagerErrorCode: 28},
		{Name: "Gone USB stick", ConfigManagerErrorCode: 45},
		{Name: "Fine", ConfigManagerErrorCode: 0},
		{Name: "Odd", ConfigManagerErrorCode: 100},
		{Name: "Camera", PNPClass: "Camera", ConfigManagerErrorCode: 22},
	}, &r)
	if len(out) != 2 || out[0].Code != 28 || out[1].Name != "Camera" || out[1].Code != 22 {
		t.Fatalf("problems: %+v", out)
	}
}

func TestCollectDriversClassError(t *testing.T) {
	now := time.Unix(1760000000, 0)
	r := collectDrivers(now,
		func() ([]Win32_PnPSignedDriver, error) { return nil, errors.New("wmi query timed out") },
		func() ([]Win32_PnPEntity, error) {
			return []Win32_PnPEntity{{Name: "Unknown", ConfigManagerErrorCode: 1}}, nil
		})
	b, err := encodeJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"ts":1760000000,"drivers":[],"problems":[{"name":"Unknown","device_id":"","class":"","code":1}],` +
		`"errors":["Win32_PnPSignedDriver: wmi query timed out"]}` + "\n"
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestEncodeDriversFitsLimit(t *testing.T) {
	typical := driverReport{V: 1, Errors: []string{}}
	for i := 0; i < maxDriverRows; i++ {
		typical.Drivers = append(typical.Drivers, driverRow{
			Device: "Intel(R) Serial IO I2C Host Controller - 51E8", Class: "System", Manufacturer: "Intel Corporation",
			Provider: "Intel Corporation", Version: "30.100.2229.1", Date: "2022-07-19", Inf: "oem123.inf", Signed: true,
			DeviceID: fmt.Sprintf(`PCI\VEN_8086&DEV_51E8&SUBSYS_0B141028&REV_01\3&11583659&0&A%d`, i),
		})
	}
	b, err := encodeDrivers(typical)
	if err != nil || len(b) > maxDriverBody {
		t.Fatalf("typical: %d bytes, %v", len(b), err)
	}
	var back driverReport
	if json.Unmarshal(b, &back) != nil || len(back.Drivers) != maxDriverRows || len(back.Errors) != 0 {
		t.Fatalf("typical rows cut: %d %v", len(back.Drivers), back.Errors)
	}

	worst := driverReport{V: 1, Errors: []string{"earlier"}}
	q := strings.Repeat(`"\`, 128)
	for i := 0; i < maxDriverRows; i++ {
		worst.Drivers = append(worst.Drivers, driverRow{Device: q[:255], Class: q[:64], Manufacturer: q[:255],
			Provider: q[:255], Version: q[:64], Inf: q[:64], DeviceID: q[:255]})
	}
	for i := 0; i < maxProblemRows; i++ {
		worst.Problems = append(worst.Problems, problemRow{Name: q[:255], DeviceID: q[:255], Class: q[:64], Code: 1})
	}
	b, err = encodeDrivers(worst)
	if err != nil || len(b) > maxDriverBody {
		t.Fatalf("worst: %d bytes, %v", len(b), err)
	}
	back = driverReport{}
	if json.Unmarshal(b, &back) != nil || len(back.Drivers) == 0 || len(back.Drivers) >= maxDriverRows ||
		len(back.Errors) != 2 || back.Errors[0] != "earlier" || !strings.Contains(back.Errors[1], "to stay under 1 MB") {
		t.Fatalf("worst: %d rows, errors %v", len(back.Drivers), back.Errors)
	}
	if len(worst.Errors) != 1 {
		t.Fatal("caller's errors changed")
	}
}

func TestPushDriversBackoff(t *testing.T) {
	var hits atomic.Int32
	status := http.StatusNotFound
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/agent1/drivers/" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		hits.Add(1)
		w.WriteHeader(status)
	})
	driversOffUntil.Store(0)
	t.Cleanup(func() { driversOffUntil.Store(0) })
	collect := func() driverReport {
		return driverReport{V: 1, Drivers: []driverRow{}, Problems: []problemRow{}, Errors: []string{}}
	}

	a.pushDrivers(false, collect)
	a.pushDrivers(false, collect)
	if hits.Load() != 1 {
		t.Fatalf("pushed %d times after a 404", hits.Load())
	}
	if off := time.Until(time.Unix(driversOffUntil.Load(), 0)); off < 23*time.Hour {
		t.Fatalf("back-off %v", off)
	}
	status = http.StatusOK
	a.pushDrivers(true, collect)
	if hits.Load() != 2 {
		t.Fatal("a server request did not override the back-off")
	}

	driversRunning.Store(true)
	a.pushDrivers(true, collect)
	driversRunning.Store(false)
	driversRerun.Store(false)
	if hits.Load() != 2 {
		t.Fatal("second push while one runs")
	}
}

func TestSendDriversNoopOffWindows(t *testing.T) {
	if driversSupported {
		t.Skip("windows")
	}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) { t.Errorf("request %s", r.URL.Path) })
	a.SendDrivers(true)
}

func TestDropDeleted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oem3.inf"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	in := []Win32_PnPSignedDriver{{InfName: "oem3.inf"}, {InfName: "OEM14.INF"}, {InfName: "machine.inf"}}
	got := dropDeleted(in, dir)
	if len(got) != 2 || got[0].InfName != "oem3.inf" || got[1].InfName != "machine.inf" {
		t.Fatalf("got %+v", got)
	}
}

func TestOEMCharmap(t *testing.T) {
	// "gelöscht" in code page 850
	out, err := oemCharmap(850).NewDecoder().String("gel\x94scht")
	if err != nil || out != "gelöscht" {
		t.Fatalf("got %q %v", out, err)
	}
	if oemCharmap(0) != oemCharmap(850) {
		t.Fatal("unknown code page should fall back to 850")
	}
}
