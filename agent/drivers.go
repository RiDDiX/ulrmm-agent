// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Driver inventory and problem devices, pushed once a day to
// /api/v3/<agent>/drivers/. Only the WMI queries are Windows code.

// WMI classes; the field names are the selected properties.
type Win32_PnPSignedDriver struct {
	DeviceName         string
	DeviceClass        string
	Manufacturer       string
	DriverProviderName string
	DriverVersion      string
	DriverDate         string
	InfName            string
	DeviceID           string
	IsSigned           bool
}

type Win32_PnPEntity struct {
	Name                   string
	PNPDeviceID            string
	ConfigManagerErrorCode uint32
	PNPClass               string
}

type driverRow struct {
	Device       string `json:"device"`
	Class        string `json:"class"`
	Manufacturer string `json:"manufacturer"`
	Provider     string `json:"provider"`
	Version      string `json:"version"`
	Date         string `json:"date"`
	Inf          string `json:"inf"`
	Signed       bool   `json:"signed"`
	DeviceID     string `json:"device_id"`
}

type problemRow struct {
	Name     string `json:"name"`
	DeviceID string `json:"device_id"`
	Class    string `json:"class"`
	Code     uint32 `json:"code"`
}

type driverReport struct {
	V        int          `json:"v"`
	TS       int64        `json:"ts"`
	Drivers  []driverRow  `json:"drivers"`
	Problems []problemRow `json:"problems"`
	Errors   []string     `json:"errors"`
}

const (
	maxDriverRows  = 2048
	maxProblemRows = 256
	maxDriverErrs  = 8
	maxDriverBody  = 1000 * 1000
	driversBackoff = 24 * time.Hour
)

var (
	driversRunning  atomic.Bool
	driversOffUntil atomic.Int64
)

// driverDate turns CIM datetime text (20230615000000.******+000) into
// YYYY-MM-DD, anything else into "".
func driverDate(cim string) string {
	if len(cim) < 8 {
		return ""
	}
	t, err := time.Parse("20060102", cim[:8])
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02")
}

func (r *driverReport) addErr(format string, args ...interface{}) {
	if len(r.Errors) < maxDriverErrs {
		r.Errors = append(r.Errors, sclip(fmt.Sprintf(format, args...), 128))
	}
}

func lessFold(a, b string) (bool, bool) {
	a, b = strings.ToLower(a), strings.ToLower(b)
	return a < b, a == b
}

func cleanDrivers(in []Win32_PnPSignedDriver, r *driverReport) []driverRow {
	out := []driverRow{}
	for _, d := range in {
		row := driverRow{
			Device:       sclip(d.DeviceName, 255),
			Class:        sclip(d.DeviceClass, 64),
			Manufacturer: sclip(d.Manufacturer, 255),
			Provider:     sclip(d.DriverProviderName, 255),
			Version:      sclip(d.DriverVersion, 64),
			Date:         driverDate(d.DriverDate),
			Inf:          sclip(d.InfName, 64),
			Signed:       d.IsSigned,
			DeviceID:     sclip(d.DeviceID, 255),
		}
		// devices without a driver come back with every field empty
		if row.Inf != "" {
			out = append(out, row)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if lt, eq := lessFold(out[i].Class, out[j].Class); !eq {
			return lt
		}
		if lt, eq := lessFold(out[i].Device, out[j].Device); !eq {
			return lt
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	if len(out) > maxDriverRows {
		r.addErr("%d drivers, the first %d sent", len(out), maxDriverRows)
		out = out[:maxDriverRows]
	}
	return out
}

// cleanProblems keeps devices with a problem code; 45 (not connected) is
// no fault.
func cleanProblems(in []Win32_PnPEntity, r *driverReport) []problemRow {
	out := []problemRow{}
	for _, d := range in {
		c := d.ConfigManagerErrorCode
		if c < 1 || c > 99 || c == 45 {
			continue
		}
		out = append(out, problemRow{
			Name:     sclip(d.Name, 255),
			DeviceID: sclip(d.PNPDeviceID, 255),
			Class:    sclip(d.PNPClass, 64),
			Code:     c,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if lt, eq := lessFold(out[i].Class, out[j].Class); !eq {
			return lt
		}
		if lt, eq := lessFold(out[i].Name, out[j].Name); !eq {
			return lt
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	if len(out) > maxProblemRows {
		r.addErr("%d problem devices, the first %d sent", len(out), maxProblemRows)
		out = out[:maxProblemRows]
	}
	return out
}

// collectDrivers: a class that fails leaves its list empty and says why.
var oemInfRe = regexp.MustCompile(`(?i)^oem[0-9]+\.inf$`)

// dropDeleted leaves out oem*.inf rows whose package is gone from the INF
// folder: after pnputil /delete-driver WMI keeps listing the old driver
// until the next reboot.
func dropDeleted(d []Win32_PnPSignedDriver, infDir string) []Win32_PnPSignedDriver {
	out := d[:0]
	for _, x := range d {
		if oemInfRe.MatchString(x.InfName) {
			if _, err := os.Stat(filepath.Join(infDir, x.InfName)); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		out = append(out, x)
	}
	return out
}

func collectDrivers(now time.Time, drivers func() ([]Win32_PnPSignedDriver, error), problems func() ([]Win32_PnPEntity, error)) driverReport {
	r := driverReport{V: 1, TS: now.Unix(), Errors: []string{}}
	d, err := drivers()
	if err != nil {
		r.addErr("Win32_PnPSignedDriver: %v", err)
	}
	r.Drivers = cleanDrivers(d, &r)
	p, err := problems()
	if err != nil {
		r.addErr("Win32_PnPEntity: %v", err)
	}
	r.Problems = cleanProblems(p, &r)
	return r
}

func encodeJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(v)
	return buf.Bytes(), err
}

// encodeDrivers cuts the driver list until the body fits the server's limit;
// escaping can make a row of clipped strings far larger than usual.
func encodeDrivers(r driverReport) ([]byte, error) {
	total, errs := len(r.Drivers), r.Errors
	for {
		b, err := encodeJSON(r)
		if err != nil || len(b) <= maxDriverBody || len(r.Drivers) == 0 {
			return b, err
		}
		r.Drivers = r.Drivers[:len(r.Drivers)*3/4]
		r.Errors = append(errs[:len(errs):len(errs)], fmt.Sprintf("%d drivers, %d sent to stay under 1 MB", total, len(r.Drivers)))
	}
}

func (a *Agent) driversLoop(every int) {
	sleepSeconds(randRange(300, 900))
	for {
		a.guard("SendDrivers", func() { a.SendDrivers(false) })
		sleepSeconds(every)
	}
}

// SendDrivers runs one push at a time. force (the server asked) ignores the
// back-off after a 404.
func (a *Agent) SendDrivers(force bool) {
	if !driversSupported {
		return
	}
	a.pushDrivers(force, func() driverReport {
		return collectDrivers(time.Now(), pnpSignedDrivers, pnpProblemDevices)
	})
}

func (a *Agent) pushDrivers(force bool, collect func() driverReport) {
	if !driversRunning.CompareAndSwap(false, true) {
		return
	}
	defer driversRunning.Store(false)
	if !force && time.Now().Unix() < driversOffUntil.Load() {
		return
	}
	b, err := encodeDrivers(collect())
	if err != nil {
		a.Logger.Debugln("SendDrivers():", err)
		return
	}
	r, err := a.rClient.R().SetHeader("Content-Type", "application/json").SetBody(b).Post(fmt.Sprintf("/api/v3/%s/drivers/", a.AgentID))
	if err != nil {
		a.Logger.Debugln("SendDrivers():", err)
		return
	}
	if r.StatusCode() == http.StatusNotFound {
		// server without the endpoint
		driversOffUntil.Store(time.Now().Add(driversBackoff).Unix())
	}
	if r.IsError() {
		a.Logger.Debugln("SendDrivers(): server answered", r.StatusCode())
	}
}
