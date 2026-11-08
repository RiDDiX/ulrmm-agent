// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestPushDriversSkipsFailedQuery(t *testing.T) {
	var hits atomic.Int32
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	driversOffUntil.Store(0)
	a.pushDrivers(true, func() driverReport {
		return collectDrivers(time.Now(),
			func() ([]Win32_PnPSignedDriver, error) { return nil, errors.New("wmi query timed out") },
			func() ([]Win32_PnPEntity, error) { return nil, nil })
	})
	if hits.Load() != 0 {
		t.Fatal("a failed driver query replaced the server's list with an empty one")
	}
}

func TestForcedDriverPushWhileOneRuns(t *testing.T) {
	var hits atomic.Int32
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	driversOffUntil.Store(0)
	t.Cleanup(func() { driversRerun.Store(false) })
	collects := 0
	var collect func() driverReport
	collect = func() driverReport {
		if collects++; collects == 1 {
			// the refresh after a driver install, while the periodic push runs
			a.pushDrivers(true, collect)
		}
		return driverReport{V: 1, Drivers: []driverRow{}, Problems: []problemRow{}, Errors: []string{}}
	}
	a.pushDrivers(false, collect)
	if collects != 2 || hits.Load() != 2 {
		t.Fatalf("%d collects, %d pushes", collects, hits.Load())
	}
	if driversRunning.Load() || driversRerun.Load() {
		t.Fatal("flags left set")
	}
}
