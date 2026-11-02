// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func apiAgent(t *testing.T, h http.HandlerFunc) *Agent {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	a := testUpdateAgent()
	a.AgentID = "agent1"
	// the RMM; every test server has the same certificate
	a.ApiURL, a.Cert = "127.0.0.1", writeCA(t, ts)
	a.rClient = a.newAPIClient(ts.URL, map[string]string{"Authorization": "Token t"})
	return a
}

func inRange(t *testing.T, name string, v, lo, hi int) {
	t.Helper()
	if v < lo || v >= hi {
		t.Fatalf("%s = %d, want [%d,%d)", name, v, lo, hi)
	}
}

func checkDefaults(t *testing.T, c AgentCheckInConfig) {
	t.Helper()
	inRange(t, "hello", c.Hello, 30, 60)
	inRange(t, "agentinfo", c.AgentInfo, 200, 400)
	inRange(t, "winsvc", c.WinSvc, 2400, 3000)
	inRange(t, "pubip", c.PubIP, 300, 500)
	inRange(t, "disks", c.Disks, 1000, 2000)
	inRange(t, "sw", c.SW, 2800, 3500)
	inRange(t, "wmi", c.WMI, 3000, 4000)
	inRange(t, "syncmesh", c.SyncMesh, 800, 1200)
	inRange(t, "drivers", c.Drivers, 80000, 90000)
}

func TestSanitizeIntervals(t *testing.T) {
	c := sanitizeIntervals(AgentCheckInConfig{Hello: -3, AgentInfo: 1, WinSvc: 77})
	inRange(t, "hello", c.Hello, 30, 60)
	if c.AgentInfo != minCheckInInterval || c.WinSvc != 77 {
		t.Fatalf("got %+v", c)
	}
	checkDefaults(t, sanitizeIntervals(AgentCheckInConfig{}))
}

func TestCheckInConfFromAPI(t *testing.T) {
	lastCheckInConf.conf = nil
	status := http.StatusBadGateway
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/agent1/config/" || r.Header.Get("Authorization") != "Token t" {
			t.Errorf("unexpected request %s %v", r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			w.Write([]byte(`{"checkin_hello": 45, "checkin_agentinfo": 2, "checkin_wmi": 0, "limit_data": true,
				"install_nushell_url": "http://example.com/nu", "install_deno_url": "HTTPS://example.com/deno"}`))
		}
	})

	// an error page before any good answer: defaults, no zero intervals
	checkDefaults(t, a.GetCheckInConfFromAPI())

	status = http.StatusOK
	c := a.GetCheckInConfFromAPI()
	if c.Hello != 45 || c.AgentInfo != minCheckInInterval || !c.LimitData {
		t.Fatalf("server values not taken: %+v", c)
	}
	inRange(t, "wmi", c.WMI, 3000, 4000)
	if c.InstallNushellUrl != "" || c.InstallDenoUrl != "HTTPS://example.com/deno" {
		t.Fatalf("download urls: %q %q", c.InstallNushellUrl, c.InstallDenoUrl)
	}

	// later errors keep the last good answer
	status = http.StatusInternalServerError
	if again := a.GetCheckInConfFromAPI(); again != c {
		t.Fatalf("last good config lost: %+v", again)
	}
	lastCheckInConf.conf = nil
}

func TestCheckIntervalFloor(t *testing.T) {
	body := `{"agent": 1, "check_interval": 0}`
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	})
	if n, err := a.GetCheckInterval(); err != nil || n != minCheckInterval {
		t.Fatalf("got %d %v", n, err)
	}
	body = `{"agent": 1, "check_interval": 90}`
	if n, err := a.GetCheckInterval(); err != nil || n != 90 {
		t.Fatalf("got %d %v", n, err)
	}

	broken := apiAgent(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if n, err := broken.GetCheckInterval(); err == nil || n != 120 {
		t.Fatalf("server error: got %d %v", n, err)
	}
}

func TestStartupReportBody(t *testing.T) {
	var body map[string]interface{}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/checkin/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusInternalServerError)
	})
	a.AgentStartup(map[string]interface{}{"stop_reason": "manual"})
	if body["agent_id"] != "agent1" || body["stop_reason"] != "manual" || len(body) != 2 {
		t.Fatalf("body %v", body)
	}
}
