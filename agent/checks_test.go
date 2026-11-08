// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/sirupsen/logrus"
)

func TestFilterEventLog(t *testing.T) {
	entries := []rmm.EventEntry{
		{Src: "Service Control Manager", Kind: "ERROR", Code: 7000, Text: "The service failed to start", RowID: 1},
		{Src: "Service Control Manager", Kind: "INFO", Code: 7036, Text: "entered the running state", RowID: 2},
		{Src: "Disk", Kind: "ERROR", Code: 7, Text: "bad block", RowID: 3},
		{Src: "disk", Kind: "ERROR", Code: 7, Text: "Bad block", RowID: 4},
	}
	uids := func(l []rmm.EventEntry) []int {
		r := []int{}
		for _, e := range l {
			r = append(r, e.RowID)
		}
		return r
	}
	cases := []struct {
		name string
		c    rmm.CheckDef
		want []int
	}{
		{"wildcard", rmm.CheckDef{EventKind: "ERROR", AnyEvent: true}, []int{1, 3, 4}},
		{"exact id", rmm.CheckDef{EventKind: "ERROR", EventCode: 7}, []int{3, 4}},
		{"source is case sensitive", rmm.CheckDef{EventKind: "ERROR", AnyEvent: true, EventSrc: "Disk"}, []int{3}},
		{"message", rmm.CheckDef{EventKind: "ERROR", AnyEvent: true, EventText: "block"}, []int{3, 4}},
		{"both", rmm.CheckDef{EventKind: "ERROR", EventCode: 7, EventSrc: "disk", EventText: "Bad"}, []int{4}},
		{"wrong type", rmm.CheckDef{EventKind: "WARNING", AnyEvent: true}, []int{}},
	}
	for _, c := range cases {
		got := filterEventLog(c.c, entries)
		if got == nil || !reflect.DeepEqual(uids(got), c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, uids(got), c.want)
		}
	}
	if filterEventLog(rmm.CheckDef{}, nil) == nil {
		t.Fatal("no entries must give an empty list, not null")
	}
}

func TestWinSvcVerdict(t *testing.T) {
	started := false
	start := func(after string) func() string { return func() string { started = true; return after } }
	cases := []struct {
		name         string
		c            rmm.CheckDef
		state        string
		err          error
		after        string
		status, info string
		startCalled  bool
	}{
		{"running", rmm.CheckDef{}, "running", nil, "", "passing", "Status: running", false},
		{"start pending allowed", rmm.CheckDef{OKIfStarting: true}, "start_pending", nil, "", "passing", "Status: start_pending", false},
		{"stopped", rmm.CheckDef{}, "stopped", nil, "", "failing", "Status: stopped", false},
		{"restarted", rmm.CheckDef{Restart: true}, "stopped", nil, "running", "passing", "Status: running", true},
		{"restart failed", rmm.CheckDef{Restart: true}, "stopped", nil, "stopped", "failing", "Status: stopped", true},
		{"start accepted, not running", rmm.CheckDef{Restart: true}, "stopped", nil, "start_pending", "failing", "Status: start_pending", true},
		{"start accepted, starting allowed", rmm.CheckDef{Restart: true, OKIfStarting: true}, "stopped", nil, "start_pending", "passing", "Status: start_pending", true},
		{"missing allowed", rmm.CheckDef{OKIfMissing: true}, "", errors.New("no such service"), "", "passing", "no such service", false},
		{"missing", rmm.CheckDef{}, "", errors.New("no such service"), "", "failing", "no such service", false},
	}
	for _, c := range cases {
		started = false
		status, info := winSvcVerdict(c.c, c.state, c.err, start(c.after))
		if status != c.status || info != c.info || started != c.startCalled {
			t.Fatalf("%s: got %q %q started=%v", c.name, status, info, started)
		}
	}

	seq := []string{"start_pending", "start_pending", "running"}
	n := 0
	get := func() (string, error) { s := seq[min(n, len(seq)-1)]; n++; return s, nil }
	if s := waitSvcRunning(get, time.Second, time.Millisecond); s != "running" || n != 3 {
		t.Fatalf("got %q after %d polls", s, n)
	}
	stopped := func() (string, error) { return "stopped", nil }
	began := time.Now()
	if s := waitSvcRunning(stopped, 30*time.Millisecond, 5*time.Millisecond); s != "stopped" || time.Since(began) > time.Second {
		t.Fatalf("got %q after %v", s, time.Since(began))
	}
}

func TestDiskCheckHung(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	old, oldWait := diskUsage, diskCheckWait
	diskUsage = func(string) (*disk.UsageStat, error) { calls.Add(1); <-release; return &disk.UsageStat{Total: 1}, nil }
	diskCheckWait = 20 * time.Millisecond
	defer func() { close(release); diskUsage, diskCheckWait = old, oldWait }()

	a := &Agent{Logger: logrus.New()}
	began := time.Now()
	if r := a.DiskCheck(rmm.CheckDef{Drive: "/mnt/nfs"}); r.Found || r.Info != "Disk /mnt/nfs does not respond" {
		t.Fatalf("%+v", r)
	}
	if time.Since(began) > time.Second {
		t.Fatal("check blocked", time.Since(began))
	}
	began = time.Now()
	if _, err := statBounded("/mnt/nfs", 5*time.Second); !errors.Is(err, errStatTimeout) || time.Since(began) > time.Second {
		t.Fatal("second call while the first hangs:", err, time.Since(began))
	}
	statInFlight.Lock()
	inFlight := statInFlight.m["/mnt/nfs"]
	statInFlight.Unlock()
	if calls.Load() != 1 || !inFlight {
		t.Fatalf("calls %d in flight %v", calls.Load(), inFlight)
	}
}

func TestRunChecks(t *testing.T) {
	var mu sync.Mutex
	var patches []map[string]interface{}
	body, status := "", http.StatusOK
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/agent1/runchecks/":
			w.WriteHeader(status)
			io.WriteString(w, body)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v3/checkrunner/":
			var m map[string]interface{}
			json.NewDecoder(r.Body).Decode(&m)
			mu.Lock()
			patches = append(patches, m)
			mu.Unlock()
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	dir := t.TempDir()
	body = `{"agent": 1, "check_interval": 120, "checks": [
		{"id": 5, "check_type": "diskspace", "disk": "` + dir + `"},
		{"id": 6, "check_type": "diskspace", "disk": "` + dir + `/missing"},
		{"id": 7, "check_type": "nonsense"}]}`
	if err := a.RunChecks(true); err != nil {
		t.Fatal(err)
	}
	if len(patches) != 2 {
		t.Fatalf("want 2 results, got %v", patches)
	}
	for _, p := range patches {
		if p["agent_id"] != "agent1" {
			t.Fatalf("result without agent_id: %v", p)
		}
		switch p["id"] {
		case 5.0:
			if p["exists"] != true || p["percent_used"] == nil {
				t.Fatalf("existing disk: %v", p)
			}
		case 6.0:
			if p["exists"] != false || p["more_info"] != "Disk "+dir+"/missing does not exist" {
				t.Fatalf("missing disk: %v", p)
			}
		default:
			t.Fatalf("unexpected result %v", p)
		}
	}

	patches, status = nil, http.StatusInternalServerError
	if err := a.RunChecks(true); err != nil || len(patches) != 0 {
		t.Fatalf("server error: %v %v", err, patches)
	}
	status, body = http.StatusOK, "{not json"
	if err := a.RunChecks(true); err == nil {
		t.Fatal("bad JSON accepted")
	}
}

func TestParseUnitShow(t *testing.T) {
	u := parseUnitShow("LoadState=loaded\nActiveState=failed\nSubState=failed\nNRestarts=3\n")
	if u != (unitState{"loaded", "failed", "failed", "3"}) || u.info() != "failed/failed, restarts 3" {
		t.Fatalf("%+v %q", u, u.info())
	}
	if (unitState{active: "active", sub: "running"}).info() != "active/running" {
		t.Fatal("NRestarts missing on old systemd")
	}
}

func TestSystemdVerdict(t *testing.T) {
	running := unitState{"loaded", "active", "running", "0"}
	dead := unitState{"loaded", "inactive", "dead", "1"}
	cases := []struct {
		name      string
		c         rmm.CheckDef
		have      bool
		st        unitState
		err       error
		after     unitState
		startErr  error
		status    string
		info      string
		wantStart bool
	}{
		{"active", rmm.CheckDef{}, true, running, nil, unitState{}, nil, "passing", "active/running, restarts 0", false},
		{"reloading", rmm.CheckDef{}, true, unitState{"loaded", "reloading", "reload", ""}, nil, unitState{}, nil, "passing", "reloading/reload", false},
		{"failed", rmm.CheckDef{}, true, unitState{"loaded", "failed", "failed", "4"}, nil, unitState{}, nil, "failing", "failed/failed, restarts 4", false},
		{"not found", rmm.CheckDef{Svc: "x.service"}, true, unitState{load: "not-found", active: "inactive", sub: "dead"}, nil, unitState{}, nil, "failing", "Unit x.service not found", false},
		{"not found may pass", rmm.CheckDef{Svc: "x.service", OKIfMissing: true}, true, unitState{load: "not-found"}, nil, unitState{}, nil, "passing", "Unit x.service not found", false},
		{"no systemd", rmm.CheckDef{}, false, unitState{}, nil, unitState{}, nil, "failing", "systemd not available", false},
		{"no systemd may pass", rmm.CheckDef{OKIfMissing: true}, false, unitState{}, nil, unitState{}, nil, "passing", "systemd not available", false},
		{"systemctl error", rmm.CheckDef{Restart: true}, true, unitState{}, errors.New("systemctl: timed out"), unitState{}, nil, "failing", "systemctl: timed out", false},
		{"stopped, no restart", rmm.CheckDef{}, true, dead, nil, unitState{}, nil, "failing", "inactive/dead, restarts 1", false},
		{"restarted", rmm.CheckDef{Restart: true}, true, dead, nil, running, nil, "passing", "active/running, restarts 0", true},
		{"restart did not help", rmm.CheckDef{Restart: true}, true, dead, nil, unitState{"loaded", "failed", "failed", "2"}, nil, "failing", "failed/failed, restarts 2", true},
		{"start failed", rmm.CheckDef{Restart: true}, true, dead, nil, unitState{}, errors.New("Job failed"), "failing", "inactive/dead, restarts 1, start failed: Job failed", true},
	}
	for _, c := range cases {
		started := false
		status, info := systemdVerdict(c.c, c.have, c.st, c.err, func() (unitState, error) {
			started = true
			return c.after, c.startErr
		})
		if status != c.status || info != c.info || started != c.wantStart {
			t.Fatalf("%s: got %s %q started=%v", c.name, status, info, started)
		}
	}
}

func TestRunChecksSystemdContainer(t *testing.T) {
	var mu sync.Mutex
	got := map[float64]map[string]interface{}{}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/agent1/runchecks/":
			io.WriteString(w, `{"agent": 1, "check_interval": 120, "checks": [
				{"id": 8, "check_type": "systemd", "svc_name": "ulrmm-test-missing.service", "pass_if_svc_not_exist": true},
				{"id": 9, "check_type": "container", "container": "ulrmm-test-missing", "container_kind": "docker", "pass_if_svc_not_exist": true}]}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v3/checkrunner/":
			var m map[string]interface{}
			json.NewDecoder(r.Body).Decode(&m)
			mu.Lock()
			got[m["id"].(float64)] = m
			mu.Unlock()
		}
	})
	if err := a.RunChecks(true); err != nil {
		t.Fatal(err)
	}
	// whatever the test host has: a missing unit or container passes here
	for _, id := range []float64{8, 9} {
		if m := got[id]; m == nil || m["status"] != "passing" || m["agent_id"] != "agent1" || m["more_info"] == "" {
			t.Fatalf("check %v: %v", id, m)
		}
	}
}
