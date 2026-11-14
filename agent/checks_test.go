// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
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
	time.Sleep(1100 * time.Millisecond)
	began = time.Now()
	if _, err := statBounded("/mnt/nfs", time.Second); !errors.Is(err, errStatTimeout) || time.Since(began) > 300*time.Millisecond {
		t.Fatal("a call hung longer than the caller's limit must fail at once:", err, time.Since(began))
	}
	statInFlight.Lock()
	inFlight := statInFlight.m["/mnt/nfs"] != nil
	statInFlight.Unlock()
	if calls.Load() != 1 || !inFlight {
		t.Fatalf("calls %d in flight %v", calls.Load(), inFlight)
	}
}

// the state push and a disk check on one path share the slow call
func TestStatBoundedShared(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	old := diskUsage
	diskUsage = func(string) (*disk.UsageStat, error) { calls.Add(1); <-release; return &disk.UsageStat{Total: 7}, nil }
	defer func() { diskUsage = old }()

	first := make(chan error, 1)
	go func() { _, err := statBounded("/shared", time.Second); first <- err }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.AfterFunc(50*time.Millisecond, func() { close(release) })
	if u, err := statBounded("/shared", time.Second); err != nil || u.Total != 7 {
		t.Fatal("second caller:", u, err)
	}
	if err := <-first; err != nil {
		t.Fatal("first caller:", err)
	}
	if calls.Load() != 1 {
		t.Fatal("calls", calls.Load())
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

func TestRunChecksSingleFlight(t *testing.T) {
	var gets atomic.Int32
	inside, release := make(chan struct{}), make(chan struct{})
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if gets.Add(1) == 1 {
			close(inside)
			<-release
		}
		io.WriteString(w, `{"agent": 1, "check_interval": 120, "checks": []}`)
	})
	done := make(chan error)
	go func() { done <- a.RunChecks(true) }()
	<-inside
	if err := a.RunChecks(false); err != nil || gets.Load() != 1 {
		t.Fatalf("second run: %v, %d requests", err, gets.Load())
	}
	if runtime.GOOS != "windows" && !a.ChecksRunning() {
		t.Fatal("ChecksRunning false during a run")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := a.RunChecks(true); err != nil || gets.Load() != 2 {
		t.Fatalf("run after the first: %v, %d requests", err, gets.Load())
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
		if rid, _ := got[id]["result_id"].(string); !resultIDPattern.MatchString(rid) {
			t.Fatalf("check %v: result_id %q", id, rid)
		}
	}
	if got[8]["result_id"] == got[9]["result_id"] {
		t.Fatal("two results share one result_id")
	}
}

func TestRunnerScriptTimeout(t *testing.T) {
	limit := 3480
	for in, want := range map[int]int{-5: -5, 0: 0, 120: 120, 541: 541, limit: limit, limit + 1: limit, 86400: limit} {
		if got := runnerScriptTimeout(in); got != want {
			t.Errorf("runnerScriptTimeout(%d) = %d, want %d", in, got, want)
		}
	}
}

// Without a long script check the child ends at 600 s as before; a long one
// gets its own timeout plus the send margin, and with the start allowance
// it still ends before the service's ceiling.
func TestRunnerDeadline(t *testing.T) {
	script := func(secs int) rmm.CheckDef { return rmm.CheckDef{Kind: "script", TimeoutSec: secs} }
	for _, c := range []struct {
		checks []rmm.CheckDef
		want   int
	}{
		{nil, 600},
		{[]rmm.CheckDef{{Kind: "diskspace"}, script(0), script(-1)}, 600},
		{[]rmm.CheckDef{script(120), script(510)}, 600},
		{[]rmm.CheckDef{script(511)}, 601},
		{[]rmm.CheckDef{script(120), script(1800), {Kind: "ping", TimeoutSec: 3000}}, 1890},
		{[]rmm.CheckDef{script(3480)}, 3570},
		{[]rmm.CheckDef{script(3510)}, 3570},
		{[]rmm.CheckDef{script(86400)}, 3570},
	} {
		got := runnerDeadline(c.checks)
		if got != c.want {
			t.Errorf("runnerDeadline(%+v) = %d, want %d", c.checks, got, c.want)
		}
		if got+checkStartAllowance > checkRunnerCeiling {
			t.Errorf("deadline %d does not end before the ceiling", got)
		}
	}
}

// resultIDs records the result_id of every check result PATCH.
func resultIDs(t *testing.T, mu *sync.Mutex, ids *[]string, r *http.Request) int {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Error(err)
	}
	id, _ := body["result_id"].(string)
	mu.Lock()
	defer mu.Unlock()
	*ids = append(*ids, id)
	return len(*ids)
}

// A result is sent again after a 5xx, with the same result_id, and not
// after a 4xx.
func TestSendCheckResultRetry(t *testing.T) {
	wait := pkgRetryWait
	pkgRetryWait = time.Millisecond
	t.Cleanup(func() { pkgRetryWait = wait })
	var mu sync.Mutex
	var ids []string
	var answers []int
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v3/checkrunner/" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		n := resultIDs(t, &mu, &ids, r)
		w.WriteHeader(answers[n-1])
	})
	for _, c := range []struct {
		answers []int
		calls   int
	}{
		{[]int{http.StatusServiceUnavailable, http.StatusOK}, 2},
		{[]int{http.StatusInternalServerError, http.StatusOK}, 2},
		{[]int{http.StatusGatewayTimeout, http.StatusBadGateway, http.StatusOK}, 3},
		{[]int{500, 500, 500, 500, http.StatusOK}, 4},
		{[]int{http.StatusBadRequest, http.StatusOK}, 1},
		{[]int{http.StatusInternalServerError, http.StatusConflict, http.StatusOK}, 2},
	} {
		ids, answers = nil, c.answers
		a.sendCheckResult(CPUMemResult{resultHead: a.checkHead(rmm.CheckDef{CheckID: 3}), Pct: 7})
		if len(ids) != c.calls {
			t.Fatalf("answers %v: %d calls, want %d", c.answers, len(ids), c.calls)
		}
		for _, id := range ids {
			if id != ids[0] || id == "" {
				t.Fatalf("answers %v: result_id per call %q", c.answers, ids)
			}
		}
	}
}

// A result whose answer did not come in time is sent again with the same
// result_id; the server applies it only once. The first request is held
// until the client gave up on it, so it times out whatever the machine's
// speed; any later one may time out as well and is then sent again.
func TestSendCheckResultRepeatedAfterTimeout(t *testing.T) {
	wait := pkgRetryWait
	pkgRetryWait = time.Millisecond
	t.Cleanup(func() { pkgRetryWait = wait })
	var mu sync.Mutex
	var ids []string
	gaveUp := make(chan struct{})
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if resultIDs(t, &mu, &ids, r) == 1 {
			<-r.Context().Done()
			close(gaveUp)
		}
	})
	a.rClient.SetTimeout(time.Second)
	a.sendCheckResult(CPUMemResult{resultHead: a.checkHead(rmm.CheckDef{CheckID: 3}), Pct: 7})
	<-gaveUp
	mu.Lock()
	defer mu.Unlock()
	if len(ids) < 2 {
		t.Fatalf("%d calls", len(ids))
	}
	for _, id := range ids {
		if id != ids[0] || id == "" {
			t.Fatalf("result_id per call: %q", ids)
		}
	}
}

var resultIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// The field the server deduplicates by: 32 lowercase hex characters, new
// for every result.
func TestCheckHeadResultID(t *testing.T) {
	a := testUpdateAgent()
	seen := map[string]bool{}
	for range 100 {
		id := a.checkHead(rmm.CheckDef{CheckID: 3}).ResultID
		if !resultIDPattern.MatchString(id) || seen[id] {
			t.Fatalf("result_id %q (seen before: %v)", id, seen[id])
		}
		seen[id] = true
	}
	b, err := json.Marshal(CPUMemResult{resultHead: a.checkHead(rmm.CheckDef{CheckID: 3})})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if id, _ := body["result_id"].(string); !resultIDPattern.MatchString(id) {
		t.Fatalf("body %s", b)
	}
}
