// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// runFake is a transfer server for protocol-2 runs. It records every
// request and progress body and keeps the committed offset like the server.
type runFake struct {
	mu       sync.Mutex
	srv      *httptest.Server
	manifest imagingManifest
	// manifestStatus answers the manifest GET when set
	manifestStatus int
	known          map[string]bool
	offset         int64
	requests       []string
	patches        []map[string]any
	events         []string
	batches        []int
	puts           []string
	conflicts      int
	// progress answers a PATCH; nil is 200 {"cancel": false}
	progress func(body map[string]any) (int, string)
	// onProgress runs outside the lock before the answer
	onProgress     func()
	failPuts       int
	failParts      int
	loseParts      int
	conflictOffset int64
	// skewOffset is added to the offset of a parts answer
	skewOffset int64
	// refusal answers the begin request when set
	refusal string
	// onParts runs under the lock when a parts request arrives
	onParts func()
}

func newRunFake(t *testing.T) *runFake {
	f := &runFake{known: map[string]bool{}, conflictOffset: -1}
	f.manifest = imagingManifest{Image: "point", Agent: "agent", Direction: "capture", Mode: "internet", Codec: "none", Native: ImagingCapability{Method: "m"}}
	f.srv = httptest.NewTLSServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *runFake) transfer() *imagingTransfer {
	return &imagingTransfer{grant: imagingGrant{URL: f.srv.URL + "/", Token: "t", Mode: "internet", Image: "point"}, client: f.srv.Client()}
}

func (f *runFake) answer(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *runFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	path := strings.TrimPrefix(r.URL.Path, "/imaging/transfers/x")
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+path)
	if path == "/progress/" {
		var b map[string]any
		json.Unmarshal(body, &b)
		// the steps of the server's ProgressSerializer
		if step, ok := b["step"]; ok && !slices.Contains([]any{"snapshot", "scan", "transfer", "verify", "cleanup"}, step) {
			f.mu.Unlock()
			f.answer(w, http.StatusBadRequest, map[string]any{"step": []string{fmt.Sprintf("%q is not a valid choice.", step)}})
			return
		}
		f.patches = append(f.patches, b)
		status, answer := 200, `{"cancel": false}`
		if f.progress != nil {
			status, answer = f.progress(b)
		}
		hook := f.onProgress
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		w.WriteHeader(status)
		w.Write([]byte(answer))
		return
	}
	defer f.mu.Unlock()
	q := r.URL.Query()
	switch path {
	case "/":
		if f.manifestStatus != 0 {
			f.answer(w, f.manifestStatus, map[string]string{"detail": "Grant revoked."})
			return
		}
		m := f.manifest
		m.Offset = f.offset
		json.NewEncoder(w).Encode(m)
	case "/begin/":
		if f.refusal != "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(f.refusal))
			return
		}
		f.offset = 0
		w.WriteHeader(http.StatusNoContent)
	case "/parts/":
		var req struct {
			Parts []struct {
				I    int
				Size int64
				ID   string
			}
		}
		json.Unmarshal(body, &req)
		f.batches = append(f.batches, len(req.Parts))
		if f.onParts != nil {
			f.onParts()
		}
		if f.failParts > 0 {
			f.failParts--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if f.conflictOffset >= 0 || len(req.Parts) == 0 || int64(req.Parts[0].I) != f.offset/imagingBlock {
			f.conflicts++
			offset := f.offset
			if f.conflictOffset >= 0 {
				offset = f.conflictOffset
			}
			f.answer(w, http.StatusConflict, map[string]any{"detail": "Batch entries must continue at the committed block.", "offset": offset})
			return
		}
		missing := []int{}
		attached := 0
		for _, p := range req.Parts {
			// the server attaches only at the committed offset, as blocks.append_parts
			if len(missing) == 0 && f.known[p.ID] && int64(p.I)*imagingBlock == f.offset {
				f.offset += p.Size
				attached++
				continue
			}
			missing = append(missing, p.I)
		}
		if f.loseParts > 0 {
			f.loseParts--
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		f.answer(w, 200, map[string]any{"attached": attached, "missing": missing, "offset": f.offset + f.skewOffset})
	case "/part/":
		if q.Get("i") != fmt.Sprint(f.offset/imagingBlock) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var size int64
		fmt.Sscan(q.Get("size"), &size)
		digest := q.Get("sha256")
		if r.Method == http.MethodPost && !f.known[digest] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			if f.failPuts > 0 {
				f.failPuts--
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != digest {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.known[digest] = true
			f.puts = append(f.puts, q.Get("i"))
		}
		f.offset += size
		w.WriteHeader(http.StatusNoContent)
	case "/seal/":
		w.WriteHeader(http.StatusAccepted)
	}
}

func (f *runFake) event(e string) {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
}

func (f *runFake) snapshot() (events, requests []string, patches []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events), slices.Clone(f.requests), slices.Clone(f.patches)
}

// finals are the progress bodies that carried a final.
func finals(patches []map[string]any) []map[string]any {
	var out []map[string]any
	for _, p := range patches {
		if p["final"] != nil {
			out = append(out, p)
		}
	}
	return out
}

// collect gathers the entries of key over all progress bodies.
func collect(patches []map[string]any, key string) []map[string]any {
	var out []map[string]any
	for _, p := range patches {
		list, _ := p[key].([]any)
		for _, e := range list {
			out = append(out, e.(map[string]any))
		}
	}
	return out
}

// oneFinal is the status, reason and body of the only final.
func oneFinal(t *testing.T, patches []map[string]any) (string, string, map[string]any) {
	t.Helper()
	fs := finals(patches)
	if len(fs) != 1 {
		t.Fatalf("%d finals in %v", len(fs), patches)
	}
	status, reason := finalOf(fs[0])
	return status, reason, fs[0]
}

func finalOf(body map[string]any) (string, string) {
	f, _ := body["final"].(map[string]any)
	return fmt.Sprint(f["status"]), fmt.Sprint(f["reason"])
}

func stubImagingOnAC(t *testing.T, onAC, known bool) {
	old := imagingOnAC
	imagingOnAC = func() (bool, bool) { return onAC, known }
	t.Cleanup(func() { imagingOnAC = old })
}

// stubHooks runs no script: each hook ends with exit[name] and is recorded.
func stubHooks(t *testing.T, f *runFake, exit map[string]int) {
	old := imagingRunScript
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		f.event(h.Name)
		return "out of " + h.Name, "", exit[h.Name], nil
	}
	t.Cleanup(func() { imagingRunScript = old })
}

func hook(phase, name, onFail string) imagingHook {
	// the hash of the empty body, so the hook runs
	sum := sha256.Sum256([]byte("\x00"))
	return imagingHook{Phase: phase, Name: name, ScriptID: len(name), SHA256: hex.EncodeToString(sum[:]), Timeout: 60, OnFail: onFail}
}

// runFlow runs a sealed claim against f; the capture yields data.
func runFlow(t *testing.T, f *runFake, claim imagingClaim, data []byte) error {
	t.Helper()
	stubImagingProbe(t)
	return flowRun(flowAgent(t, f, data), f, claim)
}

// flowAgent stubs the capture and the progress period for flowRun.
func flowAgent(t *testing.T, f *runFake, data []byte) *Agent {
	oldEvery, oldCapture, oldWait := imagingProgressEvery, imagingStartCapture, pkgRetryWait
	imagingProgressEvery, pkgRetryWait = time.Hour, time.Millisecond
	imagingStartCapture = func(_ context.Context, c ImagingCapability) (io.ReadCloser, error) {
		f.event("capture:" + c.Priority)
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	t.Cleanup(func() { imagingProgressEvery, imagingStartCapture, pkgRetryWait = oldEvery, oldCapture, oldWait })
	a := testUpdateAgent()
	a.AgentID = "agent"
	return a
}

func flowRun(a *Agent, f *runFake, claim imagingClaim) error {
	claim.Run = "run-1"
	claim.RunConfig.Smart = "off"
	return a.imagingRunClaim(context.Background(), claim, f.transfer(), ImagingCapability{Method: "m", Ready: true})
}

// bareRun is a run without meter and transfer.
func bareRun(a *Agent, claim imagingClaim) *imagingRun {
	r := &imagingRun{a: a, claim: claim, done: make(chan struct{}), metered: make(chan struct{}), ended: make(chan struct{}), step: "snapshot"}
	r.ctx, r.cancel = context.WithCancelCause(context.Background())
	return r
}

func TestHookOrderAndPostAlways(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	claim := imagingClaim{Hooks: []imagingHook{hook("post-backup", "D", "abort"), hook("post-snapshot", "C", "abort"),
		hook("pre-snapshot", "B", "abort"), hook("pre-backup", "A", "abort")}}
	claim.RunConfig.Priority = "background"
	if err := runFlow(t, f, claim, []byte("data")); err != nil {
		t.Fatal(err)
	}
	events, requests, patches := f.snapshot()
	if !reflect.DeepEqual(events, []string{"A", "B", "capture:background", "C", "D"}) {
		t.Fatalf("order %v", events)
	}
	if len(finals(patches)) != 0 || !slices.Contains(requests, "POST /seal/") {
		t.Fatalf("a sealed run sent a final: %v", requests)
	}
	f = newRunFake(t)
	stubHooks(t, f, map[string]int{"B": 1, "C1": 1})
	claim.Hooks = []imagingHook{hook("pre-snapshot", "B", "abort"), hook("post-snapshot", "C1", "abort"), hook("post-snapshot", "C2", "abort"), hook("post-backup", "D", "abort")}
	if err := runFlow(t, f, claim, []byte("data")); err == nil {
		t.Fatal("a failed pre-snapshot hook did not fail the run")
	}
	events, _, patches = f.snapshot()
	if !reflect.DeepEqual(events, []string{"B", "C1", "C2", "D"}) {
		t.Fatalf("after a pre-snapshot abort: %v", events)
	}
	if fs := finals(patches); len(fs) != 1 {
		t.Fatalf("finals %v", fs)
	} else if status, reason := finalOf(fs[0]); status != "failed" || reason != "Hook B failed in pre-snapshot." {
		t.Fatalf("final %s %q", status, reason)
	}
}

func TestHookAbortFailsRun(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, map[string]int{"A": 3, "W": 1, "T": cmdTimeoutExit})
	timed := hook("pre-backup", "T", "warn")
	timed.Timeout = 0
	claim := imagingClaim{Hooks: []imagingHook{hook("pre-backup", "W", "warn"), timed, hook("pre-backup", "A", "abort"), hook("pre-backup", "X", "abort"),
		hook("pre-snapshot", "B", "abort"), hook("post-backup", "D", "abort")}}
	runFlow(t, f, claim, []byte("data"))
	events, requests, patches := f.snapshot()
	if !reflect.DeepEqual(events, []string{"W", "T", "A", "D"}) {
		t.Fatalf("hooks %v", events)
	}
	if slices.Contains(requests, "GET /") {
		t.Fatal("the run went on after a failed pre-backup hook")
	}
	if status, reason, _ := oneFinal(t, patches); status != "failed" || reason != "Hook A failed in pre-backup." {
		t.Fatalf("final %s %q", status, reason)
	}
	warnings := collect(patches, "warnings")
	if len(warnings) != 2 || warnings[0]["code"] != "hook" || warnings[0]["detail"] != "Hook W failed in pre-backup." || warnings[1]["detail"] != "Hook T timeout in pre-backup." {
		t.Fatalf("warnings %v", warnings)
	}
	results := collect(patches, "hooks")
	var statuses []string
	for _, r := range results {
		statuses = append(statuses, fmt.Sprint(r["phase"], " ", r["status"]))
	}
	if !reflect.DeepEqual(statuses, []string{"pre-backup failed", "pre-backup timeout", "pre-backup failed", "post-backup ok", "pre-backup skipped", "pre-snapshot skipped"}) ||
		results[0]["exit_code"] != 1.0 || results[0]["stdout"] != "out of W" || results[4]["script_id"] != 1.0 {
		t.Fatalf("results %v", results)
	}
}

func TestSuspendedHookAbort(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	s := hook("pre-backup", "S", "abort")
	s.Suspended = true
	runFlow(t, f, imagingClaim{Hooks: []imagingHook{s}}, []byte("data"))
	events, _, patches := f.snapshot()
	if status, reason, _ := oneFinal(t, patches); len(events) != 0 || status != "failed" || reason != "Hook S failed in pre-backup." {
		t.Fatalf("ran %v, final %s %q", events, status, reason)
	}
	if results := collect(patches, "hooks"); len(results) != 1 || results[0]["status"] != "suspended" {
		t.Fatalf("results %v", results)
	}
	f = newRunFake(t)
	stubHooks(t, f, nil)
	s.OnFail = "warn"
	if err := runFlow(t, f, imagingClaim{Hooks: []imagingHook{s}}, []byte("data")); err != nil {
		t.Fatal(err)
	}
	events, _, patches = f.snapshot()
	if w := collect(patches, "warnings"); len(events) != 1 || events[0] != "capture:" || len(w) != 1 || w[0]["detail"] != "Hook S suspended in pre-backup." {
		t.Fatalf("ran %v, warnings %v", events, w)
	}
}

func TestPostBackupHooksTravelWithFinal(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, map[string]int{"B": 1})
	claim := imagingClaim{Hooks: []imagingHook{hook("pre-snapshot", "B", "abort"), hook("post-backup", "D", "warn")}}
	runFlow(t, f, claim, []byte("data"))
	_, _, patches := f.snapshot()
	fs := finals(patches)
	if len(fs) != 1 {
		t.Fatalf("finals %v", fs)
	}
	hooks, _ := fs[0]["hooks"].([]any)
	if len(hooks) == 0 || hooks[len(hooks)-1].(map[string]any)["phase"] != "post-backup" {
		t.Fatalf("the final carried hooks %v", hooks)
	}
	f = newRunFake(t)
	stubHooks(t, f, nil)
	if err := runFlow(t, f, claim, []byte("data")); err != nil {
		t.Fatal(err)
	}
	_, requests, patches := f.snapshot()
	last := patches[len(patches)-1]
	hooks, _ = last["hooks"].([]any)
	seal := slices.Index(requests, "POST /seal/")
	if requests[len(requests)-1] != "PATCH /progress/" || seal < 0 || seal > len(requests)-2 || last["final"] != nil ||
		len(hooks) == 0 || hooks[len(hooks)-1].(map[string]any)["phase"] != "post-backup" {
		t.Fatalf("after the seal: %v, last %v", requests, last)
	}
}

func TestPatch409ResendsLogAndHooksOnly(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, map[string]int{"A": 1})
	f.progress = func(b map[string]any) (int, string) {
		if b["final"] != nil {
			return http.StatusConflict, `{"detail": "This run has ended."}`
		}
		return 200, `{"cancel": false}`
	}
	runFlow(t, f, imagingClaim{Hooks: []imagingHook{hook("pre-backup", "A", "abort"), hook("pre-snapshot", "B", "abort"), hook("post-backup", "D", "warn")}}, []byte("data"))
	_, _, patches := f.snapshot()
	at := slices.IndexFunc(patches, func(p map[string]any) bool { return p["final"] != nil })
	if at < 0 || at != len(patches)-2 || len(finals(patches)) != 1 {
		t.Fatalf("patches %v", patches)
	}
	resend := patches[len(patches)-1]
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range resend {
			if !yield(k) {
				return
			}
		}
	})
	hooks := resend["hooks"].([]any)
	if !reflect.DeepEqual(keys, []string{"hooks", "log", "run"}) || len(hooks) < 2 || hooks[len(hooks)-1].(map[string]any)["status"] != "skipped" {
		t.Fatalf("resend after 409: %v", resend)
	}
}

func TestPatch404Or403StopsWithoutRetry(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	f.manifestStatus = http.StatusForbidden
	if err := runFlow(t, f, imagingClaim{}, []byte("data")); err == nil {
		t.Fatal("a refused grant passed")
	}
	if _, _, patches := f.snapshot(); len(finals(patches)) != 0 {
		t.Fatalf("a final after 403: %v", patches)
	}
	f = newRunFake(t)
	stubHooks(t, f, map[string]int{"A": 1})
	f.progress = func(b map[string]any) (int, string) {
		if b["final"] != nil {
			return http.StatusNotFound, `{"detail": "Not found."}`
		}
		return 200, `{"cancel": false}`
	}
	runFlow(t, f, imagingClaim{Hooks: []imagingHook{hook("pre-backup", "A", "abort")}}, []byte("data"))
	_, _, patches := f.snapshot()
	if len(finals(patches)) != 1 || patches[len(patches)-1]["final"] == nil {
		t.Fatalf("after 404: %v", patches)
	}
	r := bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	r.answered(nil, http.StatusNotFound, &imagingStatusError{"progress/", http.StatusNotFound, ""}, imagingTaken{})
	if cause := context.Cause(r.ctx); cause == nil || imagingFinalFor(cause, "upload") != nil {
		t.Fatalf("a 404 progress answer: %v", cause)
	}
}

func TestFinalTable(t *testing.T) {
	a := testUpdateAgent()
	old := imagingDisks
	imagingDisks = func(*Agent) []HDisk { return []HDisk{{Name: "sda", Health: "failing", Smart: "failed"}} }
	t.Cleanup(func() { imagingDisks = old })
	smart := bareRun(a, imagingClaim{})
	smart.claim.RunConfig.Smart = "abort"
	hookRun := bareRun(a, imagingClaim{Hooks: []imagingHook{hook("post-snapshot", "Snap", "abort")}})
	f := newRunFake(t)
	stubHooks(t, f, map[string]int{"Snap": 1})
	lost := bareRun(a, imagingClaim{})
	paused := bareRun(a, imagingClaim{})
	paused.claim.RunConfig.PauseMaxMinutes = 30
	paused.netSince = time.Now().Add(-31 * time.Minute)
	stubImagingOnAC(t, false, true)
	battery := bareRun(a, imagingClaim{})
	battery.claim.RunConfig.PauseOnBattery, battery.claim.RunConfig.PauseMaxMinutes = true, 5
	battery.batterySince = time.Now().Add(-6 * time.Minute)
	battery.battery()
	stop := a.serverNowMs()
	window := bareRun(a, imagingClaim{StopAt: &stop})
	window.window()
	cancelled := bareRun(a, imagingClaim{Run: "r"})
	a.imaging.run = cancelled
	a.imagingCancel("r")
	long := strings.Repeat("x", 300)
	cause := func(r *imagingRun) error { return context.Cause(r.ctx) }
	for i, c := range []struct {
		err            error
		phase          string
		status, reason string
	}{
		{smart.smart(), "network", "failed", "SMART warning on sda: health failing, SMART failed"},
		{hookRun.runHooks("post-snapshot"), "capture", "failed", "Hook Snap failed in post-snapshot."},
		{fmt.Errorf("wbadmin: %s", long), "capture", "failed", "Capture failed: wbadmin: " + long[:191]},
		{&imagingStreamError{"walk broke"}, "capture", "failed", "Capture failed: imaging stream failed: walk broke"},
		{&imagingStatusError{"part/?i=3", 400, "Bad block."}, "upload", "failed", "The server refused the upload: 400 Bad block."},
		{&imagingStatusError{"parts/", 409, "Batch entries must continue at the committed block."}, "upload", "failed", "The server refused the upload: 409 Batch entries must continue at the committed block."},
		{&imagingStatusError{"part/?i=3", 507, "Full."}, "upload", "failed", "The server refused the upload: 507 Full."},
		{&imagingStatusError{"seal/", 400, "Digest mismatch."}, "upload", "failed", "The server refused the seal: 400 Digest mismatch."},
		{lost.netLost(context.Background()), "upload", "interrupted", "The network was lost."},
		{paused.netLost(context.Background()), "upload", "interrupted", "Paused longer than 30 minutes."},
		{cause(battery), "upload", "interrupted", "On battery longer than 5 minutes."},
		{cause(window), "upload", "interrupted", "The backup window ended."},
		{cause(cancelled), "upload", "cancelled", "Cancelled from the dashboard."},
	} {
		final := imagingFinalFor(c.err, c.phase)
		if final == nil || final.Status != c.status || final.Reason != c.reason {
			t.Errorf("row %d: %+v, want %s %q", i, final, c.status, c.reason)
		}
	}
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		if final := imagingFinalFor(&imagingStatusError{"", status, ""}, "upload"); final != nil {
			t.Errorf("%d sends %+v", status, final)
		}
	}
	// preflight and service stop go through the run itself
	f = newRunFake(t)
	flowA := flowAgent(t, f, nil)
	stubImagingProbe(t).notReady = true
	flowRun(flowA, f, imagingClaim{})
	_, _, patches := f.snapshot()
	if fs := finals(patches); len(fs) != 1 {
		t.Fatalf("preflight: %v", patches)
	} else if status, reason := finalOf(fs[0]); status != "failed" || reason != "The backup source is no longer ready: The backup source changed." {
		t.Fatalf("preflight: %s %q", status, reason)
	}
	f = newRunFake(t)
	r := bareRun(a, imagingClaim{Run: "r"})
	r.t = f.transfer()
	a.imaging.run = r
	oldWait := imagingStopWait
	imagingStopWait = 0
	t.Cleanup(func() { imagingStopWait = oldWait })
	a.imagingServiceStop()
	_, _, patches = f.snapshot()
	if status, reason, _ := oneFinal(t, patches); len(patches) != 1 || status != "interrupted" || reason != "The agent service stopped." ||
		context.Cause(r.ctx) == nil {
		t.Fatalf("service stop: %v", patches)
	}
}

func TestThrottleBucket(t *testing.T) {
	var b imagingBucket
	now := time.Unix(1000, 0)
	if w := b.take(now, 100, 1000); w != 0 {
		t.Fatalf("within the burst: %v", w)
	}
	if w := b.take(now, 1000, 1000); w != 100*time.Millisecond {
		t.Fatalf("deficit wait %v", w)
	}
	if w := b.take(now.Add(100*time.Millisecond), 0, 1000); w != 0 {
		t.Fatalf("after paying the deficit: %v", w)
	}
	if w := b.take(now, 1<<30, 0); w != 0 {
		t.Fatal("0 is unlimited")
	}
	zone := time.FixedZone("local", 3600)
	th := imagingThrottle{DefaultKbps: 7}
	for _, r := range []struct {
		days       []int
		start, end string
		kbps       int
	}{{[]int{1}, "08:00", "18:00", 2000}, {[]int{6}, "22:00", "06:00", 500}, {[]int{3}, "00:00", "00:00", 100}} {
		th.Rules = append(th.Rules, struct {
			Days  []int  `json:"days"`
			Start string `json:"start"`
			End   string `json:"end"`
			Kbps  int    `json:"kbps"`
		}{r.days, r.start, r.end, r.kbps})
	}
	for at, want := range map[string]int{
		"2026-11-23 09:00": 2000, "2026-11-23 18:00": 7, "2026-11-23 07:59": 7,
		"2026-11-28 23:00": 500, "2026-11-29 05:59": 500, "2026-11-29 06:00": 7, "2026-11-30 05:00": 7,
		"2026-11-25 12:00": 100, "2026-11-26 00:30": 7,
	} {
		now, _ := time.ParseInLocation("2006-01-02 15:04", at, zone)
		if got := imagingThrottleKbps(th, now); got != want {
			t.Errorf("%s: %d kbps, want %d", at, got, want)
		}
	}
	r := bareRun(testUpdateAgent(), imagingClaim{})
	r.claim.RunConfig.Throttle.DefaultKbps = 8 // 1000 bytes per second
	// a deficit of 12 days: no clock moves past it during the test
	r.bucket.take(time.Now(), 1<<30, 1000)
	r.cancel(imagingCancelled)
	if err := r.charge(r.ctx, 1000); err != imagingCancelled {
		t.Fatalf("a throttle wait outlived the run: %v", err)
	}
}

func TestNetworkPauseResume(t *testing.T) {
	old := imagingPauseEvery
	imagingPauseEvery = time.Millisecond
	t.Cleanup(func() { imagingPauseEvery = old })
	f := newRunFake(t)
	f.failParts = 7
	r := bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	r.claim.RunConfig.PauseMaxMinutes = 30
	tr := f.transfer()
	tr.run = r
	if err := tr.upload(r.ctx, f.manifest, strings.NewReader("block")); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	tries := f.batches
	f.mu.Unlock()
	body, _ := r.body(nil, false)
	log := strings.Join(body["log"].([]string), "\n")
	if len(tries) != 8 || body["state"] != "running" || !strings.Contains(log, "The network was lost; the upload pauses.") || !strings.Contains(log, "The network is back") {
		t.Fatalf("%d tries, state %v, log %s", len(tries), body["state"], log)
	}
	if err := r.netLost(r.ctx); err != nil {
		t.Fatal(err)
	}
	if body, _ := r.body(nil, false); body["state"] != "paused" || body["pause_reason"] != "network" {
		t.Fatalf("during the pause: %v %v", body["state"], body["pause_reason"])
	}
}

func TestPauseMaxInterrupts(t *testing.T) {
	r := bareRun(testUpdateAgent(), imagingClaim{})
	r.claim.RunConfig.PauseMaxMinutes = 1
	r.netSince = time.Now().Add(-2 * time.Minute)
	if err := r.netLost(context.Background()); err == nil || err.Error() != "Paused longer than 1 minutes." {
		t.Fatalf("network pause past the limit: %v", err)
	}
	stubImagingOnAC(t, false, true)
	r.claim.RunConfig.PauseOnBattery = true
	r.batterySince = time.Now().Add(-30 * time.Second)
	r.battery()
	if cause := context.Cause(r.ctx); cause != nil {
		t.Fatalf("interrupted inside the limit: %v", cause)
	}
	r.batterySince = time.Now().Add(-2 * time.Minute)
	r.battery()
	if cause := context.Cause(r.ctx); cause == nil || cause.Error() != "On battery longer than 1 minutes." {
		t.Fatalf("battery pause past the limit: %v", cause)
	}
}

func TestStopAtInterrupts(t *testing.T) {
	a := testUpdateAgent()
	// the server clock is an hour ahead of this one
	a.sec2.offset.Store(time.Hour.Milliseconds())
	stop := time.Now().Add(30 * time.Minute).UnixMilli()
	r := bareRun(a, imagingClaim{StopAt: &stop})
	r.window()
	if cause := context.Cause(r.ctx); cause == nil || cause.Error() != "The backup window ended." {
		t.Fatalf("stop_at on the server clock: %v", cause)
	}
	later := a.serverNowMs() + time.Hour.Milliseconds()
	r = bareRun(a, imagingClaim{StopAt: &later})
	r.window()
	if context.Cause(r.ctx) != nil {
		t.Fatal("interrupted before stop_at")
	}
	sealed := a.serverNowMs() - 1
	r = bareRun(a, imagingClaim{StopAt: &sealed})
	r.sealed = true
	r.window()
	if context.Cause(r.ctx) != nil {
		t.Fatal("a sealed run was interrupted")
	}
}

func TestWindowWarningOnceTenMinutesBefore(t *testing.T) {
	a := testUpdateAgent()
	far := a.serverNowMs() + 11*time.Minute.Milliseconds()
	r := bareRun(a, imagingClaim{StopAt: &far})
	r.window()
	if len(r.warnings) != 0 {
		t.Fatalf("warned 11 minutes before: %v", r.warnings)
	}
	near := a.serverNowMs() + 9*time.Minute.Milliseconds()
	r.claim.StopAt = &near
	r.window()
	r.window()
	want := "The backup window ends at " + time.UnixMilli(near).UTC().Format("15:04") + " UTC."
	if len(r.warnings) != 1 || r.warnings[0] != (imagingWarning{"window", want}) || context.Cause(r.ctx) != nil {
		t.Fatalf("warnings %v", r.warnings)
	}
}

func TestBatteryDeferAndPause(t *testing.T) {
	a := testUpdateAgent()
	a.imaging.config = imagingConfig{raw: []byte("{}"), status: "applied", doc: imagingDoc{OnBattery: "defer", ScheduleEvents: []string{"ac_connected"}}}
	for _, c := range []struct {
		onAC, known bool
		ac          any
		deferred    string
	}{{false, true, false, "on_battery"}, {true, true, true, ""}, {false, false, nil, ""}} {
		stubImagingOnAC(t, c.onAC, c.known)
		report, _ := a.imagingReport(ImagingCapability{})
		if ac := report["conditions"].(map[string]any)["on_ac"]; ac != c.ac || report["deferred"] != c.deferred {
			t.Errorf("on AC %v known %v: on_ac %v, deferred %q", c.onAC, c.known, ac, report["deferred"])
		}
	}
	a.imaging.config.doc.OnBattery = "run"
	stubImagingOnAC(t, false, true)
	if report, _ := a.imagingReport(ImagingCapability{}); report["deferred"] != "" {
		t.Fatal("deferred with on_battery run")
	}
	drainImagingWake()
	if a.imagingACStep(false) != true || len(a.imaging.events) != 0 {
		t.Fatal("an event without a change to AC")
	}
	stubImagingOnAC(t, true, true)
	if a.imagingACStep(true) || !reflect.DeepEqual(a.imaging.events, []string{"ac_connected"}) {
		t.Fatalf("events %v", a.imaging.events)
	}
	select {
	case <-imagingWake:
	default:
		t.Fatal("no poll after AC came back")
	}
	old := imagingGateEvery
	imagingGateEvery = time.Millisecond
	t.Cleanup(func() { imagingGateEvery = old })
	r := bareRun(a, imagingClaim{})
	r.claim.RunConfig.PauseOnBattery, r.claim.RunConfig.PauseMaxMinutes = true, 30
	stubImagingOnAC(t, false, true)
	r.battery()
	if body, _ := r.body(nil, false); body["state"] != "paused" || body["pause_reason"] != "battery" {
		t.Fatalf("on battery: %v %v", body["state"], body["pause_reason"])
	}
	passed := make(chan error, 1)
	go func() { passed <- r.gate() }()
	select {
	case <-passed:
		t.Fatal("the upload went on during a battery pause")
	case <-time.After(20 * time.Millisecond):
	}
	stubImagingOnAC(t, true, true)
	r.battery()
	if err := <-passed; err != nil {
		t.Fatal(err)
	}
	r = bareRun(a, imagingClaim{})
	r.claim.RunConfig.PauseOnBattery = true
	stubImagingOnAC(t, false, true)
	r.battery()
	if cause := context.Cause(r.ctx); cause == nil || cause.Error() != "On battery longer than 0 minutes." {
		t.Fatalf("pause limit 0: %v", cause)
	}
}

func TestCancelRPC(t *testing.T) {
	a := testUpdateAgent()
	r := bareRun(a, imagingClaim{Run: "run-1"})
	a.imaging.run = r
	req := &rpcReq{a: a, msg: &nats.Msg{}, p: &NatsMsg{Func: "imagingcancel", Data: payloadMap{"run": "run-2"}}}
	req.run()
	if !req.replied || context.Cause(r.ctx) != nil || a.imagingCancel("") {
		t.Fatal("another run was cancelled")
	}
	req = &rpcReq{a: a, msg: &nats.Msg{}, p: &NatsMsg{Func: "imagingcancel", Data: payloadMap{"run": "run-1"}}}
	req.run()
	if !req.replied || context.Cause(r.ctx) != imagingCancelled {
		t.Fatalf("cancel: %v", context.Cause(r.ctx))
	}
	a.imaging.run = nil
	if a.imagingCancel("run-1") {
		t.Fatal("a finished run counts as running")
	}
	r = bareRun(a, imagingClaim{Run: "run-1"})
	r.answered([]byte(`{"cancel": true}`), 200, nil, imagingTaken{})
	if context.Cause(r.ctx) != imagingCancelled {
		t.Fatal("the cancel flag of a progress answer was ignored")
	}
}

func TestProgressMeterDropsWhileInFlight(t *testing.T) {
	f := newRunFake(t)
	r := bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	r.t = f.transfer()
	r.logf("first line")
	arrived, release := make(chan struct{}, 8), make(chan struct{})
	f.onProgress = func() {
		arrived <- struct{}{}
		<-release
	}
	// a ticker channel: one tick waits, the others are dropped
	tick := make(chan time.Time, 1)
	go r.meter(tick)
	<-arrived
	for range 50 {
		select {
		case tick <- time.Now():
		default:
		}
	}
	close(release)
	<-arrived
	close(r.done)
	<-r.metered
	_, _, patches := f.snapshot()
	if len(patches) != 2 || len(patches[0]["log"].([]any)) != 1 || len(patches[1]["log"].([]any)) != 0 {
		t.Fatalf("%d PATCHes: %v", len(patches), patches)
	}
}

func TestHooksStopAfterCancel(t *testing.T) {
	f := newRunFake(t)
	r := bareRun(testUpdateAgent(), imagingClaim{Run: "r", Hooks: []imagingHook{hook("pre-backup", "A", "abort"), hook("pre-backup", "B", "abort"),
		hook("pre-snapshot", "C", "warn"), hook("post-backup", "D", "warn")}})
	old := imagingRunScript
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		f.event(h.Name)
		if h.Name == "A" {
			r.cancel(imagingCancelled)
		}
		return "", "", 0, nil
	}
	t.Cleanup(func() { imagingRunScript = old })
	if err := r.runHooks("pre-backup"); err != imagingCancelled {
		t.Fatalf("pre-backup after a cancel: %v", err)
	}
	if err := r.runHooks("pre-snapshot"); err != imagingCancelled {
		t.Fatalf("pre-snapshot after a cancel: %v", err)
	}
	r.runHooks("post-backup")
	r.reportRest(false)
	events, _, _ := f.snapshot()
	var got []string
	for _, h := range r.hooks {
		got = append(got, h.Phase+" "+h.Status)
	}
	if !reflect.DeepEqual(events, []string{"A", "D"}) || !reflect.DeepEqual(got, []string{"pre-backup ok", "post-backup ok", "pre-backup skipped", "pre-snapshot skipped"}) {
		t.Fatalf("ran %v, results %v", events, got)
	}
}

func TestServiceStopWaitsForPostHooks(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	entered := make(chan struct{})
	imagingStartCapture = func(ctx context.Context, _ ImagingCapability) (io.ReadCloser, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("post-backup", "D", "warn")}}) }()
	<-entered
	a.imagingServiceStop()
	<-done
	_, _, patches := f.snapshot()
	fs := finals(patches)
	if len(fs) != 1 {
		t.Fatalf("finals %v", fs)
	}
	hooks, _ := fs[0]["hooks"].([]any)
	if status, reason := finalOf(fs[0]); status != "interrupted" || reason != "The agent service stopped." || len(hooks) != 1 || hooks[0].(map[string]any)["status"] != "ok" {
		t.Fatalf("final %s %q, hooks %v", status, reason, hooks)
	}
}

func TestMeterRunsDuringPostHooks(t *testing.T) {
	f := newRunFake(t)
	cleanup := make(chan struct{})
	var once sync.Once
	f.progress = func(b map[string]any) (int, string) {
		if b["step"] == "cleanup" {
			once.Do(func() { close(cleanup) })
		}
		return 200, `{"cancel": false}`
	}
	old := imagingRunScript
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		select {
		case <-cleanup:
			return "", "", 0, nil
		case <-time.After(10 * time.Second):
			return "", "no progress while the hook ran", 1, nil
		}
	}
	t.Cleanup(func() { imagingRunScript = old })
	stubImagingProbe(t)
	a := flowAgent(t, f, []byte("data"))
	imagingProgressEvery = time.Millisecond
	if err := flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("post-backup", "D", "warn")}}); err != nil {
		t.Fatal(err)
	}
	_, _, patches := f.snapshot()
	if results := collect(patches, "hooks"); len(results) != 1 || results[0]["status"] != "ok" {
		t.Fatalf("results %v", results)
	}
}

// brokenStream is a typed nil that the Linux start gives with its error.
type brokenStream struct{ io.Reader }

func (s *brokenStream) Read(p []byte) (int, error) { return s.Reader.Read(p) }
func (s *brokenStream) Close() error               { _ = s.Reader; return nil }

func TestCapturePanicEndsRun(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	imagingStartCapture = func(context.Context, ImagingCapability) (io.ReadCloser, error) { panic("boom") }
	claim := imagingClaim{Hooks: []imagingHook{hook("post-backup", "D", "warn")}}
	if err := flowRun(a, f, claim); err == nil {
		t.Fatal("a panic ended the run without an error")
	}
	events, _, patches := f.snapshot()
	if status, reason, _ := oneFinal(t, patches); status != "failed" || reason != "Agent error during the backup: boom" || !slices.Contains(events, "D") || a.imaging.run != nil {
		t.Fatalf("final %s %q, hooks %v", status, reason, events)
	}
	f = newRunFake(t)
	stubHooks(t, f, nil)
	imagingStartCapture = func(context.Context, ImagingCapability) (io.ReadCloser, error) {
		return (*brokenStream)(nil), errors.New("child failed")
	}
	flowRun(a, f, claim)
	_, _, patches = f.snapshot()
	if fs := finals(patches); len(fs) != 1 {
		t.Fatalf("finals %v", fs)
	} else if _, reason := finalOf(fs[0]); reason != "Capture failed: child failed" {
		t.Fatalf("a failed start with a typed nil stream: %q", reason)
	}
}

func TestFinalReasonClipped(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, map[string]int{strings.Repeat("ä", 300): 1})
	runFlow(t, f, imagingClaim{Hooks: []imagingHook{hook("pre-backup", strings.Repeat("ä", 300), "abort")}}, nil)
	_, _, patches := f.snapshot()
	_, reason, _ := oneFinal(t, patches)
	if n := len([]rune(reason)); n != imagingReasonMax || !strings.HasPrefix(reason, "Hook ää") {
		t.Fatalf("reason of %d characters: %q", n, reason)
	}
}

func TestClaimFailureBeforeRun(t *testing.T) {
	a, f := imagingFakeAgent(t)
	rf := newRunFake(t)
	stubHooks(t, rf, nil)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rf.srv.Certificate().Raw}), 0o600)
	a.Cert = ca
	claim := func(change map[string]any) []byte {
		c := map[string]any{"url": rf.srv.URL + "/imaging/transfers/x/", "token": "t", "claim": "c1", "image_id": "point", "network_mode": "internet",
			"run": "run-1", "hooks": []imagingHook{hook("post-backup", "D", "warn")}}
		maps.Copy(c, change)
		b, _ := json.Marshal(c)
		return b
	}
	f.status, f.seal, f.header, f.version, f.doc, f.grant = 200, true, "1", 1, imagingTestDoc(t, a.AgentID, nil), claim(nil)
	updateRunning.Store(true)
	err := a.imagingPoll(context.Background(), ImagingCapability{})
	updateRunning.Store(false)
	_, _, patches := rf.snapshot()
	fs := finals(patches)
	if err == nil || len(fs) != 1 || len(f.polls) != 1 {
		t.Fatalf("during an update: %v, finals %v, polls %d", err, fs, len(f.polls))
	}
	hooks, _ := fs[0]["hooks"].([]any)
	if status, reason := finalOf(fs[0]); status != "interrupted" || reason != "The agent is being updated; the backup runs again after the update." ||
		len(hooks) != 1 || hooks[0].(map[string]any)["status"] != "skipped" {
		t.Fatalf("final %s %q, hooks %v", status, reason, hooks)
	}
	for what, grant := range map[string][]byte{"transfer": claim(map[string]any{"url": "http://rmm/imaging/transfers/x/"}), "decode": claim(map[string]any{"run": 5})} {
		f.grant = grant
		if err := a.imagingPoll(context.Background(), ImagingCapability{}); err == nil {
			t.Fatalf("%s: no error", what)
		}
		if report := f.lastPoll(); report["claim"] != "c1" || report["failure"] != "network" || report["image_id"] != "point" {
			t.Fatalf("%s: report %v", what, report)
		}
	}
}

func TestRefusalListDetail(t *testing.T) {
	f := newRunFake(t)
	f.refusal = `["Upload exceeded the approved source size."]`
	err := f.transfer().upload(context.Background(), f.manifest, strings.NewReader("block"))
	if final := imagingFinalFor(err, "upload"); final == nil || final.Reason != "The server refused the upload: 400 Upload exceeded the approved source size." {
		t.Fatalf("refusal as a list: %v", err)
	}
}

func TestPartsOffsetMustMatch(t *testing.T) {
	f := newRunFake(t)
	f.known[blockID([]byte("block"))] = true
	f.skewOffset = 1
	tr := f.transfer()
	tr.run = bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	err := tr.upload(context.Background(), f.manifest, strings.NewReader("block"))
	_, requests, _ := f.snapshot()
	if err == nil || err.Error() != "the server attached the batch to offset 6 instead of 5" || slices.Contains(requests, "POST /seal/") {
		t.Fatalf("a batch answer with another offset: %v", err)
	}
}

func TestBatterySampledByTime(t *testing.T) {
	old := imagingBatteryEvery
	t.Cleanup(func() { imagingBatteryEvery = old })
	for every, want := range map[time.Duration]int{time.Hour: 1, 0: 7} {
		imagingBatteryEvery = every
		calls := 0
		oldAC := imagingOnAC
		imagingOnAC = func() (bool, bool) {
			calls++
			return true, true
		}
		f := newRunFake(t)
		arrived := make(chan struct{}, 8)
		f.onProgress = func() { arrived <- struct{}{} }
		r := bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
		r.t, r.claim.RunConfig.PauseOnBattery = f.transfer(), true
		tick := make(chan time.Time, 1)
		go r.meter(tick)
		for range 6 {
			<-arrived
			tick <- time.Now()
		}
		<-arrived
		close(r.done)
		<-r.metered
		imagingOnAC = oldAC
		if calls != want {
			t.Errorf("sampled every %v: %d samples over 7 reports, want %d", every, calls, want)
		}
	}
}

func TestGateBeforePut(t *testing.T) {
	f := newRunFake(t)
	r := bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	f.onParts = func() {
		r.mu.Lock()
		r.batterySince = time.Now()
		r.mu.Unlock()
		r.cancel(imagingCancelled)
	}
	tr := f.transfer()
	tr.run = r
	// the requests do not see the cancel, only the gate of the run does
	err := tr.upload(context.Background(), f.manifest, strings.NewReader("block"))
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != imagingCancelled || len(f.puts) != 0 {
		t.Fatalf("a PUT during a battery pause: %v, puts %v", err, f.puts)
	}
}

func TestPostSnapshotAfterCapturePanic(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	imagingStartCapture = func(context.Context, ImagingCapability) (io.ReadCloser, error) { panic("boom") }
	flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("pre-snapshot", "B", "abort"), hook("post-snapshot", "C", "abort"), hook("post-backup", "D", "warn")}})
	events, _, patches := f.snapshot()
	var got []string
	for _, h := range collect(patches, "hooks") {
		got = append(got, fmt.Sprint(h["phase"], " ", h["status"]))
	}
	if !reflect.DeepEqual(events, []string{"B", "C", "D"}) || !reflect.DeepEqual(got, []string{"pre-snapshot ok", "post-snapshot ok", "post-backup ok"}) {
		t.Fatalf("ran %v, results %v", events, got)
	}
}

func TestFinishRecoversPostHookPanic(t *testing.T) {
	f := newRunFake(t)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	old := imagingRunScript
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) { panic("hook broke") }
	t.Cleanup(func() { imagingRunScript = old })
	s := hook("pre-backup", "S", "abort")
	s.Suspended = true
	if err := flowRun(a, f, imagingClaim{Hooks: []imagingHook{s, hook("post-backup", "D", "warn"), hook("post-backup", "E", "warn")}}); err == nil {
		t.Fatal("no error after a panic in a post hook")
	}
	_, _, patches := f.snapshot()
	status, reason, body := oneFinal(t, patches)
	var got []string
	for _, h := range body["hooks"].([]any) {
		got = append(got, fmt.Sprint(h.(map[string]any)["phase"], " ", h.(map[string]any)["status"]))
	}
	if status != "failed" || reason != "Agent error during the backup: hook broke" || a.imaging.run != nil ||
		!reflect.DeepEqual(got[len(got)-2:], []string{"post-backup failed", "post-backup skipped"}) {
		t.Fatalf("final %s %q, hooks %v", status, reason, got)
	}
}

func TestStopDeadlineNoSecondFinal(t *testing.T) {
	f := newRunFake(t)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	entered, started, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	imagingStartCapture = func(ctx context.Context, _ ImagingCapability) (io.ReadCloser, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	old, oldWait := imagingRunScript, imagingStopWait
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		if h.Name == "D" {
			close(started)
			<-release
		}
		return "", "", 0, nil
	}
	imagingStopWait = 0
	t.Cleanup(func() { imagingRunScript, imagingStopWait = old, oldWait })
	done := make(chan error, 1)
	go func() {
		done <- flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("post-snapshot", "C", "warn"), hook("post-backup", "D", "warn"), hook("post-backup", "E", "warn")}})
	}()
	<-entered
	a.imagingCancel("run-1")
	<-started
	// D still runs at the deadline: the stop sends the final itself
	a.imagingServiceStop()
	close(release)
	<-done
	_, _, patches := f.snapshot()
	status, reason, body := oneFinal(t, patches)
	hooks := body["hooks"].([]any)
	var got []string
	for _, h := range hooks {
		got = append(got, fmt.Sprint(h.(map[string]any)["phase"], " ", h.(map[string]any)["status"]))
	}
	at := slices.Index(got, "post-backup failed")
	if status != "interrupted" || reason != "The agent service stopped." || at < 0 || got[len(got)-1] != "post-backup skipped" ||
		hooks[at].(map[string]any)["stderr"] != "The agent service stopped while this hook ran; the script was left running." || patches[len(patches)-1]["final"] == nil {
		t.Fatalf("final %s %q, hooks %v, patches %v", status, reason, got, patches)
	}
}

func TestHookHashChecked(t *testing.T) {
	f := newRunFake(t)
	stubHooks(t, f, nil)
	h := hook("pre-backup", "A", "abort")
	// script_hash of the server for this shell and code
	h.Shell, h.Code, h.SHA256 = "powershell", "Write-Output 'Grüße'\r\n", "5469def1e8910b6d6e9247eadf96ad43ca96dbaefc5a5f76e28d497b5238be72"
	r := bareRun(testUpdateAgent(), imagingClaim{Run: "r", Hooks: []imagingHook{h}})
	if res := r.hook(0, h); res.Status != "ok" {
		t.Fatalf("the approved body: %+v", res)
	}
	h.Code += "Remove-Item C:\\Data -Recurse\r\n"
	res := r.hook(0, h)
	if events, _, _ := f.snapshot(); len(events) != 1 || res.Status != "failed" || res.Stderr != "The script does not match its approved hash; it was not run." {
		t.Fatalf("a changed body: ran %v, %+v", events, res)
	}
}

func TestSealedRunReportsPanickedPostHook(t *testing.T) {
	f := newRunFake(t)
	old := imagingRunScript
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		if h.Name == "D" {
			panic("hook broke")
		}
		return "", "", 0, nil
	}
	t.Cleanup(func() { imagingRunScript = old })
	claim := imagingClaim{Hooks: []imagingHook{hook("pre-backup", "A", "abort"), hook("post-backup", "D", "warn"), hook("post-backup", "E", "warn")}}
	if err := runFlow(t, f, claim, []byte("data")); err != nil {
		t.Fatal(err)
	}
	_, requests, patches := f.snapshot()
	var got []string
	for _, h := range collect(patches, "hooks") {
		got = append(got, fmt.Sprint(h["phase"], " ", h["status"]))
	}
	if !slices.Contains(requests, "POST /seal/") || len(finals(patches)) != 0 || !reflect.DeepEqual(got, []string{"pre-backup ok", "post-backup failed", "post-backup skipped"}) {
		t.Fatalf("results %v, requests %v", got, requests)
	}
}

func TestServiceStopWaitsForFinalOnWire(t *testing.T) {
	f := newRunFake(t)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	entered, started, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	imagingStartCapture = func(ctx context.Context, _ ImagingCapability) (io.ReadCloser, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	old, oldWait := imagingRunScript, imagingStopWait
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		close(started)
		<-release
		return "", "", 0, nil
	}
	imagingStopWait = 200 * time.Millisecond
	t.Cleanup(func() { imagingRunScript, imagingStopWait = old, oldWait })
	sending, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.onProgress = func() {
		if _, _, patches := f.snapshot(); patches[len(patches)-1]["final"] != nil {
			once.Do(func() { close(sending) })
			<-unblock
		}
	}
	done := make(chan error, 1)
	go func() { done <- flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("post-backup", "D", "warn")}}) }()
	<-entered
	stopped := make(chan struct{})
	go func() {
		a.imagingServiceStop()
		close(stopped)
	}()
	// the stop has the run: its cancel started the post hook
	<-started
	close(release)
	<-sending
	early := false
	select {
	case <-stopped:
		early = true
	case <-time.After(2 * imagingStopWait):
	}
	close(unblock)
	if early {
		t.Fatal("the stop returned while the final of the run was on the wire")
	}
	<-stopped
	<-done
	_, _, patches := f.snapshot()
	if status, reason, _ := oneFinal(t, patches); status != "interrupted" || reason != "The agent service stopped." {
		t.Fatalf("final %s %q", status, reason)
	}
}

func TestServiceStopKeepsSealedRunReport(t *testing.T) {
	f := newRunFake(t)
	stubImagingProbe(t)
	a := flowAgent(t, f, []byte("data"))
	started, release := make(chan struct{}), make(chan struct{})
	old, oldWait := imagingRunScript, imagingStopWait
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) {
		close(started)
		<-release
		return "", "", 0, nil
	}
	imagingStopWait = 50 * time.Millisecond
	t.Cleanup(func() { imagingRunScript, imagingStopWait = old, oldWait })
	done := make(chan error, 1)
	go func() { done <- flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("post-backup", "D", "warn")}}) }()
	<-started
	stopped := make(chan struct{})
	go func() {
		a.imagingServiceStop()
		close(stopped)
	}()
	// past the wait of the stop, inside its budget
	time.Sleep(3 * imagingStopWait)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-stopped
	_, requests, patches := f.snapshot()
	hooks, _ := patches[len(patches)-1]["hooks"].([]any)
	if !slices.Contains(requests, "POST /seal/") || len(finals(patches)) != 0 || len(hooks) != 1 || hooks[0].(map[string]any)["status"] != "ok" {
		t.Fatalf("after a stop during the post hooks of a sealed run: %v", patches)
	}
}

func TestServiceStopFindsRunSendingFinal(t *testing.T) {
	f := newRunFake(t)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	entered := make(chan struct{})
	imagingStartCapture = func(ctx context.Context, _ ImagingCapability) (io.ReadCloser, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	oldWait := imagingStopWait
	imagingStopWait = 50 * time.Millisecond
	t.Cleanup(func() { imagingStopWait = oldWait })
	sending, unblock := make(chan struct{}), make(chan struct{})
	f.onProgress = func() {
		if _, _, patches := f.snapshot(); patches[len(patches)-1]["final"] != nil {
			close(sending)
			<-unblock
		}
	}
	done := make(chan error, 1)
	go func() { done <- flowRun(a, f, imagingClaim{}) }()
	<-entered
	a.imagingCancel("run-1")
	<-sending
	stopped := make(chan struct{})
	go func() {
		a.imagingServiceStop()
		close(stopped)
	}()
	early := false
	select {
	case <-stopped:
		early = true
	case <-time.After(3 * imagingStopWait):
	}
	close(unblock)
	if early {
		t.Fatal("the stop did not find the run whose final was on the wire")
	}
	<-stopped
	<-done
	_, _, patches := f.snapshot()
	if status, _, _ := oneFinal(t, patches); status != "cancelled" || a.imaging.run != nil {
		t.Fatalf("final %s, run %v", status, a.imaging.run)
	}
}

func TestPostSnapshotPanicClosesStream(t *testing.T) {
	f := newRunFake(t)
	stubImagingProbe(t)
	a := flowAgent(t, f, nil)
	pr, pw := io.Pipe()
	pw.Close()
	imagingStartCapture = func(context.Context, ImagingCapability) (io.ReadCloser, error) { return pr, nil }
	old := imagingRunScript
	imagingRunScript = func(_ *Agent, h imagingHook, _ bool, _ string) (string, string, int, error) { panic("hook broke") }
	t.Cleanup(func() { imagingRunScript = old })
	flowRun(a, f, imagingClaim{Hooks: []imagingHook{hook("post-snapshot", "C", "warn")}})
	// a reader closed by the capture answers ErrClosedPipe, an open one EOF
	if _, err := pr.Read(nil); err != io.ErrClosedPipe {
		t.Fatalf("the capture stream was left open: %v", err)
	}
}
