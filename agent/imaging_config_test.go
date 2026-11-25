// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

type imagingVector struct {
	Document  map[string]any `json:"document"`
	Canonical string         `json:"canonical"`
	SHA256    string         `json:"sha256"`
}

// the server renders the same file; both copies must stay byte-identical
func loadImagingVectors(t *testing.T) []imagingVector {
	t.Helper()
	b, err := os.ReadFile("testdata/imaging_config_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []imagingVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// imagingTestDoc is the builtin-defaults vector for agentID with change applied.
func imagingTestDoc(t *testing.T, agentID string, change map[string]any) string {
	t.Helper()
	doc := maps.Clone(loadImagingVectors(t)[0].Document)
	doc["agent_id"] = agentID
	maps.Copy(doc, change)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConfigVectorsFile(t *testing.T) {
	vectors := loadImagingVectors(t)
	if len(vectors) < 4 {
		t.Fatalf("%d vectors", len(vectors))
	}
	nonASCII := false
	for i, v := range vectors {
		raw := []byte(v.Canonical)
		if got := hashHex(raw); got != v.SHA256 {
			t.Errorf("vector %d: sha256 %s, want %s", i, got, v.SHA256)
		}
		nonASCII = nonASCII || strings.ContainsFunc(v.Canonical, func(r rune) bool { return r > 127 })
		doc, errs := parseImagingDoc(raw, v.Document["agent_id"].(string))
		if len(errs) != 0 || doc.NetworkMode != v.Document["network_mode"] {
			t.Errorf("vector %d: %+v %v", i, doc, errs)
		}
		var back map[string]any
		if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, v.Document) {
			t.Errorf("vector %d: canonical text and document differ: %v", i, err)
		}
	}
	if !nonASCII {
		t.Error("no vector holds non-ASCII text")
	}
}

// imagingFake answers the poll and the config fetch like a delivery-1
// server, sealed to the vector identity when seal is set.
type imagingFake struct {
	t       *testing.T
	a       *Agent
	cmd     ed25519.PrivateKey
	mu      sync.Mutex
	header  string
	seal    bool
	status  int
	grant   []byte
	version int
	doc     string
	polls   []map[string]any
	fetches int
	// redirect moves every other request to this path, which answers with grant
	redirect string
	// fetchErr fails the config fetch in transit; badSeal signs it for another path
	fetchErr error
	badSeal  bool
}

func (f *imagingFake) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, body := f.status, f.grant
	h := http.Header{}
	switch {
	case f.redirect != "" && r.URL.Path == f.redirect:
		status = 200
	case f.redirect != "":
		if r.Method == http.MethodPost {
			f.polls = append(f.polls, nil)
		}
		status = http.StatusFound
		h.Set("Location", "https://rmm"+f.redirect)
	case r.Method == http.MethodGet:
		f.fetches++
		if f.fetchErr != nil {
			return nil, f.fetchErr
		}
		status = 200
		body, _ = json.Marshal(map[string]any{"version": f.version, "document": f.doc})
	default:
		var report map[string]any
		json.NewDecoder(r.Body).Decode(&report)
		f.polls = append(f.polls, report)
	}
	if f.header != "" {
		h.Set(imagingConfigHeader, f.header)
	}
	if f.seal && status == 200 && r.Header.Get(sealAsk) == "1" {
		path := r.URL.Path
		if f.badSeal && r.Method == http.MethodGet {
			path = "/api/v3/other/imaging/config/"
		}
		body = sealAnswer(f.t, f.a, f.cmd, path, body)
		h.Set(sealMarker, "1")
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

func (f *imagingFake) lastPoll() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls[len(f.polls)-1]
}

// imagingFakeAgent is the registered, armed vector agent talking to an
// imagingFake that answers 204 without a version until told otherwise.
func imagingFakeAgent(t *testing.T) (*Agent, *imagingFake) {
	a, cmd := sec2Agent(t, loadVectors(t))
	f := &imagingFake{t: t, a: a, cmd: cmd, status: 204}
	stubImagingOnAC(t, false, false)
	a.BaseURL = "https://rmm"
	a.rClient = resty.New().SetBaseURL("https://rmm").SetTransport(&sealTransport{base: f, a: a})
	drainImagingWake()
	return a, f
}

func imagingPollOnce(t *testing.T, a *Agent) {
	t.Helper()
	if err := a.imagingPoll(context.Background(), ImagingCapability{Method: "m", Ready: true}); err != nil {
		t.Fatal(err)
	}
}

func imagingConfigNow(a *Agent) imagingConfig {
	a.imaging.mu.Lock()
	defer a.imaging.mu.Unlock()
	return a.imaging.config
}

func TestConfigHashExactBytes(t *testing.T) {
	a, f := imagingFakeAgent(t)
	doc := imagingTestDoc(t, a.AgentID, nil)
	// spacing, <, & and non-ASCII text that a re-encoding would change
	doc = "{ " + strings.Replace(doc[1:], `"name":"images"`, `"name" : "Büro <A&B>"`, 1)
	f.header, f.seal, f.version, f.doc = "3", true, 3, doc
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); c.status != "applied" || c.hash != hashHex([]byte(doc)) || !bytes.Equal(c.raw, []byte(doc)) || !bytes.Contains(c.raw, []byte(`"name" : "Büro <A&B>"`)) {
		t.Fatalf("status %s hash %s errors %v", c.status, c.hash, c.errors)
	}
}

func TestConfigValidationTable(t *testing.T) {
	const id = "agent-1"
	hook := func(k string, v any) []map[string]any {
		h := map[string]any{"phase": "pre-backup", "script_id": 1, "sha256": strings.Repeat("a", 64), "timeout": 300, "on_fail": "abort"}
		h[k] = v
		return []map[string]any{h}
	}
	rule := func(k string, v any) map[string]any {
		r := map[string]any{"days": []int{1}, "start": "08:00", "end": "18:00", "kbps": 1}
		r[k] = v
		return map[string]any{"default_kbps": 0, "rules": []any{r}}
	}
	for _, c := range []struct {
		key            string
		value          any
		field, message string
	}{
		{"schema", 2, "schema", "Unsupported document schema 2."},
		{"schema", "1", "schema", "Unsupported document schema 1."},
		{"agent_id", "agent-2", "agent_id", "The document belongs to another agent."},
		{"target", map[string]any{"id": 1, "kind": "s3", "name": "x"}, "target.kind", "Target kind s3 is not supported by this agent."},
		{"network_mode", "lan", "network_mode", "Unknown network mode lan."},
		{"compression", "zstd", "compression", "Unknown compression zstd."},
		{"compression_level", 10, "compression_level", "Compression level must be 0-9."},
		{"compression_level", -1, "compression_level", "Compression level must be 0-9."},
		{"auto_setup", "always", "auto_setup", "Unknown value always."},
		{"smart", "ignore", "smart", "Unknown value ignore."},
		{"priority", "high", "priority", "Unknown value high."},
		{"on_battery", nil, "on_battery", "Unknown value null."},
		{"pause_max_minutes", 241, "pause_max_minutes", "Pause limit must be 0-240 minutes."},
		{"throttle", "fast", "throttle", "Invalid bandwidth rule 0: not an object."},
		{"throttle", map[string]any{"default_kbps": 10_000_001, "rules": []any{}}, "throttle", "Invalid bandwidth rule 0: default_kbps must be 0-10000000."},
		{"throttle", rule("days", []int{8}), "throttle", "Invalid bandwidth rule 1: days must be 1-7."},
		{"throttle", rule("end", "24:00"), "throttle", "Invalid bandwidth rule 1: start and end must be HH:MM."},
		{"throttle", rule("kbps", -1), "throttle", "Invalid bandwidth rule 1: kbps must be 0-10000000."},
		{"schedule_events", []string{"agent_start", "boot"}, "schedule_events", "Unknown event boot."},
		{"hooks", hook("phase", "during"), "hooks", "Invalid hook 1: unknown phase during."},
		{"hooks", hook("on_fail", "ignore"), "hooks", "Invalid hook 1: unknown on_fail ignore."},
		{"hooks", hook("timeout", 0), "hooks", "Invalid hook 1: timeout must be 1-3600 seconds."},
		{"hooks", hook("sha256", strings.Repeat("a", 63)), "hooks", "Invalid hook 1: sha256 must be 64 hex digits."},
		{"hooks", make([]map[string]any, 9), "hooks", "Invalid hook 9: at most 8 hooks."},
		{"timezone", 5, "", ""},
		{"volumes", "x", "", ""},
		{"unknown_key", 1, "", ""},
	} {
		_, errs := parseImagingDoc([]byte(imagingTestDoc(t, id, map[string]any{c.key: c.value})), id)
		want := []imagingConfigError{{c.field, c.message}}
		if c.field == "" {
			want = nil
		}
		if !reflect.DeepEqual(errs, want) {
			t.Errorf("%s=%v: %v", c.key, c.value, errs)
		}
	}
	_, dialErr := imagingDialContext(os.Getenv("ULRMM_IMAGING_INTERFACE"))
	_, errs := parseImagingDoc([]byte(imagingTestDoc(t, id, map[string]any{"network_mode": "internal"})), id)
	if (dialErr == nil) != (errs == nil) || dialErr != nil && !reflect.DeepEqual(errs, []imagingConfigError{{"network_mode", "Internal-only mode is not usable here: " + dialErr.Error()}}) {
		t.Errorf("internal mode: %v, dial %v", errs, dialErr)
	}
	if _, errs := parseImagingDoc([]byte(`[]`), id); len(errs) != 1 || errs[0].Field != "document" {
		t.Errorf("not an object: %v", errs)
	}
}

func TestConfigErrorKeepsPreviousDoc(t *testing.T) {
	a, f := imagingFakeAgent(t)
	good := imagingTestDoc(t, a.AgentID, map[string]any{"auto_setup": "all"})
	f.header, f.seal, f.version, f.doc = "1", true, 1, good
	imagingPollOnce(t, a)
	bad := imagingTestDoc(t, a.AgentID, map[string]any{"auto_setup": "off", "compression": "zstd"})
	f.header, f.version, f.doc = "2", 2, bad
	imagingPollOnce(t, a)
	c := imagingConfigNow(a)
	if c.version != 2 || c.status != "error" || c.hash != hashHex([]byte(bad)) || len(c.errors) != 1 || c.errors[0].Field != "compression" {
		t.Fatalf("%d %s %v", c.version, c.status, c.errors)
	}
	if string(c.raw) != good || c.doc.AutoSetup != "all" {
		t.Fatal("the applied document was replaced")
	}
	if c.autoSetup() != "off" || c.smart() != "warn" {
		t.Fatalf("while the last document is refused: auto_setup %s, smart %s", c.autoSetup(), c.smart())
	}
	imagingPollOnce(t, a)
	cfg := f.lastPoll()["config"].(map[string]any)
	if cfg["version"] != 2.0 || cfg["hash"] != hashHex([]byte(bad)) || cfg["status"] != "error" ||
		!reflect.DeepEqual(cfg["errors"], []any{map[string]any{"field": "compression", "message": "Unknown compression zstd."}}) {
		t.Fatalf("reported %v", cfg)
	}
}

func TestConfigFetchOnHeaderChange(t *testing.T) {
	a, f := imagingFakeAgent(t)
	a.imagingStarted()
	imagingPollOnce(t, a)
	first := f.lastPoll()
	if first["protocol"] != 2.0 || first["deferred"] != "" || len(first["capabilities"].([]any)) != 1 ||
		!reflect.DeepEqual(first["config"], map[string]any{"version": 0.0, "hash": "", "status": "none", "errors": []any{}, "checks_version": 0.0}) ||
		!reflect.DeepEqual(first["conditions"].(map[string]any)["events"], []any{"agent_start"}) || first["conditions"].(map[string]any)["on_ac"] != nil {
		t.Fatalf("first poll %v", first)
	}
	if f.fetches != 0 {
		t.Fatal("fetched without a version from the server")
	}
	f.header, f.seal, f.version, f.doc = "3", true, 3, imagingTestDoc(t, a.AgentID, nil)
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); f.fetches != 1 || c.version != 3 || c.status != "applied" || c.hash != hashHex([]byte(f.doc)) {
		t.Fatalf("fetches %d, %d %s", f.fetches, c.version, c.status)
	}
	select {
	case <-imagingWake:
	default:
		t.Fatal("no wake for the acknowledgement")
	}
	imagingPollOnce(t, a)
	ack := f.lastPoll()
	if f.fetches != 1 || !reflect.DeepEqual(ack["config"], map[string]any{"version": 3.0, "hash": hashHex([]byte(f.doc)), "status": "applied", "errors": []any{}, "checks_version": 0.0}) {
		t.Fatalf("fetches %d, ack %v", f.fetches, ack["config"])
	}
	if len(ack["conditions"].(map[string]any)["events"].([]any)) != 0 {
		t.Fatal("an event was sent twice")
	}
	a.imagingReconnected()
	imagingPollOnce(t, a)
	if f.fetches != 2 {
		t.Fatal("no fetch after a NATS reconnect")
	}
	f.header, f.version, f.doc = "4", 4, imagingTestDoc(t, a.AgentID, map[string]any{"auto_setup": "off"})
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); f.fetches != 3 || c.version != 4 || c.doc.AutoSetup != "off" {
		t.Fatalf("fetches %d, version %d", f.fetches, c.version)
	}
	f.header, f.seal, f.version = "5", false, 5
	if err := a.imagingPoll(context.Background(), ImagingCapability{Method: "m", Ready: true}); err == nil {
		t.Fatal("an unsealed document did not fail the poll")
	}
	if c := imagingConfigNow(a); f.fetches != 4 || c.version != 5 || c.status != "error" || c.doc.AutoSetup != "off" || len(c.errors) != 1 || c.errors[0].Field != "sealing" {
		t.Fatalf("an unsealed document: version %d, status %s, errors %v", c.version, c.status, c.errors)
	}
}

func TestNoHeaderLegacyMode(t *testing.T) {
	a, f := imagingFakeAgent(t)
	a.imagingStarted()
	imagingPollOnce(t, a)
	f.status = 200
	f.grant = []byte(`{"url":"http://old/imaging/transfers/1/","token":"t","claim":"c1","image_id":"i1","network_mode":"internet","run":"r"}`)
	if err := a.imagingPoll(context.Background(), ImagingCapability{}); err == nil || !strings.Contains(err.Error(), "invalid HTTPS imaging grant") {
		t.Fatalf("unsealed grant of an old server: %v", err)
	}
	failure := f.lastPoll()
	if f.fetches != 0 || failure["failure"] != "network" || failure["claim"] != "c1" || failure["image_id"] != "i1" {
		t.Fatalf("fetches %d, report %v", f.fetches, failure)
	}
	if c := imagingConfigNow(a); c.autoSetup() != "off" || c.status != "" {
		t.Fatalf("legacy mode: auto_setup %s, status %s", c.autoSetup(), c.status)
	}
}

func TestNoDocumentAutoSetupOff(t *testing.T) {
	probes := stubImagingProbe(t)
	a, f := imagingFakeAgent(t)
	if a.imagingCached(context.Background()); probes.level != "off" || probes.calls != 1 {
		t.Fatalf("without a document: level %q, probes %d", probes.level, probes.calls)
	}
	a.imagingCached(context.Background())
	if probes.calls != 1 {
		t.Fatal("probed again without a reason")
	}
	f.header, f.seal, f.version, f.doc = "1", true, 1, imagingTestDoc(t, a.AgentID, nil)
	imagingPollOnce(t, a)
	if a.imagingProbe(context.Background()); probes.level != "safe" {
		t.Fatalf("after a document: level %q", probes.level)
	}
}

func imagingRunOnce(t *testing.T, a *Agent) {
	t.Helper()
	if err := a.RunImaging(); err != nil {
		t.Fatal(err)
	}
}

func checksVersion(poll map[string]any) any { return poll["config"].(map[string]any)["checks_version"] }

func TestStartOrderAcknowledgeFirst(t *testing.T) {
	probes := stubImagingProbe(t)
	a, f := imagingFakeAgent(t)
	a.imagingStarted()
	f.header, f.seal, f.version, f.doc = "3", true, 3, imagingTestDoc(t, a.AgentID, nil)
	imagingRunOnce(t, a)
	if probes.calls != 1 || probes.level != "off" || checksVersion(f.lastPoll()) != 0.0 || f.fetches != 1 {
		t.Fatalf("start: probes %d (%s), checks_version %v, fetches %d", probes.calls, probes.level, checksVersion(f.lastPoll()), f.fetches)
	}
	drainImagingWake()
	imagingRunOnce(t, a)
	ack := f.lastPoll()["config"].(map[string]any)
	if ack["status"] != "applied" || ack["version"] != 3.0 || ack["checks_version"] != 0.0 {
		t.Fatalf("the acknowledgement waited for a probe or claimed new checks: %v", ack)
	}
	if probes.calls != 2 || probes.level != "safe" {
		t.Fatalf("no probe under the new document after the acknowledgement: %d %s", probes.calls, probes.level)
	}
	select {
	case <-imagingWake:
	default:
		t.Fatal("the new checks wait for the next regular poll")
	}
	imagingRunOnce(t, a)
	if checksVersion(f.lastPoll()) != 3.0 || probes.calls != 2 {
		t.Fatalf("checks_version %v, probes %d", checksVersion(f.lastPoll()), probes.calls)
	}
}

func TestProbeAgainWhileNotReadyAndOnWake(t *testing.T) {
	probes := stubImagingProbe(t)
	a, _ := imagingFakeAgent(t)
	probes.notReady = true
	imagingRunOnce(t, a)
	imagingRunOnce(t, a)
	if probes.calls != 3 {
		t.Fatalf("not ready: %d probes over two polls", probes.calls)
	}
	probes.notReady = false
	imagingRunOnce(t, a)
	n := probes.calls
	imagingRunOnce(t, a)
	if probes.calls != n {
		t.Fatal("a ready state was probed on a regular poll")
	}
	drainImagingWake()
	a.imagingWoken()
	drainImagingWake()
	imagingRunOnce(t, a)
	if probes.calls != n+1 {
		t.Fatal("no probe after the server woke the poll")
	}
	a.imaging.mu.Lock()
	wall := a.imaging.checksAt == a.imaging.checksAt.Round(0)
	a.imaging.checksAt = time.Now().Round(0).Add(-imagingProbeEvery)
	a.imaging.mu.Unlock()
	imagingRunOnce(t, a)
	if !wall || probes.calls != n+2 {
		t.Fatalf("6 h in wall time: wall clock %v, probes %d", wall, probes.calls)
	}
}

func TestProbeDiscardedAfterNewDocument(t *testing.T) {
	probes := stubImagingProbe(t)
	a, _ := imagingFakeAgent(t)
	probes.during = func(a *Agent) {
		a.imaging.mu.Lock()
		a.imaging.gen++
		a.imaging.mu.Unlock()
	}
	a.imagingProbe(context.Background())
	a.imaging.mu.Lock()
	stored := !a.imaging.checksAt.IsZero()
	a.imaging.reportedGen = a.imaging.gen
	a.imaging.mu.Unlock()
	if stored {
		t.Fatal("a probe under an older document was stored")
	}
	if due, wake := a.imagingRecheck(); !due || !wake {
		t.Fatal("no probe for the new document")
	}
}

func TestFixedKeptUntilReported(t *testing.T) {
	probes := stubImagingProbe(t)
	a, _ := imagingFakeAgent(t)
	at := int64(5)
	probes.checks = []imagingCheck{{ID: "win.vss_service", State: "fixed", Fix: "sc", FixArgv: []string{"sc"}, FixedAt: &at}}
	a.imagingProbe(context.Background())
	probes.checks = []imagingCheck{{ID: "win.vss_service", State: "ok"}}
	a.imagingProbe(context.Background())
	if c := a.imaging.checks[0]; c.State != "fixed" || c.FixedAt == nil || *c.FixedAt != 5 || c.Fix != "sc" {
		t.Fatalf("an unreported fix was dropped: %+v", c)
	}
	imagingPollOnce(t, a)
	a.imagingProbe(context.Background())
	if c := a.imaging.checks[0]; c.State != "ok" || c.FixedAt != nil {
		t.Fatalf("a reported fix was kept: %+v", c)
	}
}

func TestErrorDocAppliedWhenRecheckPasses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the tunnel interface rule of Linux makes the refusal environmental")
	}
	a, f := imagingFakeAgent(t)
	t.Setenv("ULRMM_IMAGING_INTERFACE", "")
	f.header, f.seal, f.version, f.doc = "2", true, 2, imagingTestDoc(t, a.AgentID, map[string]any{"network_mode": "internal"})
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); c.status != "error" {
		t.Fatalf("internal mode without a tunnel: %s", c.status)
	}
	t.Setenv("ULRMM_IMAGING_INTERFACE", "wg0")
	imagingPollOnce(t, a)
	c := imagingConfigNow(a)
	cfg := f.lastPoll()["config"].(map[string]any)
	if c.status != "applied" || c.doc.NetworkMode != "internal" || c.autoSetup() != "safe" || f.fetches != 1 || cfg["status"] != "applied" || cfg["version"] != 2.0 {
		t.Fatalf("status %s, fetches %d, reported %v", c.status, f.fetches, cfg)
	}
}

// bareFakeAgent talks to the fake without sealTransport, so only the checks
// of the imaging code decide.
func bareFakeAgent(t *testing.T) (*Agent, *imagingFake) {
	a, f := imagingFakeAgent(t)
	a.rClient = resty.New().SetBaseURL("https://rmm").SetTransport(f)
	return a, f
}

func TestConfigFetchNeedsOpenedMarker(t *testing.T) {
	a, f := bareFakeAgent(t)
	f.header, f.version, f.doc = "3", 3, imagingTestDoc(t, a.AgentID, nil)
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); f.fetches != 1 || c.version != 0 || c.raw != nil {
		t.Fatalf("an unopened document was taken: fetches %d, version %d", f.fetches, c.version)
	}
}

func TestUnmarkedGrantRefusedOnceHeaderSeen(t *testing.T) {
	a, f := bareFakeAgent(t)
	a.imaging.headerAt.Store(time.Now().UnixMilli())
	f.status, f.grant = 200, []byte(`{"url":"https://rmm/imaging/transfers/1/","token":"t","claim":"c1","image_id":"i1","network_mode":"internet"}`)
	err := a.imagingPoll(context.Background(), ImagingCapability{})
	if err == nil || !strings.Contains(err.Error(), "refusing an unsealed imaging answer") || len(f.polls) != 1 {
		t.Fatalf("%v, %d posts", err, len(f.polls))
	}
}

func TestImagingRedirectRefused(t *testing.T) {
	a, f := imagingFakeAgent(t)
	f.redirect = "/api/v3/" + a.AgentID + "/elsewhere/"
	f.grant = []byte(`{"url":"https://rmm/imaging/transfers/1/","token":"t","claim":"c1","image_id":"i1","network_mode":"internet"}`)
	err := a.imagingPoll(context.Background(), ImagingCapability{})
	if err == nil || !strings.Contains(err.Error(), "redirected") || len(f.polls) != 1 {
		t.Fatalf("%v, %d posts", err, len(f.polls))
	}
	f.redirect, f.header, f.seal, f.version, f.doc = "", "1", true, 1, imagingTestDoc(t, a.AgentID, nil)
	imagingPollOnce(t, a)
	f.redirect = "/api/v3/" + a.AgentID + "/imaging/config/x/"
	f.grant, _ = json.Marshal(map[string]any{"version": 2, "document": imagingTestDoc(t, a.AgentID, map[string]any{"smart": "off"})})
	a.imagingSyncConfig(context.Background(), "2")
	if c := imagingConfigNow(a); c.version != 1 {
		t.Fatalf("a redirected config answer was taken: version %d", c.version)
	}
}

func TestConfigSealRefusedReported(t *testing.T) {
	a, f := imagingFakeAgent(t)
	good := imagingTestDoc(t, a.AgentID, map[string]any{"auto_setup": "all"})
	f.header, f.seal, f.version, f.doc = "1", true, 1, good
	imagingPollOnce(t, a)
	f.header, f.version, f.doc = "2", 2, imagingTestDoc(t, a.AgentID, map[string]any{"smart": "off"})
	f.fetchErr = errors.New("connection reset by peer")
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); c.version != 1 || c.status != "applied" || len(c.errors) != 0 {
		t.Fatalf("a network error was reported: %d %s %v", c.version, c.status, c.errors)
	}
	f.fetchErr, f.badSeal = nil, true
	// the refusal fails the poll, so the loop backs off
	var refused *sealError
	if err := a.imagingPoll(context.Background(), ImagingCapability{Method: "m", Ready: true}); !errors.As(err, &refused) {
		t.Fatalf("a refused seal: poll error %v", err)
	}
	c := imagingConfigNow(a)
	want := []imagingConfigError{{"sealing", "The agent cannot verify the server's sealed answer (signature). Its enrolment key does not match this server."}}
	if c.version != 2 || c.hash != "" || c.status != "error" || !reflect.DeepEqual(c.errors, want) || string(c.raw) != good || c.autoSetup() != "off" {
		t.Fatalf("seal refused: %d %q %s %v", c.version, c.hash, c.status, c.errors)
	}
	a.imagingRevalidate()
	if c := imagingConfigNow(a); c.status != "error" || c.version != 2 {
		t.Fatalf("revalidated a refused seal: %s %d", c.status, c.version)
	}
	fetches := f.fetches
	if err := a.imagingPoll(context.Background(), ImagingCapability{Method: "m", Ready: true}); !errors.As(err, &refused) {
		t.Fatalf("a refused seal again: poll error %v", err)
	}
	cfg := f.lastPoll()["config"].(map[string]any)
	if f.fetches != fetches+1 || cfg["version"] != 2.0 || cfg["hash"] != "" || cfg["status"] != "error" ||
		!reflect.DeepEqual(cfg["errors"], []any{map[string]any{"field": "sealing", "message": want[0].Message}}) {
		t.Fatalf("fetches %d, poll %v", f.fetches-fetches, cfg)
	}
	f.badSeal = false
	imagingPollOnce(t, a)
	if c := imagingConfigNow(a); c.version != 2 || c.status != "applied" || c.doc.Smart != "off" || len(c.errors) != 0 {
		t.Fatalf("after the seal opens again: %d %s %v", c.version, c.status, c.errors)
	}
}
