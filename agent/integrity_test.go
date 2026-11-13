// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func integrityDoc(k ed25519.PrivateKey, iss string, builds map[string]map[string]string) string {
	return mintJWS(k, map[string]string{"alg": "EdDSA", "kid": testKid(k), "typ": integrityTyp},
		map[string]interface{}{"v": 1, "typ": integrityTyp, "iss": iss, "iat": time.Now().Unix(), "builds": builds, "windows": "setup-only"})
}

func TestVerifyIntegrityDoc(t *testing.T) {
	key := testEnrollKey(t)
	sum := strings.Repeat("ab", 32)
	builds := map[string]map[string]string{"3.25.10.2026": {"linux-amd64": sum}}
	doc := integrityDoc(key, "https://api.example.com", builds)

	if got, err := verifyIntegrityDoc(doc, "api.example.com", "3.25.10.2026", "linux-amd64"); err != nil || got != sum {
		t.Fatalf("listed build: %q %v", got, err)
	}
	if got, err := verifyIntegrityDoc(doc, "api.example.com", "v3.25.10.2026", "linux-amd64"); err != nil || got != sum {
		t.Fatalf("v prefix: %q %v", got, err)
	}
	// own builds and other platforms are not listed: nothing to compare
	for _, c := range [][2]string{{"9.99.99.2099", "linux-amd64"}, {"3.25.10.2026", "darwin-arm64"}} {
		if got, err := verifyIntegrityDoc(doc, "api.example.com", c[0], c[1]); err != nil || got != "" {
			t.Fatalf("%v: %q %v", c, got, err)
		}
	}
	if _, err := verifyIntegrityDoc(doc, "evil.example.com", "3.25.10.2026", "linux-amd64"); err == nil {
		t.Fatal("a manifest of another server was taken")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := verifyIntegrityDoc(integrityDoc(other, "https://api.example.com", builds), "api.example.com", "3.25.10.2026", "linux-amd64"); err == nil {
		t.Fatal("a manifest signed with another key was taken")
	}
	parts := strings.Split(doc, ".")
	forged := parts[0] + "." + b64json(map[string]interface{}{"v": 1, "typ": integrityTyp, "iss": "https://api.example.com", "builds": map[string]map[string]string{"3.25.10.2026": {"linux-amd64": strings.Repeat("cd", 32)}}}) + "." + parts[2]
	if _, err := verifyIntegrityDoc(forged, "api.example.com", "3.25.10.2026", "linux-amd64"); err == nil {
		t.Fatal("a changed manifest was taken")
	}
	pins := pinDoc(key, "https://api.example.com", 1, "cGlu")
	if _, err := verifyIntegrityDoc(pins, "api.example.com", "3.25.10.2026", "linux-amd64"); err == nil {
		t.Fatal("a pin document was taken as a manifest")
	}
	if _, err := verifyIntegrityDoc(integrityDoc(key, "http://api.example.com", builds), "api.example.com", "3.25.10.2026", "linux-amd64"); err == nil {
		t.Fatal("a plain http issuer was taken")
	}
	bad := integrityDoc(key, "https://api.example.com", map[string]map[string]string{"3.25.10.2026": {"linux-amd64": "x"}})
	if _, err := verifyIntegrityDoc(bad, "api.example.com", "3.25.10.2026", "linux-amd64"); err == nil {
		t.Fatal("a sha256 that is not one was taken")
	}
}

func integrityEvents(a *Agent) int {
	n := 0
	for _, e := range a.events {
		if e.Kind == "integrity_mismatch" {
			n++
		}
	}
	return n
}

func TestIntegrityMismatchRepairsOncePerDay(t *testing.T) {
	key := testEnrollKey(t)
	f := newHealFixture(t)
	good := sumOf(t, "good build")
	f.server, f.srvErr, f.payload = healDownload{Version: "2.11.1", URL: "https://api.example.com/agent", SHA256: good}, nil, "good build"
	f.server.UpdateSig = updateSig(key, "url", f.server.URL, "version", "2.11.1", "sha256", good)
	a := testUpdateAgent()
	a.Version, a.ApiURL = "2.11.1", "api.example.com"
	doc := integrityDoc(key, "https://api.example.com", map[string]map[string]string{"2.11.1": {runtime.GOOS + "-" + runtime.GOARCH: good}})

	a.integrity(f.h, doc, f.main, f.now)
	if integrityEvents(a) != 0 || len(f.reports) != 0 {
		t.Fatal("the listed build was reported")
	}

	writeFile(t, f.main, "tampered")
	a.integrity(f.h, doc, f.main, f.now)
	if integrityEvents(a) != 1 || readFile(t, f.main) != "good build" || len(f.reports) != 1 {
		t.Fatalf("mismatch: events %d, binary %q, reports %v", integrityEvents(a), readFile(t, f.main), f.reports)
	}

	a.events = nil
	writeFile(t, f.main, "tampered")
	a.integrity(f.h, doc, f.main, f.now.Add(23*time.Hour))
	if integrityEvents(a) != 1 || readFile(t, f.main) != "tampered" || len(f.reports) != 1 {
		t.Fatal("a second repair within 24h")
	}
	a.integrity(f.h, doc, f.main, f.now.Add(25*time.Hour))
	if readFile(t, f.main) != "good build" || len(f.reports) != 2 {
		t.Fatal("no repair after 24h")
	}

	// a download that does not match the server's checksum is not installed
	writeFile(t, f.main, "tampered")
	f.payload = "other"
	a.integrity(f.h, doc, f.main, f.now.Add(50*time.Hour))
	if readFile(t, f.main) != "tampered" {
		t.Fatal("an unverified download was installed")
	}
}

func TestIntegrityUnlistedOrRefused(t *testing.T) {
	key := testEnrollKey(t)
	f := newHealFixture(t)
	f.srvErr = nil
	writeFile(t, f.main, "own build")
	a := testUpdateAgent()
	a.Version, a.ApiURL = "2.11.1", "api.example.com"
	plat := runtime.GOOS + "-" + runtime.GOARCH
	for _, doc := range []string{
		integrityDoc(key, "https://api.example.com", map[string]map[string]string{"2.10.1": {plat: sumOf(t, "x")}}),
		integrityDoc(key, "https://other.example.com", map[string]map[string]string{"2.11.1": {plat: sumOf(t, "x")}}),
	} {
		a.integrity(f.h, doc, f.main, f.now)
	}
	if len(a.events) != 0 || len(f.reports) != 0 || readFile(t, f.main) != "own build" {
		t.Fatal("an unlisted version or a refused manifest led to a repair")
	}
	if _, err := os.Stat(filepath.Join(f.h.dir(), integrityStampFile)); err == nil {
		t.Fatal("repair stamp written")
	}
}

// A failed manifest fetch is retried after integrityRetry, a good one
// waits the full interval.
func TestCheckIntegrityRetriesAFailedFetch(t *testing.T) {
	testEnrollKey(t)
	var hits, serve atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if serve.Load() == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"jws":"x"}`))
	}))
	defer ts.Close()
	integrityState.Lock()
	integrityState.next, integrityState.busy = time.Time{}, false
	integrityState.Unlock()
	a := testUpdateAgent()
	a.Cert, a.BaseURL = writeCA(t, ts), ts.URL
	now := time.Now()
	step := func(at time.Duration, want int32, why string) {
		t.Helper()
		a.checkIntegrity(now.Add(at))
		if got := hits.Load(); got != want {
			t.Fatalf("%s: %d fetches, want %d", why, got, want)
		}
	}
	step(0, 1, "first check")
	step(integrityRetry-time.Second, 1, "retried before the retry interval")
	step(integrityRetry, 2, "no retry after a failed fetch")
	serve.Store(1)
	step(2*integrityRetry, 3, "no retry after the second failure")
	step(2*integrityRetry+integrityEvery-time.Second, 3, "fetched again within the interval after a success")
	step(2*integrityRetry+integrityEvery, 4, "not fetched after the interval")
}

// A fetch that panics is recovered by the service guard and retried like a
// failed one, it does not leave the check switched off.
func TestCheckIntegrityRetriesAfterAPanic(t *testing.T) {
	testEnrollKey(t)
	integrityState.Lock()
	integrityState.next, integrityState.busy = time.Time{}, false
	integrityState.Unlock()
	fetches := 0
	integrityFetch = func(*Agent) (string, error) {
		fetches++
		if fetches == 1 {
			panic("transport broke")
		}
		return "", errors.New("unreachable")
	}
	t.Cleanup(func() { integrityFetch = (*Agent).getIntegrityDoc })
	a := testUpdateAgent()
	a.BaseURL = "https://api.example.com"
	now := time.Now()
	a.guard("checkIntegrity", func() { a.checkIntegrity(now) })
	a.guard("checkIntegrity", func() { a.checkIntegrity(now.Add(integrityRetry - time.Second)) })
	if fetches != 1 {
		t.Fatalf("%d fetches before the retry interval, want 1", fetches)
	}
	a.guard("checkIntegrity", func() { a.checkIntegrity(now.Add(integrityRetry)) })
	if fetches != 2 {
		t.Fatalf("%d fetches after the retry interval, want 2", fetches)
	}
}

// A server whose current build is not the listed one (rolled back, a build
// in dist before the switch) is no source for the repair.
func TestIntegrityRepairNeedsTheListedBuild(t *testing.T) {
	key := testEnrollKey(t)
	f := newHealFixture(t)
	f.server, f.srvErr, f.payload = healDownload{Version: "2.11.0", URL: "https://api.example.com/agent", SHA256: sumOf(t, "older build")}, nil, "older build"
	a := testUpdateAgent()
	a.Version, a.ApiURL = "2.11.1", "api.example.com"
	doc := integrityDoc(key, "https://api.example.com", map[string]map[string]string{"2.11.1": {runtime.GOOS + "-" + runtime.GOARCH: sumOf(t, "good build")}})
	writeFile(t, f.main, "tampered")
	a.integrity(f.h, doc, f.main, f.now)
	if integrityEvents(a) != 1 || readFile(t, f.main) != "tampered" || f.p.installed2 != "" || len(f.reports) != 0 {
		t.Fatalf("binary %q, installed %q", readFile(t, f.main), f.p.installed2)
	}
	if _, err := os.Stat(filepath.Join(f.h.dir(), integrityStampFile)); err == nil {
		t.Fatal("repair stamp written")
	}
}

// Windows: the server ships a setup, so its sha256 differs from the listed
// agent exe; agent_sha256 names the exe inside it and the repair goes ahead.
func TestIntegrityRepairWithSetupDownload(t *testing.T) {
	key := testEnrollKey(t)
	f := newHealFixture(t)
	setup, exe := sumOf(t, "setup"), sumOf(t, "good build")
	f.server, f.srvErr, f.payload = healDownload{Version: "2.11.1", URL: "https://api.example.com/agent", SHA256: setup, AgentSHA256: exe}, nil, "setup"
	f.server.UpdateSig = updateSig(key, "url", f.server.URL, "version", "2.11.1", "sha256", setup)
	a := testUpdateAgent()
	a.Version, a.ApiURL = "2.11.1", "api.example.com"
	doc := integrityDoc(key, "https://api.example.com", map[string]map[string]string{"2.11.1": {runtime.GOOS + "-" + runtime.GOARCH: exe}})
	writeFile(t, f.main, "tampered")
	a.integrity(f.h, doc, f.main, f.now)
	if integrityEvents(a) != 1 || len(f.reports) != 1 {
		t.Fatalf("no repair from the setup: events %d, reports %v", integrityEvents(a), f.reports)
	}

	// without agent_sha256 the setup hash is compared and nothing happens
	g := newHealFixture(t)
	g.server, g.srvErr, g.payload = healDownload{Version: "2.11.1", URL: "https://api.example.com/agent", SHA256: setup}, nil, "setup"
	g.server.UpdateSig = f.server.UpdateSig
	b := testUpdateAgent()
	b.Version, b.ApiURL = "2.11.1", "api.example.com"
	writeFile(t, g.main, "tampered")
	b.integrity(g.h, doc, g.main, g.now)
	if len(g.reports) != 0 {
		t.Fatal("repaired with a download that is not the listed build")
	}
}
