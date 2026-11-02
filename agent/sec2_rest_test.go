// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
)

// fakeIdentityServer answers the identity, token and recover endpoints and
// checks every signature like the server does.
type fakeIdentityServer struct {
	mu       sync.Mutex
	t        *testing.T
	agentID  string
	regCode  int
	regBody  map[string]interface{}
	clockOff int64
	ed       ed25519.PublicKey
	calls    []string
	auth     []string
	nonce    []byte
	refresh  string
	gen      int
	// the first registration is answered as after an identity reset
	resetOnce bool
	// checkinterval: what to rotate, or 401 for a token it does not know
	rotate       []string
	unknownToken bool
	// refresh refused with this detail (default "unknown token"); a grant
	// without a token needs the release window, one with a family token
	// gets 409
	refreshDetail string
	window        bool
	ca            *testCA
	// refresh answers carry a now_ms this many ms old (the retry cache)
	staleNow int64
	// the caps of the last registration
	caps []string
}

func (f *fakeIdentityServer) answer(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeIdentityServer) now() int64 { return time.Now().UnixMilli() + f.clockOff }

func (f *fakeIdentityServer) tokens() map[string]interface{} {
	f.gen++
	f.refresh = fmt.Sprintf("refresh-%d", f.gen)
	return map[string]interface{}{
		"access": fmt.Sprintf("access-%d", f.gen), "refresh": f.refresh, "now_ms": f.now(),
		"access_expires":  time.UnixMilli(f.now()).Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh_expires": time.UnixMilli(f.now()).Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
	}
}

func (f *fakeIdentityServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	var body map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&body)
	b64 := func(k string) []byte { b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(body[k])); return b }
	ts := func() int64 { n, _ := body["ts"].(float64); return int64(n) }
	pre := "/api/v3/" + f.agentID
	switch r.URL.Path {
	case pre + "/identity/":
		if f.resetOnce {
			f.resetOnce = false
			f.answer(w, 403, map[string]interface{}{"detail": "quarantined", "new_identity": true})
			return
		}
		if d := ts() - f.now(); d > 30_000 || d < -30_000 {
			f.answer(w, 400, map[string]interface{}{"detail": "clock", "now_ms": f.now()})
			return
		}
		f.caps = nil
		if cs, ok := body["caps"].([]interface{}); ok {
			for _, c := range cs {
				f.caps = append(f.caps, fmt.Sprint(c))
			}
		}
		ed := b64("ed25519")
		nk, _ := body["nkey"].(string)
		msg := []byte("ulrmm-idreg-v1\x00" + f.agentID + "\x00")
		msg = append(append(append(msg, ed...), b64("x25519")...), nk...)
		msg = tsBytes(msg, ts())
		if !ed25519.Verify(ed, msg, b64("sig")) {
			f.answer(w, 400, map[string]string{"detail": "signature"})
			return
		}
		if idreg := b64("idreg"); len(idreg) > 0 {
			rot := append([]byte("ulrmm-idrot-v1"), msg[len("ulrmm-idreg-v1"):]...)
			if !ed25519.Verify(f.ed, rot, idreg) {
				f.answer(w, 409, map[string]string{"detail": "identity already registered"})
				return
			}
		}
		f.ed = ed
		ans := map[string]interface{}{"kid": keyID(ed), "state": "active", "sec2": "optional", "rotate": []string{}, "now_ms": f.now()}
		for k, v := range f.regBody {
			ans[k] = v
		}
		f.answer(w, f.regCode, ans)
	case pre + "/token/challenge/", pre + "/recover/challenge/":
		f.nonce = []byte(strings.Repeat("n", 32))
		f.answer(w, 200, map[string]interface{}{"nonce": base64.StdEncoding.EncodeToString(f.nonce), "now_ms": f.now()})
	case pre + "/token/grant/":
		if !ed25519.Verify(f.ed, tsBytes(append([]byte("ulrmm-grant-v1\x00"+f.agentID+"\x00"), f.nonce...), ts()), b64("sig")) {
			f.answer(w, 403, map[string]string{"detail": "signature"})
			return
		}
		switch auth := r.Header.Get("Authorization"); {
		case auth == "" && !f.window:
			f.answer(w, 401, map[string]string{"detail": "token required"})
			return
		case strings.HasPrefix(auth, "Token access-"):
			f.answer(w, 409, map[string]string{"detail": "token family exists"})
			return
		}
		f.window = false
		f.answer(w, 200, f.tokens())
	case pre + "/token/refresh/":
		if d := ts() - f.now(); d > 30_000 || d < -30_000 {
			f.answer(w, 400, map[string]interface{}{"detail": "clock", "now_ms": f.now()})
			return
		}
		ref, _ := body["refresh"].(string)
		sum := sha256.Sum256([]byte(ref))
		if ref != f.refresh || !ed25519.Verify(f.ed, tsBytes(append([]byte("ulrmm-refresh-v1\x00"+f.agentID+"\x00"), sum[:]...), ts()), b64("sig")) {
			d := f.refreshDetail
			if d == "" {
				d = "unknown token"
			}
			f.answer(w, 401, map[string]string{"detail": d})
			return
		}
		ans := f.tokens()
		ans["now_ms"] = f.now() - f.staleNow
		f.answer(w, 200, ans)
	case pre + "/security-event/":
		if r.Header.Get("Authorization") != fmt.Sprintf("Token access-%d", f.gen) {
			f.answer(w, 401, map[string]string{"detail": "Invalid token."})
			return
		}
		f.answer(w, 201, map[string]string{})
	case pre + "/recover/":
		csr, _ := body["csr"].(string)
		sum := sha256.Sum256([]byte(csr))
		msg := tsBytes(append([]byte("ulrmm-recover-v1\x00"+f.agentID+"\x00"), f.nonce...), ts())
		if !strings.Contains(csr, "CERTIFICATE REQUEST") || !ed25519.Verify(f.ed, append(msg, sum[:]...), b64("sig")) {
			f.answer(w, 403, map[string]string{"detail": "recovery not allowed"})
			return
		}
		f.answer(w, 200, f.tokens())
	case pre + "/cert/":
		csr, _ := body["csr"].(string)
		f.answer(w, 200, map[string]string{"cert": f.ca.issue(f.t, csr, time.Now().Add(-time.Minute), time.Now().Add(90*24*time.Hour))})
	case pre + "/checkinterval/":
		if f.unknownToken {
			f.answer(w, 401, map[string]string{"detail": "Invalid token."})
			return
		}
		f.answer(w, 200, map[string]interface{}{"agent": 1, "check_interval": 60, "rotate": f.rotate, "now_ms": f.now()})
	default:
		f.answer(w, 404, map[string]string{"detail": "Not found."})
	}
}

func identityAgent(t *testing.T, f *fakeIdentityServer) *Agent {
	t.Helper()
	old := etcConfig
	t.Cleanup(func() { etcConfig = old })
	etcConfig = filepath.Join(t.TempDir(), "agent.json")
	createAgentConfig("https://api", "agent1", "api", "legacy", "1", "", "", "", "", "")
	f.t, f.agentID = t, "agent1"
	if f.regCode == 0 {
		f.regCode = 201
	}
	a := apiAgent(t, f.ServeHTTP)
	a.Logger.SetOutput(io.Discard)
	a.NatsProxyPath = "natsws"
	return a
}

// secretText is a config secret as the agent reads it (under the KEK once
// the service made the keystore).
func secretText(name string) string {
	b, _ := unprotect(name)
	return string(b)
}

func natsOpts(t *testing.T, a *Agent) nats.Options {
	t.Helper()
	var o nats.Options
	for _, opt := range a.natsAuth() {
		if err := opt(&o); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

// First start of an R2 service: identity made, registered, the install
// token exchanged for a family, NATS logs in with the nkey on the agent's
// own path.
func TestIdentityRegistrationAndGrant(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	if o := natsOpts(t, a); o.User != "agent1" || o.ProxyPath != "natsws" || o.Nkey != "" {
		t.Fatalf("before registration: %+v", o)
	}
	a.setupIdentity()
	if !a.registered() {
		t.Fatal("not registered", f.calls)
	}
	if kid, _ := confValue(confIdentityKid); kid != a.sec2.ident.Load().kid {
		t.Error("kid not stored")
	}
	if tok := secretText("Token"); tok != "access-1" || !a.haveRefresh() || a.sec2.access.Load() == nil || *a.sec2.access.Load() != "access-1" {
		t.Errorf("token family not stored: %q", tok)
	}
	if issued, exp := confMs(confAccessIssued), confMs(confAccessExpires); exp-issued < int64(6*24*time.Hour/time.Millisecond) {
		t.Error("access lifetime", issued, exp)
	}
	o := natsOpts(t, a)
	if o.Nkey != a.sec2.ident.Load().nkeyPub || o.User != "" || o.Password != "" || o.ProxyPath != "natsws/agent1" || o.SignatureCB == nil {
		t.Fatalf("after registration: %+v", o)
	}
	sig, _ := o.SignatureCB([]byte("nonce"))
	if len(sig) != 64 {
		t.Error("nkey signature")
	}
	// the next start keeps everything and asks nothing
	n := len(f.calls)
	b := apiAgent(t, f.ServeHTTP)
	b.setupIdentity()
	if !b.registered() || len(f.calls) != n {
		t.Error("second start:", f.calls[n:])
	}
	// REST uses the family token from now on
	_, _ = a.rClient.R().Get("/api/v3/agent1/checkinterval/")
	if got := f.auth[len(f.auth)-1]; got != "Token access-1" {
		t.Error("Authorization", got)
	}
}

func TestIdentityClockRetry(t *testing.T) {
	f := &fakeIdentityServer{clockOff: int64(5 * time.Minute / time.Millisecond)}
	a := identityAgent(t, f)
	a.setupIdentity()
	if !a.registered() || f.calls[0] != f.calls[1] {
		t.Fatal(f.calls)
	}
	if off := a.sec2.offset.Load(); off < 299_000 || off > 301_000 {
		t.Error("offset", off)
	}
}

func TestIdentityRefusedKeepsLegacyLogin(t *testing.T) {
	for _, code := range []int{403, 404, 409} {
		f := &fakeIdentityServer{regCode: code}
		a := identityAgent(t, f)
		a.setupIdentity()
		if a.registered() || natsOpts(t, a).User != "agent1" || len(f.calls) != 1 {
			t.Errorf("%d: %v", code, f.calls)
		}
		if a.registrationDue(time.Now()) || !a.registrationDue(time.Now().Add(identityRetry+time.Second)) == (code != 404) {
			t.Errorf("%d: retry rule", code)
		}
		if code == 404 {
			a.pins.Store(&pinSet{Cmd: []cmdKey{{Kid: "k"}}})
			if !a.registrationDue(time.Now().Add(identityRetry + time.Second)) {
				t.Error("404: a pin document with command keys asks again")
			}
		}
	}
}

// After "reset identity" the server answers 403 with new_identity: the
// agent makes a new seed and registers it.
func TestIdentityResetByAdmin(t *testing.T) {
	f := &fakeIdentityServer{resetOnce: true}
	a := identityAgent(t, f)
	a.loadIdentity()
	first := a.sec2.ident.Load().kid
	if ok, _ := a.registerIdentity(); !ok || !a.registered() || a.sec2.ident.Load().kid == first {
		t.Fatal("reset:", f.calls)
	}
	if kid, _ := confValue(confIdentityKid); kid == first || kid != a.sec2.ident.Load().kid {
		t.Error("stored kid", kid)
	}
}

func TestTokenRefreshAndRecover(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	if !a.refreshToken() {
		t.Fatal("refresh", f.calls)
	}
	if tok := secretText("Token"); tok != "access-2" || f.auth[len(f.auth)-1] != "" {
		t.Errorf("token %q, refresh sent Authorization %q", tok, f.auth[len(f.auth)-1])
	}
	// a refresh token the server no longer knows and no release window:
	// the grant on the identity alone is refused, recover takes over
	f.refresh = "gone"
	n := len(f.calls)
	if !a.refreshToken() {
		t.Fatal("refresh refused, no recovery", f.calls[n:])
	}
	if got := strings.Join(f.calls[n:], " "); !strings.Contains(got, "/token/grant/") || !strings.HasSuffix(got, "POST /api/v3/agent1/recover/") {
		t.Error("calls", got)
	}
	if tok := secretText("Token"); tok != "access-3" || a.recoverDue(time.Now().Add(time.Hour)) {
		t.Error("after recover", tok)
	}
	if a.recoverDue(time.Now()) {
		t.Error("recover twice within 30 minutes")
	}
}

func TestCredentialAnswerHints(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	n := len(f.calls)
	a.credentialAnswer("https://api/api/v3/agent1/identity/", 401, `{"detail":"token expired","refresh":true}`)
	a.credentialAnswer("https://api/api/v3/agent1/checkinterval/", 401, `{"detail":"token expired","refresh":true}`)
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		done := len(f.calls) > n && f.calls[len(f.calls)-1] == "POST /api/v3/agent1/token/refresh/"
		f.mu.Unlock()
		if done || time.Now().After(deadline) {
			if !done {
				t.Fatal("no refresh after the hint", f.calls[n:])
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// rotate_pending "identity": new keys signed by the old identity; the new
// seed waits as IdentityKeyNext until the server took it.
func TestIdentityRotation(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	old := a.sec2.ident.Load()
	oldSeed, _ := confValue(confIdentityKey)
	a.setRotate([]string{"identity", "cert"})
	f.regBody = map[string]interface{}{"rotate": []string{}}
	if !a.rotateIdentity() {
		t.Fatal("rotation", f.calls)
	}
	cur := a.sec2.ident.Load()
	seed, _ := confValue(confIdentityKey)
	next, _ := confValue(confIdentityNext)
	kid, _ := confValue(confIdentityKid)
	if cur.kid == old.kid || seed == oldSeed || next != "" || kid != cur.kid || !a.registered() {
		t.Fatalf("after rotation: kid %s next %q", kid, next)
	}
	if !ed25519.PublicKey(f.ed).Equal(ed25519.PublicKey(cur.edPub())) {
		t.Error("server has other keys")
	}
	// a rotation signed with a key the server does not have is refused and
	// keeps the identity
	a.sec2.ident.Store(old)
	a.sec2.kid.Store(&old.kid)
	if a.rotateIdentity() {
		t.Error("rotation signed by a stale key")
	}
	if n, _ := confValue(confIdentityNext); n == "" {
		t.Error("the pending seed is kept for a retry")
	}
	// cert asks for a renewal regardless of the lifetime
	a.sec2.ident.Store(cur)
	a.sec2.kid.Store(&cur.kid)
	a.setRotate([]string{"cert"})
	a.doRotations()
	if !a.sec2.forceCert.Load() {
		t.Error("cert rotation not requested")
	}
}

// The check interval answer carries what the dashboard asked to rotate.
func TestCheckIntervalCarriesRotate(t *testing.T) {
	f := &fakeIdentityServer{rotate: []string{"token"}, clockOff: 90_000}
	a := identityAgent(t, f)
	if _, err := a.GetCheckInterval(); err != nil || a.sec2.rotate.Load() != nil {
		t.Fatal("unregistered agent took the hint", err)
	}
	a.setupIdentity()
	a.sec2.offset.Store(0)
	if n, err := a.GetCheckInterval(); err != nil || n != 60 {
		t.Fatal(n, err)
	}
	if r := a.sec2.rotate.Load(); r == nil || strings.Join(*r, ",") != "token" {
		t.Fatalf("rotate %v", r)
	}
	if off := a.sec2.offset.Load(); off < 89_000 || off > 91_000 {
		t.Error("offset", off)
	}
}

// The server's database is older than the agent's tokens (a restored
// backup): an unknown token leads to refresh, then recover.
func TestUnknownTokenRecovers(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	f.mu.Lock()
	f.refresh, f.unknownToken = "restored", true
	f.mu.Unlock()
	if _, err := a.GetCheckInterval(); err == nil {
		t.Fatal("unknown token accepted")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		f.mu.Lock()
		done := f.calls[len(f.calls)-1] == "POST /api/v3/agent1/recover/"
		f.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no recovery", f.calls)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if tok := secretText("Token"); tok == "access-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recovered tokens not stored")
		}
	}
}

// An expired refresh token goes to recover at once, without a grant; so
// does a start after the refresh lifetime.
func TestExpiredRefreshRecoversAtOnce(t *testing.T) {
	f := &fakeIdentityServer{refreshDetail: "token expired"}
	a := identityAgent(t, f)
	a.setupIdentity()
	f.refresh = "old"
	n := len(f.calls)
	if !a.refreshToken() {
		t.Fatal("no recovery", f.calls[n:])
	}
	if got := strings.Join(f.calls[n:], " "); strings.Contains(got, "grant") || !strings.HasSuffix(got, "/recover/") {
		t.Error("calls", got)
	}
	if err := setConfValues(map[string]string{confRefreshExpires: strconv.FormatInt(time.Now().Add(-time.Minute).UnixMilli(), 10)}); err != nil {
		t.Fatal(err)
	}
	b := apiAgent(t, f.ServeHTTP)
	b.Logger.SetOutput(io.Discard)
	n = len(f.calls)
	b.setupIdentity()
	if got := strings.Join(f.calls[n:], " "); !strings.HasSuffix(got, "POST /api/v3/agent1/recover/") {
		t.Error("start after the refresh lifetime:", got)
	}
}

// Inside a release window (a quarantine released, a restored database) an
// unknown or revoked token gets a grant on the identity signature alone,
// and the revoked client certificate is renewed at once.
func TestReleaseWindowGrant(t *testing.T) {
	ca := newTestCA(t, "agent CA")
	for _, via := range []string{"refresh", "rest"} {
		f := &fakeIdentityServer{ca: ca}
		a := identityAgent(t, f)
		a.setupIdentity()
		old := ca.pair(t, "agent1", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
		a.clientCert.Store(old)
		f.mu.Lock()
		f.refresh, f.window = "restored", true
		n := len(f.calls)
		f.mu.Unlock()
		if via == "refresh" {
			if !a.refreshToken() {
				t.Fatal(via, f.calls[n:])
			}
		} else {
			a.credentialAnswer("https://api/api/v3/agent1/checkinterval/", 401, `{"detail":"token revoked"}`)
			for deadline := time.Now().Add(5 * time.Second); a.clientCert.Load() == old; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal(via, "no renewal", f.calls[n:])
				}
			}
		}
		f.mu.Lock()
		got := strings.Join(f.calls[n:], " ")
		for i, c := range f.calls[n:] {
			if strings.Contains(c, "/token/") && f.auth[n+i] != "" {
				t.Errorf("%s: %s sent a token", via, c)
			}
		}
		f.mu.Unlock()
		if strings.Contains(got, "recover") || !strings.Contains(got, "POST /api/v3/agent1/token/grant/") || !strings.HasSuffix(got, "POST /api/v3/agent1/cert/") {
			t.Errorf("%s: calls %s", via, got)
		}
		if tok := secretText("Token"); tok != "access-2" || a.clientCert.Load() == old || a.sec2.forceCert.Load() {
			t.Errorf("%s: token %q, cert renewed %v", via, tok, a.clientCert.Load() != old)
		}
	}
}

// 409 to a grant: a family exists. The heartbeat does not grant again.
func TestGrantConflictNotRetried(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	if err := setConfValues(map[string]string{confRefresh: ""}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.sec2.pinsAt = now.Add(time.Hour)
	a.sec2.recoverAt = now.Add(time.Hour)
	a.sec2Heartbeat(now)
	a.sec2Heartbeat(now.Add(heartbeatEvery))
	grants := 0
	for _, c := range f.calls {
		if strings.HasSuffix(c, "/token/grant/") {
			grants++
		}
	}
	if grants != 2 || !a.sec2.grantRefused.Load() || !a.sec2.refreshBad.Load() {
		t.Errorf("grants %d (the first one at setup), %v", grants, f.calls)
	}
}

// A refresh answered from the server's retry cache carries the time of its
// first issue, which is not the server clock. A refused clock names the
// server time and the refresh goes once more with it.
func TestRefreshClock(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	f.mu.Lock()
	f.staleNow = 48_000
	f.mu.Unlock()
	a.sec2.offset.Store(0)
	if !a.refreshToken() {
		t.Fatal("refresh", f.calls)
	}
	if off := a.sec2.offset.Load(); off < -1000 || off > 1000 {
		t.Error("clock learned from a cached answer, offset", off)
	}
	a.sec2.offset.Store(-60_000)
	n := len(f.calls)
	if !a.refreshToken() {
		t.Fatal("refresh after a refused clock", f.calls[n:])
	}
	if got := strings.Join(f.calls[n:], " "); got != "POST /api/v3/agent1/token/refresh/ POST /api/v3/agent1/token/refresh/" {
		t.Error("calls", got)
	}
	if off := a.sec2.offset.Load(); off < -1000 || off > 1000 {
		t.Error("offset", off)
	}
}

// rotate identity and cert at once: the certificate is renewed before the
// restart for the new login ends the process.
func TestIdentityRotationRenewsCertFirst(t *testing.T) {
	oldBy, oldExit, oldDir := restartByExit, exitProcess, nixAgentDir
	t.Cleanup(func() { restartByExit, exitProcess, nixAgentDir = oldBy, oldExit, oldDir })
	nixAgentDir = t.TempDir()
	ca := newTestCA(t, "agent CA")
	f := &fakeIdentityServer{ca: ca}
	a := identityAgent(t, f)
	a.ProgramDir = nixAgentDir
	a.setupIdentity()
	old := ca.pair(t, "agent1", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	a.clientCert.Store(old)
	restarted := false
	restartByExit, exitProcess = true, func(int) {
		restarted = true
		if a.clientCert.Load() == old {
			t.Error("restart before the certificate was renewed")
		}
	}
	a.setRotate([]string{"identity", "cert"})
	a.doRotations()
	if !restarted || a.sec2.forceCert.Load() {
		t.Error("restarted", restarted, "calls", f.calls)
	}
}

// Security events wait for the new pair: a token answer does not send them
// with the access token it replaces. No 401 then uses up the refresh on an
// unknown token, which a restored database needs.
func TestSecurityEventsAfterNewTokens(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	a.setupIdentity()
	sent := func() (ok, refused int) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, c := range f.calls {
			if strings.HasSuffix(c, securityEventPath) {
				if f.auth[i] == fmt.Sprintf("Token access-%d", f.gen) {
					ok++
				} else {
					refused++
				}
			}
		}
		return
	}
	a.queueSecurityEvent("envelope_refused", "signature")
	if !a.refreshToken() {
		t.Fatal("refresh", f.calls)
	}
	for deadline := time.Now().Add(5 * time.Second); a.pendingSecurityEvents(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("events not sent", f.calls)
		}
	}
	if ok, refused := sent(); ok != 1 || refused != 0 {
		t.Errorf("sent %d, refused %d", ok, refused)
	}
	a.queueSecurityEvent("envelope_refused", "kid")
	if _, _, err := a.challenge("/api/v3/agent1/token/challenge/", true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if ok, _ := sent(); ok != 1 || !a.pendingSecurityEvents() {
		t.Error("a token answer sent the events, calls", f.calls)
	}
	if !a.sec2.refusedNow("unknown-token", time.Now()) {
		t.Error("the refresh on an unknown token was used up")
	}
}
