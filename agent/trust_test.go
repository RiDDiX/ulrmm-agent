// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testLeaf is a server certificate for 127.0.0.1 from ca, or self-signed
// when ca is nil.
func testLeaf(t *testing.T, ca *testCA, nb, na time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "rmm"},
		NotBefore: nb, NotAfter: na, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	var der []byte
	if ca != nil {
		der = ca.sign(t, tmpl, &key.PublicKey)
	} else {
		var err error
		if der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key); err != nil {
			t.Fatal(err)
		}
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func parsed(t *testing.T, ders ...[]byte) []*x509.Certificate {
	var out []*x509.Certificate
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func TestCheckRMMCert(t *testing.T) {
	now := time.Now()
	rmmCA, public, attacker := newTestCA(t, "rmm CA"), newTestCA(t, "public CA"), newTestCA(t, "attacker CA")
	good := testLeaf(t, rmmCA, now.Add(-time.Hour), now.Add(time.Hour))
	// a CA the system trusts issued a certificate for the RMM's name
	foreign := testLeaf(t, public, now.Add(-time.Hour), now.Add(time.Hour))
	forged := testLeaf(t, attacker, now.Add(-time.Hour), now.Add(time.Hour))
	self := testLeaf(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	selfExpired := testLeaf(t, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	roots := x509.NewCertPool()
	roots.AddCert(rmmCA.cert)
	roots.AddCert(public.cert)
	pins := &pinSet{Seq: 1, Primary: []string{spkiPin(rmmCA.cert.Raw)}}
	leafPins := &pinSet{Seq: 1, Primary: []string{"b3RoZXI="}, Backup: []string{spkiPin(self.Certificate[0])}}

	for _, tc := range []struct {
		name  string
		certs []*x509.Certificate
		host  string
		pins  *pinSet
		ok    bool
	}{
		{"verified chain, root pinned", parsed(t, good.Certificate[0]), "127.0.0.1", pins, true},
		{"verified chain, leaf pinned as backup", parsed(t, good.Certificate[0]), "127.0.0.1", &pinSet{Backup: []string{spkiPin(good.Certificate[0])}}, true},
		{"verified chain without a pinned key", parsed(t, good.Certificate[0]), "127.0.0.1", &pinSet{Primary: []string{"b3RoZXI="}}, false},
		{"other trusted CA while pins are stored", parsed(t, foreign.Certificate[0]), "127.0.0.1", pins, false},
		{"untrusted chain with the pinned root appended", parsed(t, forged.Certificate[0], rmmCA.cert.Raw), "127.0.0.1", pins, false},
		{"trusted foreign chain with the pinned root appended", parsed(t, foreign.Certificate[0], rmmCA.cert.Raw), "127.0.0.1", pins, false},
		{"self-signed pinned leaf", parsed(t, self.Certificate[0]), "127.0.0.1", leafPins, true},
		{"self-signed pinned leaf, other host name", parsed(t, self.Certificate[0]), "rmm.example", leafPins, false},
		{"self-signed pinned leaf, expired", parsed(t, selfExpired.Certificate[0]), "127.0.0.1", &pinSet{Primary: []string{spkiPin(selfExpired.Certificate[0])}}, false},
		{"no pins: verified chain", parsed(t, good.Certificate[0]), "127.0.0.1", nil, true},
		{"no pins: other trusted CA", parsed(t, foreign.Certificate[0]), "127.0.0.1", nil, true},
		{"no pins: wrong host name", parsed(t, good.Certificate[0]), "rmm.example", nil, false},
		{"no pins: self-signed", parsed(t, self.Certificate[0]), "127.0.0.1", nil, false},
		{"nothing sent", nil, "127.0.0.1", pins, false},
	} {
		if err := checkRMMCert(tc.certs, tc.host, roots, tc.pins, now); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// rmmTestAgent talks to the RMM at 127.0.0.1 with the build key k.
func rmmTestAgent(t *testing.T) *Agent {
	a := testUpdateAgent()
	a.AgentID, a.ApiURL = "agent-1", "127.0.0.1"
	old := etcConfig
	etcConfig = filepath.Join(t.TempDir(), "none", "conf")
	t.Cleanup(func() { etcConfig = old })
	return a
}

func rmmServer(t *testing.T, cert tls.Certificate, maxVersion uint16, h http.Handler) *httptest.Server {
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	}
	return quietTLSServer(t, h, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersion})
}

func rmmGet(a *Agent, base string) error {
	r, err := a.newAPIClient(base, nil).R().Get("/api/v3/x/")
	if err == nil && r.String() != "ok" {
		err = errors.New("answer " + r.String())
	}
	return err
}

func download(a *Agent, link string) error {
	return a.fetchFile(link, filepath.Join(a.UnixTmpDir, "dl"), "", time.Minute)
}

func TestRMMConnections(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t, "rmm CA")
	srv := rmmServer(t, testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour)), 0, nil)
	tls12 := rmmServer(t, testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour)), tls.VersionTLS12, nil)
	self := testLeaf(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	selfSrv := rmmServer(t, self, 0, nil)

	a := rmmTestAgent(t)
	a.UnixTmpDir = t.TempDir()
	a.Cert = ca.file(t)
	a.pins.Store(&pinSet{Primary: []string{spkiPin(ca.cert.Raw)}})
	if err := rmmGet(a, srv.URL); err != nil {
		t.Fatalf("pinned CA: %v", err)
	}
	if err := download(a, srv.URL); err != nil {
		t.Fatalf("download, pinned CA: %v", err)
	}
	if err := rmmGet(a, tls12.URL); err == nil {
		t.Fatal("the RMM was accepted over TLS 1.2")
	}

	a.pins.Store(&pinSet{Seq: 1, Primary: []string{"b3RoZXI="}})
	if err := rmmGet(a, srv.URL); err == nil {
		t.Fatal("verified chain without a pinned key accepted")
	}
	if err := download(a, srv.URL); err == nil {
		t.Fatal("download: verified chain without a pinned key accepted")
	}
	if len(a.events) != 1 || a.events[0].Kind != "pin_mismatch" || !strings.HasPrefix(a.events[0].Detail, "127.0.0.1: ") {
		t.Fatalf("events %+v", a.events)
	}

	// other hosts: no pins, TLS 1.2 is fine
	a.ApiURL = "rmm.example"
	if err := download(a, srv.URL); err != nil {
		t.Fatalf("another host is held to the RMM pins: %v", err)
	}
	if err := download(a, tls12.URL); err != nil {
		t.Fatalf("another host over TLS 1.2: %v", err)
	}
	a.ApiURL = "127.0.0.1"

	// self-signed server, leaf pinned, no CA file
	a.Cert = ""
	a.pins.Store(&pinSet{Seq: 1, Primary: []string{spkiPin(self.Certificate[0])}})
	if err := rmmGet(a, selfSrv.URL); err != nil {
		t.Fatalf("pinned self-signed server: %v", err)
	}
	// no pins: plain verification
	a.pins.Store(nil)
	if err := rmmGet(a, selfSrv.URL); err == nil {
		t.Fatal("unknown self-signed server accepted without pins")
	}
	a.Cert = ca.file(t)
	if err := rmmGet(a, srv.URL); err != nil {
		t.Fatalf("no pins, CA file: %v", err)
	}
}

// A client is set up for the host it starts with. A redirect from another
// host onto the RMM still gets the RMM's checks, one away from the RMM is
// refused.
func TestRedirectsAndRMMTrust(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t, "rmm CA")
	cert := testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour))
	rmm := rmmServer(t, cert, 0, nil)
	rmm12 := rmmServer(t, cert, tls.VersionTLS12, nil)
	byName := func(s *httptest.Server) string { return "https://localhost:" + s.URL[strings.LastIndex(s.URL, ":")+1:] }
	redirect := func(to string) *httptest.Server {
		return rmmServer(t, cert, 0, http.RedirectHandler(to, http.StatusFound))
	}
	a := rmmTestAgent(t)
	a.UnixTmpDir, a.Cert, a.ApiURL = t.TempDir(), ca.file(t), "localhost"
	a.pins.Store(&pinSet{Primary: []string{spkiPin(ca.cert.Raw)}})
	if err := download(a, redirect(byName(rmm)).URL); err != nil {
		t.Fatalf("redirect onto the RMM: %v", err)
	}
	if err := download(a, redirect(byName(rmm12)).URL); err == nil {
		t.Fatal("redirect onto the RMM over TLS 1.2 accepted")
	}
	a.pins.Store(&pinSet{Primary: []string{"b3RoZXI="}})
	if err := download(a, redirect(byName(rmm)).URL); err == nil {
		t.Fatal("redirect onto the RMM skipped the pins")
	}

	a.ApiURL = "127.0.0.1"
	a.pins.Store(nil)
	if err := download(a, redirect(byName(rmm)).URL); err == nil || !strings.Contains(err.Error(), "away from the RMM") {
		t.Fatalf("redirect away from the RMM: %v", err)
	}
}

func TestHTTPRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	defer plain.Close()
	a := rmmTestAgent(t)
	a.UnixTmpDir = t.TempDir()
	if err := rmmGet(a, plain.URL); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("REST over http: %v", err)
	}
	if err := download(a, plain.URL); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("download over http: %v", err)
	}
	if err := a.runtimeDownload(plain.URL, filepath.Join(a.UnixTmpDir, "rt")); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("runtime download over http: %v", err)
	}
	// a redirect down to http
	tlsSrv := httptest.NewTLSServer(http.RedirectHandler(plain.URL, http.StatusFound))
	defer tlsSrv.Close()
	a.Cert = writeCA(t, tlsSrv)
	if err := download(a, tlsSrv.URL); err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("redirect to http: %v", err)
	}
}

// pinDocServer is the RMM with cert that answers the pin document doc()
// and records what the pin requests carried.
type pinDocServer struct {
	*httptest.Server
	mu    sync.Mutex
	doc   string
	asked atomic.Int32
	creds []string
}

func newPinDocServer(t *testing.T, cert tls.Certificate) *pinDocServer {
	s := &pinDocServer{}
	s.Server = quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pinsPath {
			w.Write([]byte("ok"))
			return
		}
		s.asked.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		if a := r.Header.Get("Authorization"); a != "" {
			s.creds = append(s.creds, "Authorization "+a)
		}
		if len(r.TLS.PeerCertificates) > 0 {
			s.creds = append(s.creds, "client certificate")
		}
		json.NewEncoder(w).Encode(map[string]string{"jws": s.doc})
	}), &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert})
	return s
}

func (s *pinDocServer) set(doc string) {
	s.mu.Lock()
	s.doc = doc
	s.mu.Unlock()
}

func pinDoc(k ed25519.PrivateKey, iss string, seq int64, primary ...string) string {
	return mintJWS(k, map[string]string{"alg": "EdDSA", "kid": testKid(k), "typ": pinsTyp},
		map[string]interface{}{"v": 1, "typ": pinsTyp, "iss": iss, "seq": seq, "primary": primary, "backup": []string{}, "iat": time.Now().Unix()})
}

func TestPinRescue(t *testing.T) {
	key := testEnrollKey(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := newTestCA(t, "agent CA")
	// the server moved to a new self-signed certificate
	self := testLeaf(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	srv := newPinDocServer(t, self)
	newPin := spkiPin(self.Certificate[0])

	a := rmmTestAgent(t)
	a.BaseURL = srv.URL
	a.clientCert.Store(ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour)))
	stale := &pinSet{Seq: 4, Primary: []string{"b3RoZXI="}}
	headers := map[string]string{"Authorization": "Token secret"}
	get := func() error {
		r, err := a.newAPIClient(srv.URL, headers).R().Get("/api/v3/x/")
		if err == nil && r.String() != "ok" {
			err = errors.New(r.String())
		}
		return err
	}

	for _, tc := range []struct{ name, doc string }{
		{"not signed by the build key", pinDoc(other, srv.URL, 5, newPin)},
		{"not newer", pinDoc(key, srv.URL, 4, newPin)},
		{"for another server", pinDoc(key, "https://other.example", 5, newPin)},
		// signed and newer, but the rescue connection saw another certificate
		{"pins do not match the serving chain", pinDoc(key, srv.URL, 5, spkiPin(ca.cert.Raw))},
	} {
		a.pins.Store(stale)
		a.rescueAt = time.Time{}
		srv.set(tc.doc)
		n := srv.asked.Load()
		if err := get(); err == nil {
			t.Fatalf("%s: connection accepted", tc.name)
		}
		if srv.asked.Load() != n+1 || a.pins.Load() != stale {
			t.Fatalf("%s: asked %d times, pins %+v", tc.name, srv.asked.Load()-n, a.pins.Load())
		}
	}

	// at most one rescue per period
	n := srv.asked.Load()
	if err := get(); err == nil || srv.asked.Load() != n {
		t.Fatalf("second rescue within the period: %v, %d", err, srv.asked.Load()-n)
	}

	a.rescueAt = time.Time{}
	a.events = nil
	srv.set(pinDoc(key, srv.URL, 5, newPin))
	if err := get(); err != nil {
		t.Fatalf("after the rescue: %v", err)
	}
	if ps := a.pins.Load(); ps.Seq != 5 || ps.Primary[0] != newPin {
		t.Fatalf("pins %+v", ps)
	}
	if len(a.events) != 1 || a.events[0].Kind != "pin_rescue" {
		t.Fatalf("events %+v", a.events)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.creds) != 0 {
		t.Fatalf("the rescue sent %v", srv.creds)
	}
}

func TestRefreshPins(t *testing.T) {
	key := testEnrollKey(t)
	ca := newTestCA(t, "rmm CA")
	now := time.Now()
	srv := newPinDocServer(t, testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour)))
	a := rmmTestAgent(t)
	a.BaseURL, a.Cert = srv.URL, ca.file(t)
	a.pins.Store(&pinSet{Primary: []string{spkiPin(ca.cert.Raw)}})
	srv.set(pinDoc(key, srv.URL, 2, spkiPin(ca.cert.Raw), spkiPin(ca.cert.Raw)))
	a.RefreshPins()
	if ps := a.pins.Load(); ps.Seq != 2 || len(ps.Primary) != 2 {
		t.Fatalf("pins %+v", ps)
	}
	// a newer signed document that does not pin the chain it came over
	srv.set(pinDoc(key, srv.URL, 3, spkiPin(newTestCA(t, "other CA").cert.Raw)))
	a.RefreshPins()
	if ps := a.pins.Load(); ps.Seq != 2 {
		t.Fatalf("pins %+v", ps)
	}
	if len(a.events) != 1 || a.events[0].Kind != "pin_mismatch" || !strings.Contains(a.events[0].Detail, "pin set 3 does not match") {
		t.Fatalf("events %+v", a.events)
	}
}

// A redirect to plain http on the same host is not followed: the token
// would go out unencrypted.
func TestAPIRedirectToHTTPRefused(t *testing.T) {
	var leaked atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer plain.Close()
	a := apiAgent(t, http.RedirectHandler(plain.URL+"/api/v3/x/", http.StatusFound).ServeHTTP)
	if _, err := a.rClient.R().Get("/api/v3/x/"); err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("redirect to http: %v", err)
	}
	if leaked.Load() != 0 {
		t.Fatal("the request went on over plain http")
	}
}

func TestVerifyPinDoc(t *testing.T) {
	key := testEnrollKey(t)
	hdr := map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": pinsTyp}
	pin := spkiPin(newTestCA(t, "x").cert.Raw)
	claims := func(kv ...interface{}) map[string]interface{} {
		c := map[string]interface{}{"v": 1, "typ": pinsTyp, "iss": "https://rmm.example", "seq": 3, "primary": []string{pin}, "backup": []string{pin}, "iat": 1}
		for i := 0; i+1 < len(kv); i += 2 {
			c[kv[i].(string)] = kv[i+1]
		}
		return c
	}
	for _, tc := range []struct {
		name string
		jws  string
		ok   bool
	}{
		{"valid", mintJWS(key, hdr, claims()), true},
		{"enrollment token", mintJWS(key, map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": "JWT"}, claims()), false},
		{"claim typ", mintJWS(key, hdr, claims("typ", "ulrmm-update")), false},
		{"http iss", mintJWS(key, hdr, claims("iss", "http://rmm.example")), false},
		{"other iss", mintJWS(key, hdr, claims("iss", "https://evil.example")), false},
		{"no seq", mintJWS(key, hdr, claims("seq", nil)), false},
		{"no primary", mintJWS(key, hdr, claims("primary", []string{})), false},
		{"pin not a sha256", mintJWS(key, hdr, claims("backup", []string{"b3RoZXI="})), false},
	} {
		ps, err := verifyPinDoc(tc.jws, "RMM.example")
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.ok && (ps.Seq != 3 || len(ps.Primary) != 1 || len(ps.Backup) != 1) {
			t.Errorf("%s: %+v", tc.name, ps)
		}
	}
}
