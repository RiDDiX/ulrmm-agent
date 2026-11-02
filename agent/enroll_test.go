// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// testPE is a minimal PE32 file: the headers, then body.
func testPE(body []byte) []byte {
	var b bytes.Buffer
	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 64)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	oh := pe.OptionalHeader32{Magic: 0x10b, NumberOfRvaAndSizes: 16}
	binary.Write(&b, binary.LittleEndian, pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_I386, SizeOfOptionalHeader: uint16(binary.Size(oh))})
	binary.Write(&b, binary.LittleEndian, oh)
	b.Write(body)
	return b.Bytes()
}

// testSign appends a certificate table the way a signer does: zero padding
// to 8 bytes, the table, its offset and size in the security directory.
func testSign(f []byte) []byte {
	f = append([]byte{}, f...)
	for len(f)%8 != 0 {
		f = append(f, 0)
	}
	table := []byte("\x10\x00\x00\x00\x00\x02\x02\x00signature")
	dir := 64 + 4 + binary.Size(pe.FileHeader{}) + 96 + 8*pe.IMAGE_DIRECTORY_ENTRY_SECURITY
	binary.LittleEndian.PutUint32(f[dir:], uint32(len(f)))
	binary.LittleEndian.PutUint32(f[dir+4:], uint32(len(table)))
	return append(f, table...)
}

// testFooter appends the enrollment block as the server does; align pads it
// to end on 8 bytes.
func testFooter(f []byte, jws string, align bool) []byte {
	out := append([]byte{}, f...)
	for align && (len(out)+len(jws)+16)%8 != 0 {
		out = append(out, 0)
	}
	out = append(out, jws...)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(jws)))
	return append(out, enrollMagic...)
}

func TestReadEnrollment(t *testing.T) {
	jws := "eyJhbGciOiJFZERTQSJ9.eyJ2IjoxfQ.c2lnbmF0dXJl"
	exe := testPE(bytes.Repeat([]byte{0x90}, 1000))
	if len(testFooter(exe, jws, false))%8 == 0 {
		t.Fatal("the unaligned case needs a block that does not end on 8 bytes")
	}
	badLen := append(append(append([]byte{}, exe...), make([]byte, 8)...), enrollMagic...)
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		file []byte
		want string
		err  error
	}{
		{"unsigned setup", testFooter(exe, jws, true), jws, nil},
		{"signed setup", testSign(testFooter(exe, jws, true)), jws, nil},
		{"padding by the signer", testSign(testFooter(exe, jws, false)), jws, nil},
		{"text file", []byte("\n  " + jws + " \r\n"), jws, nil},
		{"generic setup", exe, "", ErrNoEnrollment},
		{"generic signed setup", testSign(exe), "", ErrNoEnrollment},
		{"other text", []byte("hello world\n"), "", ErrNoEnrollment},
		{"empty file", nil, "", ErrNoEnrollment},
	} {
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, tc.file, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readEnrollment(p)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Fatalf("%s: %q %v", tc.name, got, err)
		}
	}
	p := filepath.Join(dir, "bad")
	os.WriteFile(p, badLen, 0o600)
	if _, err := readEnrollment(p); err == nil || errors.Is(err, ErrNoEnrollment) {
		t.Fatalf("a broken block must be an error, not a generic installer: %v", err)
	}
}

// -m install -enroll with a generic installer ends with exit code 3 before
// it does anything else.
func TestEnrollGenericInstallerExit3(t *testing.T) {
	if p := os.Getenv("ULRMM_TEST_ENROLL_FILE"); p != "" {
		l := logrus.New()
		l.SetOutput(io.Discard)
		(&Agent{Logger: l}).Install(&Installer{EnrollFile: p, Silent: true})
		os.Exit(0)
	}
	p := filepath.Join(t.TempDir(), "setup.exe")
	if err := os.WriteFile(p, testSign(testPE(nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollGenericInstallerExit3$")
	cmd.Env = append(os.Environ(), "ULRMM_TEST_ENROLL_FILE="+p)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 || !strings.Contains(string(out), ErrNoEnrollment.Error()) {
		t.Fatalf("%v %q", err, out)
	}
}

// Install with enrollment data: every request carries it, the server is
// pinned, newagent gets the claims and a certificate request. The fake
// server stops the install at newagent.
func TestInstallSendsEnrollmentAndCSR(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Install removes an existing installation on this OS")
	}
	if os.Getenv("ULRMM_TEST_INSTALL") != "" {
		BrandEnrollPubKey = os.Getenv("ULRMM_TEST_PUBKEY")
		(&Agent{Logger: logrus.New(), Version: "2.25.10.2026"}).Install(&Installer{EnrollFile: os.Getenv("ULRMM_TEST_ENROLL_FILE"),
			Cert: os.Getenv("ULRMM_TEST_CA"), Silent: true, Timeout: time.Minute})
		os.Exit(0)
	}
	key := testEnrollKey(t)
	ca := newTestCA(t, "test server CA")
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "rmm"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &srvKey.PublicKey)
	type request struct {
		path, auth string
		body       map[string]interface{}
	}
	reqs := make(chan request, 8)
	ts := quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		reqs <- request{r.Method + " " + r.URL.Path, r.Header.Get("Authorization"), body}
		if r.URL.Path == "/api/v3/newagent/" {
			http.Error(w, "stop here", http.StatusBadRequest)
		}
	}), &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: srvKey}}})

	hdr := map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": "JWT"}
	jws := mintJWS(key, hdr, testClaims(time.Now(), "iss", ts.URL, "pins", []string{spkiPin(leaf)}))
	p := filepath.Join(t.TempDir(), "enroll.jws")
	os.WriteFile(p, []byte(jws), 0o600)
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstallSendsEnrollmentAndCSR$")
	cmd.Env = append(os.Environ(), "ULRMM_TEST_INSTALL=1", "ULRMM_TEST_PUBKEY="+BrandEnrollPubKey,
		"ULRMM_TEST_ENROLL_FILE="+p, "ULRMM_TEST_CA="+ca.file(t))
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(out), "stop here") {
		t.Fatalf("install did not stop at newagent: %v %q", err, out)
	}
	close(reqs)
	var paths []string
	for r := range reqs {
		paths = append(paths, r.path)
		if r.auth != "Enroll "+jws {
			t.Fatalf("%s: Authorization %q", r.path, r.auth)
		}
		if r.path != "POST /api/v3/newagent/" {
			continue
		}
		csrPEM, _ := r.body["csr"].(string)
		b, _ := pem.Decode([]byte(csrPEM))
		if b == nil {
			t.Fatalf("newagent without a certificate request: %v", r.body)
		}
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil || csr.Subject.CommonName == "" || csr.Subject.CommonName != r.body["agent_id"] {
			t.Fatalf("request: %v %v", err, r.body["agent_id"])
		}
		if r.body["site"] != float64(7) || r.body["monitoring_type"] != "workstation" {
			t.Fatalf("claims not used: %v", r.body)
		}
		// the server renders the NATS permissions of this version right away
		if r.body["version"] != "2.25.10.2026" {
			t.Fatalf("newagent without the version: %v", r.body["version"])
		}
	}
	if got := strings.Join(paths, ", "); got != "GET /api/v3/installer/, POST /api/v3/installer/, POST /api/v3/newagent/" {
		t.Fatalf("requests: %s", got)
	}
}

// testEnrollKey puts a new public key into the build and returns the private one.
func testEnrollKey(t *testing.T) ed25519.PrivateKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := BrandEnrollPubKey
	BrandEnrollPubKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { BrandEnrollPubKey = old })
	return priv
}

func testKid(k ed25519.PrivateKey) string {
	s := sha256.Sum256(k.Public().(ed25519.PublicKey))
	return hex.EncodeToString(s[:])[:16]
}

func b64json(v interface{}) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func mintJWS(k ed25519.PrivateKey, hdr, claims interface{}) string {
	in := b64json(hdr) + "." + b64json(claims)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, []byte(in)))
}

// testClaims are valid claims; kv replaces some.
func testClaims(now time.Time, kv ...interface{}) map[string]interface{} {
	c := map[string]interface{}{
		"v": 1, "iss": "https://api.example.com", "dep": "dep-uid", "cli": 3, "site": 7,
		"mon": "workstation", "pol": nil, "flg": map[string]bool{"power": true, "ping": false, "rdp": true},
		"pins": []string{"cGlu"}, "iat": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix(),
		"jti": strings.Repeat("a", 32),
	}
	for i := 0; i+1 < len(kv); i += 2 {
		c[kv[i].(string)] = kv[i+1]
	}
	return c
}

func TestVerifyEnrollment(t *testing.T) {
	key := testEnrollKey(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	hdr := map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": "JWT"}
	valid := mintJWS(key, hdr, testClaims(now))
	p := strings.Split(valid, ".")
	for _, tc := range []struct{ name, jws, err string }{
		{"valid", valid, ""},
		{"within the leeway", mintJWS(key, hdr, testClaims(now, "iat", now.Add(-48*time.Hour).Unix(), "exp", now.Add(-23*time.Hour).Unix())), ""},
		{"tampered claim", p[0] + "." + b64json(testClaims(now, "site", 8)) + "." + p[2], "signature does not match"},
		{"tampered header", b64json(map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": "JOSE"}) + "." + p[1] + "." + p[2], "signature does not match"},
		{"wrong key", mintJWS(other, hdr, testClaims(now)), "signature does not match"},
		{"kid mismatch", mintJWS(key, map[string]string{"alg": "EdDSA", "kid": testKid(other), "typ": "JWT"}, testClaims(now)), "key id does not match"},
		{"expired", mintJWS(key, hdr, testClaims(now, "iat", now.Add(-48*time.Hour).Unix(), "exp", now.Add(-25*time.Hour).Unix())), "expired"},
		{"alg none", mintJWS(key, map[string]string{"alg": "none", "kid": testKid(key)}, testClaims(now)), "algorithm"},
		{"version 2", mintJWS(key, hdr, testClaims(now, "v", 2)), "version"},
		{"issued in the future", mintJWS(key, hdr, testClaims(now, "iat", now.Add(25*time.Hour).Unix(), "exp", now.Add(48*time.Hour).Unix())), "future"},
		{"no site", mintJWS(key, hdr, testClaims(now, "site", 0)), "site missing"},
		{"bad agent type", mintJWS(key, hdr, testClaims(now, "mon", "router")), "agent type"},
		{"bad server URL", mintJWS(key, hdr, testClaims(now, "iss", "ftp://api.example.com")), "server URL"},
		{"too long", valid + strings.Repeat("A", enrollMaxJWS), "too long"},
		{"not a token", "abc", "not a signed token"},
	} {
		c, err := verifyEnrollment(tc.jws, now)
		if tc.err == "" {
			if err != nil || c.Iss != "https://api.example.com" || c.Cli != 3 || c.Site != 7 || c.Mon != "workstation" ||
				!c.Flg.Power || c.Flg.Ping || !c.Flg.RDP || len(c.Pins) != 1 {
				t.Fatalf("%s: %+v %v", tc.name, c, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s: want %q, got %v", tc.name, tc.err, err)
		}
	}
	BrandEnrollPubKey = ""
	if _, err := verifyEnrollment(valid, now); err == nil || err.Error() != "this build has no enrollment key" {
		t.Fatalf("build without a key: %v", err)
	}
}

func TestApplyEnrollmentReplacesFlags(t *testing.T) {
	key := testEnrollKey(t)
	jws := mintJWS(key, map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": "JWT"}, testClaims(time.Now()))
	p := filepath.Join(t.TempDir(), "enroll.jws")
	os.WriteFile(p, []byte(jws+"\n"), 0o600)
	i := &Installer{EnrollFile: p, RMM: "https://flag.example", ClientID: 99, SiteID: 99, AgentType: "server", Token: "flag-token"}
	if err := applyEnrollment(i, time.Now()); err != nil {
		t.Fatal(err)
	}
	if i.RMM != "https://api.example.com" || i.ClientID != 3 || i.SiteID != 7 || i.AgentType != "workstation" ||
		!i.Power || i.Ping || !i.RDP || i.Token != "" || i.Enroll != jws || len(i.Pins) != 1 || i.Pins[0] != "cGlu" {
		t.Fatalf("%+v", i)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert, key, pool}
}

func (ca *testCA) sign(t *testing.T, tmpl *x509.Certificate, pub interface{}) []byte {
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.SerialNumber = sn
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// issue signs a client certificate for the request, as the server does.
func (ca *testCA) issue(t *testing.T, csrPEM string, nb, na time.Time) string {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil {
		t.Fatal("no PEM in the request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("bad request: %v", err)
	}
	der := ca.sign(t, &x509.Certificate{
		Subject: csr.Subject, NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, csr.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// pair is a client certificate with its key, made through newCSR.
func (ca *testCA) pair(t *testing.T, cn string, nb, na time.Time) *tls.Certificate {
	csr, key, err := newCSR(cn)
	if err != nil {
		t.Fatal(err)
	}
	c, err := keyPair(ca.issue(t, csr, nb, na), key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// file writes the CA certificate as PEM, like a -cert file.
func (ca *testCA) file(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600)
	return p
}

func quietTLSServer(t *testing.T, h http.Handler, conf *tls.Config) *httptest.Server {
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = conf
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func spkiPin(der []byte) string {
	c, _ := x509.ParseCertificate(der)
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(s[:])
}

func TestNewCSR(t *testing.T) {
	csrPEM, keyPEM, err := newCSR("agent-xyz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "agent-xyz" {
		t.Fatalf("request: %v %+v", err, csr.Subject)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("not P-256: %T", csr.PublicKey)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil || !k.(*ecdsa.PrivateKey).PublicKey.Equal(pub) {
		t.Fatalf("key does not belong to the request: %v", err)
	}
	if _, again, _ := newCSR("agent-xyz"); again == keyPEM {
		t.Fatal("the key was reused")
	}
}

// mtlsServer answers with the common name of the client certificate, or
// "none".
func mtlsServer(t *testing.T, ca *testCA, auth tls.ClientAuthType) *httptest.Server {
	return quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := "none"
		if len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		io.WriteString(w, cn)
	}), &tls.Config{ClientAuth: auth, ClientCAs: ca.pool})
}

func TestClientCertPresented(t *testing.T) {
	ca, other := newTestCA(t, "test agent CA"), newTestCA(t, "other CA")
	now := time.Now()
	valid := ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour))
	expired := ca.pair(t, "agent-1", now.Add(-2*time.Hour), now.Add(-time.Hour))
	foreign := other.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour))
	required := mtlsServer(t, ca, tls.RequireAndVerifyClientCert)
	optional := mtlsServer(t, ca, tls.VerifyClientCertIfGiven)

	a := testUpdateAgent()
	a.ApiURL = "127.0.0.1"
	paths := map[string]func(url string) (string, error){
		"API client": func(url string) (string, error) {
			r, err := a.newAPIClient(url, nil).R().Get("/")
			return r.String(), err
		},
		"download": func(url string) (string, error) {
			c, err := a.httpClient(url, time.Minute)
			if err != nil {
				return "", err
			}
			resp, err := c.Get(url)
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			return string(b), err
		},
	}
	for _, tc := range []struct {
		name string
		cert *tls.Certificate
		srv  *httptest.Server
		want string // "": refused
	}{
		{"custom CA", valid, required, "agent-1"},
		{"no certificate", nil, required, ""},
		{"expired stays home", expired, optional, "none"},
		{"other CA stays home", foreign, optional, "none"},
	} {
		a.Cert = writeCA(t, tc.srv)
		a.clientCert.Store(tc.cert)
		for name, get := range paths {
			got, err := get(tc.srv.URL)
			if tc.want == "" && err == nil {
				t.Fatalf("%s, %s: answered %q without a client certificate", tc.name, name, got)
			}
			if tc.want != "" && (err != nil || got != tc.want) {
				t.Fatalf("%s, %s: %q %v", tc.name, name, got, err)
			}
		}
	}
	a.Cert = ""
	if c := a.tlsFor("127.0.0.1"); c.GetClientCertificate == nil {
		t.Fatal("system roots: the client certificate is missing")
	}
	if c := a.tlsFor("downloads.example"); c.GetClientCertificate != nil || c.InsecureSkipVerify || c.RootCAs != nil {
		t.Fatal("another host gets the client certificate or no verification")
	}
}

func TestClientCertDroppedWhenNginxRefusesIt(t *testing.T) {
	ca := newTestCA(t, "test agent CA")
	now := time.Now()
	for _, tc := range []struct {
		code    int
		body    string
		dropped bool
	}{
		{400, "<html><head><title>400 The SSL certificate error</title></head></html>", true},
		{400, `{"site":["invalid"]}`, false},
		{401, `{"detail":"client certificate does not belong to this agent"}`, true},
		// nothing went out, so the certificate is not the problem
		{401, `{"detail":"client certificate required"}`, false},
		{401, `{"detail":"Invalid token."}`, false},
	} {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			io.WriteString(w, tc.body)
		}))
		a := testUpdateAgent()
		a.ApiURL, a.Cert = "127.0.0.1", writeCA(t, ts)
		a.clientCert.Store(ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour)))
		a.newAPIClient(ts.URL, nil).R().Get("/")
		ts.Close()
		if (a.clientCert.Load() == nil) != tc.dropped {
			t.Fatalf("%q: dropped %v", tc.body, a.clientCert.Load() == nil)
		}
	}

	// a renewal finished while the refused request was out
	a := testUpdateAgent()
	a.clientCert.Store(ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour)))
	newer := ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(2*time.Hour))
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a.clientCert.Store(newer)
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"detail":"client certificate does not belong to this agent"}`)
	}))
	defer ts.Close()
	a.ApiURL, a.Cert = "127.0.0.1", writeCA(t, ts)
	a.newAPIClient(ts.URL, nil).R().Get("/")
	if a.clientCert.Load() != newer {
		t.Fatal("the refusal of the old certificate dropped the renewed one")
	}
}

// The server's clock runs 10 minutes ahead: the certificate it just issued
// is not valid yet by the agent's clock. In required mode the agent must
// present it anyway and keep it.
func TestClientCertNotValidYetByAgentClock(t *testing.T) {
	ca := newTestCA(t, "test agent CA")
	ahead := func() time.Time { return time.Now().Add(10 * time.Minute) }
	srv := quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"detail":"client certificate required"}`)
			return
		}
		io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}), &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool, Time: ahead})
	fresh := ca.pair(t, "agent-1", ahead().Add(-5*time.Minute), ahead().Add(time.Hour))

	a := testUpdateAgent()
	a.ApiURL, a.Cert = "127.0.0.1", writeCA(t, srv)
	a.clientCert.Store(fresh)
	r, err := a.newAPIClient(srv.URL, nil).R().Get("/")
	if err != nil || r.String() != "agent-1" {
		t.Fatalf("API client: %d %q %v", r.StatusCode(), r.String(), err)
	}
	if a.clientCert.Load() != fresh {
		t.Fatal("the certificate was dropped")
	}
	c, err := a.httpClient(srv.URL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "agent-1" {
		t.Fatalf("download: %q", b)
	}
}

func TestCertDue(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(180 * 24 * time.Hour)}
	twoThirds := nb.Add(120 * 24 * time.Hour)
	for _, tc := range []struct {
		leaf *x509.Certificate
		now  time.Time
		due  bool
	}{
		{nil, nb, true},
		{leaf, nb.Add(time.Hour), false},
		{leaf, twoThirds.Add(-time.Second), false},
		{leaf, twoThirds.Add(time.Second), true},
		{leaf, leaf.NotAfter.Add(time.Hour), true},
	} {
		if got := certDue(tc.leaf, tc.now, 0); got != tc.due {
			t.Fatalf("%v at %v: %v", tc.leaf != nil, tc.now, got)
		}
	}
}
