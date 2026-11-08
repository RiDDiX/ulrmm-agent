// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Trust in the RMM. Connections to the RMM host (REST and NATS) take TLS
// 1.3 and checkRMMCert; every other host the system roots plus the -cert CA.
// Pins are base64 SHA-256 hashes of a SubjectPublicKeyInfo: the enrollment
// token brings the first set (seq 0), the server's signed pin document
// (/api/v3/pins/) newer ones.

const (
	confPins       = "Pins"
	pinsTyp        = "ulrmm-pins"
	pinsPath       = "/api/v3/pins/"
	pinDocMax      = 16384
	pinRescueEvery = 5 * time.Minute
)

var (
	rmmCurves      = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
	errPinMismatch = errors.New("the server certificate matches none of the pinned keys")
)

type pinSet struct {
	Seq     int64    `json:"seq"`
	Primary []string `json:"primary"`
	Backup  []string `json:"backup"`
	// command keys and the sec2 mode (envelope.go); absent before R2
	Cmd  []cmdKey `json:"cmd,omitempty"`
	Sec2 string   `json:"sec2,omitempty"`
}

type cmdKey struct {
	Kid   string `json:"kid"`
	Ed    string `json:"ed"`
	State string `json:"state"`
}

func (p *pinSet) cmdKeys() []cmdKey {
	if p == nil {
		return nil
	}
	return p.Cmd
}

// cmdKey is the public key listed under kid, nil when none is.
func (p *pinSet) cmdKey(kid string) ed25519.PublicKey {
	if p == nil {
		return nil
	}
	for _, k := range p.Cmd {
		if k.Kid == kid {
			b, _ := base64.StdEncoding.DecodeString(k.Ed)
			return b
		}
	}
	return nil
}

func (p *pinSet) empty() bool { return p == nil || len(p.Primary)+len(p.Backup) == 0 }

func (p *pinSet) has(c *x509.Certificate) bool {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(sum[:])
	return stringInSlice(pin, p.Primary) || stringInSlice(pin, p.Backup)
}

// checkRMMCert decides whether certs, as the server sent them, can be the
// RMM at host:
// (a) the leaf verifies for host against roots, with certs[1:] as
// intermediates; with pins stored a certificate of a verified chain must be
// pinned;
// (b) when that fails and pins are stored, the leaf itself is pinned, valid
// for host and now (self-signed servers; TLS 1.3 proves the leaf key);
// (c) without pins (a) alone.
// A certificate the server merely appends is never matched against a pin.
func checkRMMCert(certs []*x509.Certificate, host string, roots *x509.CertPool, pins *pinSet, now time.Time) error {
	if len(certs) == 0 {
		return errors.New("the server sent no certificate")
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: host, CurrentTime: now})
	if pins.empty() {
		return err
	}
	if err == nil {
		for _, chain := range chains {
			for _, c := range chain {
				if pins.has(c) {
					return nil
				}
			}
		}
		return errPinMismatch
	}
	if !pins.has(leaf) {
		return errPinMismatch
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return err
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("the pinned server certificate is expired or not valid yet")
	}
	return nil
}

func (a *Agent) isRMMHost(host string) bool {
	return host != "" && a.ApiURL != "" && strings.EqualFold(host, a.ApiURL)
}

// rmmRoots are the system roots plus the -cert CA; nil (the system roots)
// without a usable CA file.
func (a *Agent) rmmRoots() *x509.CertPool {
	if a.Cert == "" {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(a.Cert)
	if err == nil && !pool.AppendCertsFromPEM(pem) {
		err = errors.New("no certificate in the file")
	}
	if err != nil {
		a.Logger.Errorln("cannot use the CA in", a.Cert, err)
		return nil
	}
	return pool
}

// tlsFor is the TLS setup for connections to host. Only the RMM gets the
// client certificate.
func (a *Agent) tlsFor(host string) *tls.Config {
	roots := a.rmmRoots()
	if a.isRMMHost(host) {
		return &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: rmmCurves,
			// the standard check is replaced by checkRMMCert in VerifyConnection
			InsecureSkipVerify:   true,
			VerifyConnection:     a.verifyRMM(host, roots),
			GetClientCertificate: a.clientCertFor,
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, VerifyConnection: func(cs tls.ConnectionState) error {
		// a redirect that ends at the RMM
		if a.isRMMHost(cs.ServerName) {
			return a.verifyRMM(cs.ServerName, roots)(cs)
		}
		return nil
	}}
}

// verifyRMM runs checkRMMCert; a refused certificate starts a pin rescue
// and is checked once more with what that brought.
func (a *Agent) verifyRMM(host string, roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if cs.Version < tls.VersionTLS13 {
			return errors.New("the RMM connection is not TLS 1.3")
		}
		err := checkRMMCert(cs.PeerCertificates, host, roots, a.pins.Load(), time.Now())
		if err == nil {
			return nil
		}
		a.rescuePins()
		if err = checkRMMCert(cs.PeerCertificates, host, roots, a.pins.Load(), time.Now()); err == nil {
			return nil
		}
		kind := "tls_failure"
		if !a.pins.Load().empty() {
			kind = "pin_mismatch"
		}
		a.queueSecurityEvent(kind, host+": "+err.Error())
		return err
	}
}

// verifyPinDoc checks a pin document: signed with the build's key, for the
// RMM at host, at least one primary pin, every pin a SHA-256.
func verifyPinDoc(jws, host string) (*pinSet, error) {
	pub, err := enrollPubKey()
	if err != nil {
		return nil, err
	}
	var c struct {
		V       int      `json:"v"`
		Typ     string   `json:"typ"`
		Iss     string   `json:"iss"`
		Seq     *int64   `json:"seq"`
		Primary []string `json:"primary"`
		Backup  []string `json:"backup"`
		Cmd     []cmdKey `json:"cmd"`
		Sec2    string   `json:"sec2"`
	}
	bad := func(why string) error { return fmt.Errorf("pin document invalid: %s", why) }
	if err := verifyJWS(pub, jws, pinsTyp, pinDocMax, &c); err != nil {
		return nil, bad(err.Error())
	}
	if c.V != 1 || c.Typ != pinsTyp || c.Seq == nil || *c.Seq < 0 {
		return nil, bad("version, type or seq")
	}
	if u, err := url.Parse(c.Iss); err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), host) {
		return nil, bad("issued for another server")
	}
	if len(c.Primary) == 0 {
		return nil, bad("no primary pins")
	}
	for _, p := range append(append([]string{}, c.Primary...), c.Backup...) {
		if b, err := base64.StdEncoding.DecodeString(p); err != nil || len(b) != sha256.Size {
			return nil, bad("pin is not a SHA-256")
		}
	}
	switch c.Sec2 {
	case "", "off", "optional", "required":
	default:
		return nil, bad("sec2 mode " + c.Sec2)
	}
	for _, k := range c.Cmd {
		b, err := base64.StdEncoding.DecodeString(k.Ed)
		sum := sha256.Sum256(b)
		if err != nil || len(b) != ed25519.PublicKeySize || k.Kid != hex.EncodeToString(sum[:])[:16] {
			return nil, bad("command key " + k.Kid)
		}
	}
	return &pinSet{Seq: *c.Seq, Primary: c.Primary, Backup: c.Backup, Cmd: c.Cmd, Sec2: c.Sec2}, nil
}

// acceptPinDoc stores a verified pin document that is newer than the
// stored pins and whose pins pass the chain of the connection (cs) that
// brought it; it reports whether it did.
func (a *Agent) acceptPinDoc(jws string, cs *tls.ConnectionState) (bool, error) {
	ps, err := verifyPinDoc(jws, a.ApiURL)
	if err != nil {
		return false, err
	}
	a.pinMu.Lock()
	defer a.pinMu.Unlock()
	// the same seq once more when the stored set lacks the sec2 claim: an
	// agent before R2 stored the document without cmd and sec2
	if cur := a.pins.Load(); cur != nil && (ps.Seq < cur.Seq || ps.Seq == cur.Seq && (cur.Sec2 != "" || ps.Sec2 == "")) {
		return false, nil
	}
	if cs == nil {
		return false, errors.New("the pin document did not come over TLS")
	}
	if err := checkRMMCert(cs.PeerCertificates, a.ApiURL, a.rmmRoots(), ps, time.Now()); err != nil {
		err = fmt.Errorf("pin set %d does not match the server that sent it: %v", ps.Seq, err)
		a.queueSecurityEvent("pin_mismatch", a.ApiURL+": "+err.Error())
		return false, err
	}
	a.pins.Store(ps)
	// another mode keeps them in memory: its write would miss the trust
	// snapshot and the service would revert it as tampered
	confTrust.Lock()
	service := confTrust.service
	confTrust.Unlock()
	if !service {
		return true, nil
	}
	if err := savePins(ps); err != nil {
		a.Logger.Debugln("pins not stored in the config:", err)
	}
	return true, nil
}

func savePins(ps *pinSet) error {
	b, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	return setConfValues(map[string]string{confPins: string(b)})
}

func loadPins(s string) (*pinSet, error) {
	if s == "" {
		return nil, nil
	}
	var ps pinSet
	if err := json.Unmarshal([]byte(s), &ps); err != nil {
		return nil, errors.New("the stored pins cannot be read")
	}
	return &ps, nil
}

// getPinDoc is the JWS the server answers on pinsPath and the TLS state of
// the connection it came over.
func getPinDoc(c *http.Client, baseURL string) (string, *tls.ConnectionState, error) {
	resp, err := c.Get(strings.TrimRight(baseURL, "/") + pinsPath)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("pin document: the server answered %d", resp.StatusCode)
	}
	var body struct {
		JWS string `json:"jws"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, pinDocMax+64)).Decode(&body); err != nil {
		return "", nil, err
	}
	return body.JWS, resp.TLS, nil
}

// RefreshPins fetches the pin document over the normal trust and keeps it
// when it is newer (service start).
func (a *Agent) RefreshPins() {
	if BrandEnrollPubKey == "" || a.BaseURL == "" {
		return
	}
	c, err := a.httpClient(a.BaseURL, 30*time.Second)
	if err != nil {
		a.Logger.Debugln("RefreshPins():", err)
		return
	}
	jws, cs, err := getPinDoc(c, a.BaseURL)
	if err != nil {
		a.Logger.Debugln("RefreshPins():", err)
		return
	}
	if _, err := a.acceptPinDoc(jws, cs); err != nil {
		a.Logger.Errorln("RefreshPins():", err)
	}
}

// rescuePins asks for the pin document over a connection that trusts any
// certificate and carries nothing of the agent (no token, no client
// certificate): only the signature of a newer document counts. At most
// once per pinRescueEvery.
func (a *Agent) rescuePins() {
	if BrandEnrollPubKey == "" || a.BaseURL == "" {
		return
	}
	a.rescueMu.Lock()
	defer a.rescueMu.Unlock()
	if !a.rescueAt.IsZero() && time.Since(a.rescueAt) < pinRescueEvery {
		return
	}
	a.rescueAt = time.Now()
	tr, err := a.transport(&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // only a signed document is used
	if err != nil {
		return
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	jws, cs, err := getPinDoc(c, a.BaseURL)
	if err != nil {
		a.Logger.Debugln("pin rescue:", err)
		return
	}
	// any certificate got the document here; it counts only when its pins
	// pass the chain this connection saw
	newer, err := a.acceptPinDoc(jws, cs)
	if err != nil {
		a.Logger.Errorln("pin rescue:", err)
		return
	}
	if newer {
		a.Logger.Infoln("pin rescue: stored pin set", a.pins.Load().Seq)
		a.queueSecurityEvent("pin_rescue", fmt.Sprintf("pin set %d", a.pins.Load().Seq))
	}
}

// transport is an HTTP transport with the agent's proxy, no keep-alive.
func (a *Agent) transport(t *tls.Config) (*http.Transport, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: t, DisableKeepAlives: true}
	if a.Proxy != "" {
		p, err := parseProxyURL(a.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(p)
	}
	return tr, nil
}

// httpClient is for downloads from link: https only, the TLS setup of its
// host, redirects only to https and, from the RMM, not to another host
// (the TLS setup is made for the host a client starts with).
func (a *Agent) httpClient(link string, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("refusing a download that is not https")
	}
	origin := u.Hostname()
	tr, err := a.transport(a.tlsFor(origin))
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: a.checkRedirect(origin)}, nil
}

// checkRedirect is the redirect rule of clients that start at host: https
// only, from the RMM not to another host, at most 10.
func (a *Agent) checkRedirect(host string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		switch {
		case len(via) >= 10:
			return errors.New("stopped after 10 redirects")
		case req.URL.Scheme != "https":
			return errors.New("refusing a redirect to plain http")
		case a.isRMMHost(host) && !strings.EqualFold(req.URL.Hostname(), host):
			return errors.New("refusing a redirect away from the RMM")
		}
		return nil
	}
}
