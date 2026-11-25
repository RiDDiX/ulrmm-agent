// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Sealed REST answers: package job plans, the self-heal download and the
// certificate answer come encrypted to the agent's static X25519 key and
// signed with a command key, once the agent asks for it (X-ULRMM-Seal).

const (
	sealAsk    = "X-ULRMM-Seal"
	sealMarker = "X-ULRMM-Sealed"
	sealMax    = 16 << 20
)

// the answers the server seals, by method and path
var sealedPaths = []struct {
	method string
	re     *regexp.Regexp
}{
	{http.MethodGet, regexp.MustCompile(`^/api/v4/[^/]+/pkgjob/[^/]+/$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v3/[^/]+/selfheal/$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v3/[^/]+/cert/$`)},
}

func sealedPath(method, path string) bool {
	for _, p := range sealedPaths {
		if p.method == method && p.re.MatchString(path) {
			return true
		}
	}
	return false
}

// The imaging answers have a rule of their own, in both armed states: an
// unsealed 204 and an old server's grant pass, a 200 that names a settings
// version must be sealed, and within 24 h of an answer that named a version
// every 200 must name one.
var imagingSealedPaths = []struct {
	method string
	re     *regexp.Regexp
}{
	{http.MethodPost, regexp.MustCompile(`^/api/v3/[^/]+/imaging/$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v3/[^/]+/imaging/config/$`)},
}

func imagingSealedPath(method, path string) bool {
	for _, p := range imagingSealedPaths {
		if p.method == method && p.re.MatchString(path) {
			return true
		}
	}
	return false
}

// sealError is a sealed answer that did not open, or an imaging answer that
// came unsealed where a seal is required; reason is the short cause.
type sealError struct{ reason, text string }

func (e *sealError) Error() string { return e.text }

func sealRefused(reason string) error { return &sealError{reason, "sealed answer: " + reason} }

func (a *Agent) imagingAnswerAllowed(path string, status int, h http.Header, sealed bool) error {
	named := len(h.Values(imagingConfigHeader)) > 0
	if named {
		a.imaging.headerAt.Store(time.Now().UnixMilli())
	}
	if status == http.StatusOK && (named && !sealed || !named && a.imagingHeaderSeen()) {
		err := &sealError{"unsealed", "refusing an unsealed imaging answer from " + path}
		a.queueSecurityEvent("envelope_refused", err.Error())
		return err
	}
	return nil
}

type sealedBody struct {
	V   int    `json:"v"`
	Kid string `json:"kid"`
	E   string `json:"e"`
	C   string `json:"c"`
	T   int64  `json:"t"`
	G   string `json:"g"`
}

func sealSigned(agentID, path string, e []byte, t int64, c []byte) []byte {
	b := append([]byte("ulrmm-seal-v1\x00"), agentID...)
	b = append(b, 0)
	b = append(append(b, path...), e...)
	return signedBytes(tsBytes(b, t), c)
}

// openSealed verifies and decrypts a sealed answer for path.
func openSealed(id *identity, agentID, path string, pins *pinSet, raw []byte, serverNowMs int64) ([]byte, error) {
	var b sealedBody
	if err := json.Unmarshal(raw, &b); err != nil || b.V != 2 {
		return nil, sealRefused("not a sealed body")
	}
	e, err1 := base64.StdEncoding.DecodeString(b.E)
	c, err2 := base64.StdEncoding.DecodeString(b.C)
	g, err3 := base64.StdEncoding.DecodeString(b.G)
	if err1 != nil || err2 != nil || err3 != nil || len(e) != 32 {
		return nil, sealRefused("malformed")
	}
	pub := pins.cmdKey(b.Kid)
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sealSigned(agentID, path, e, b.T, c), g) {
		return nil, sealRefused("signature")
	}
	if d := b.T - serverNowMs; d > e2eClockWindow.Milliseconds() || -d > e2eClockWindow.Milliseconds() {
		return nil, sealRefused("clock")
	}
	ep, err := ecdh.X25519().NewPublicKey(e)
	if err != nil {
		return nil, sealRefused("key")
	}
	shared, err := id.x.ECDH(ep)
	if err != nil {
		return nil, sealRefused("key")
	}
	key, _ := hkdf.Key(sha256.New, shared, nil, "ulrmm seal v1\x00"+agentID+path, 32)
	plain, err := unseal(key, make([]byte, 12), c, []byte(path))
	if err != nil {
		return nil, sealRefused("decrypt")
	}
	return plain, nil
}

// sealTransport asks for sealed answers once the identity is registered
// and opens them before resty reads the body. An armed agent refuses a
// covered answer that came unsealed.
type sealTransport struct {
	base http.RoundTripper
	a    *Agent
}

func (t *sealTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	a := t.a
	registered := a.registered()
	if registered {
		req = req.Clone(req.Context())
		req.Header.Set(sealAsk, "1")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Header.Del(imagingOpened)
	sealed := registered && resp.Header.Get(sealMarker) == "1"
	if imagingSealedPath(req.Method, req.URL.Path) {
		if err := a.imagingAnswerAllowed(req.URL.Path, resp.StatusCode, resp.Header, sealed); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}
	if !registered {
		return resp, nil
	}
	if !sealed {
		if a.sec2Armed() && resp.StatusCode/100 == 2 && sealedPath(req.Method, req.URL.Path) {
			resp.Body.Close()
			return nil, errors.New("refusing an unsealed answer from " + req.URL.Path)
		}
		return resp, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, sealMax))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	plain, err := openSealed(a.sec2.ident.Load(), a.AgentID, req.URL.Path, a.pins.Load(), raw, time.Now().UnixMilli()+a.sec2.offset.Load())
	if err != nil {
		a.queueSecurityEvent("envelope_refused", req.URL.Path+": "+err.Error())
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(plain))
	resp.ContentLength = int64(len(plain))
	resp.Header.Set("Content-Length", strconv.Itoa(len(plain)))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Del(sealMarker)
	resp.Header.Set(imagingOpened, "1")
	return resp, nil
}
