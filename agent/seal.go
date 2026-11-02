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
		return nil, errors.New("sealed answer: not a sealed body")
	}
	e, err1 := base64.StdEncoding.DecodeString(b.E)
	c, err2 := base64.StdEncoding.DecodeString(b.C)
	g, err3 := base64.StdEncoding.DecodeString(b.G)
	if err1 != nil || err2 != nil || err3 != nil || len(e) != 32 {
		return nil, errors.New("sealed answer: malformed")
	}
	pub := pins.cmdKey(b.Kid)
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sealSigned(agentID, path, e, b.T, c), g) {
		return nil, errors.New("sealed answer: signature")
	}
	if d := b.T - serverNowMs; d > e2eClockWindow.Milliseconds() || -d > e2eClockWindow.Milliseconds() {
		return nil, errors.New("sealed answer: clock")
	}
	ep, err := ecdh.X25519().NewPublicKey(e)
	if err != nil {
		return nil, errors.New("sealed answer: key")
	}
	shared, err := id.x.ECDH(ep)
	if err != nil {
		return nil, errors.New("sealed answer: key")
	}
	key, _ := hkdf.Key(sha256.New, shared, nil, "ulrmm seal v1\x00"+agentID+path, 32)
	plain, err := unseal(key, make([]byte, 12), c, []byte(path))
	if err != nil {
		return nil, errors.New("sealed answer: decrypt")
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
	if !a.registered() {
		return t.base.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	req.Header.Set(sealAsk, "1")
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get(sealMarker) != "1" {
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
	return resp, nil
}
