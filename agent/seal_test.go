// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// sealAnswer seals plain for path the way the server does.
func sealAnswer(t *testing.T, a *Agent, cmd ed25519.PrivateKey, path string, plain []byte) []byte {
	t.Helper()
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := e.ECDH(a.sec2.ident.Load().x.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, "ulrmm seal v1\x00"+a.AgentID+path, 32)
	if err != nil {
		t.Fatal(err)
	}
	c := seal(key, make([]byte, 12), plain, []byte(path))
	ep, tms := e.PublicKey().Bytes(), a.serverNowMs()
	b64 := base64.StdEncoding.EncodeToString
	b, _ := json.Marshal(sealedBody{V: 2, Kid: keyID(cmd.Public().(ed25519.PublicKey)), E: b64(ep), C: b64(c), T: tms,
		G: b64(ed25519.Sign(cmd, sealSigned(a.AgentID, path, ep, tms, c)))})
	return b
}

type statusRT struct {
	status int
	hdr    http.Header
	body   []byte
}

func (f *statusRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Header: f.hdr.Clone(), Body: io.NopCloser(bytes.NewReader(f.body)), Request: r}, nil
}

func imagingHdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func imagingTrip(a *Agent, rt http.RoundTripper, method, path string) (*http.Response, error) {
	req, _ := http.NewRequest(method, "https://rmm"+path, nil)
	return (&sealTransport{base: rt, a: a}).RoundTrip(req)
}

const (
	pollPath   = "/api/v3/x/imaging/"
	configPath = "/api/v3/x/imaging/config/"
)

func TestImagingPathsNotInSealedPaths(t *testing.T) {
	for _, c := range []struct{ method, path string }{{"POST", pollPath}, {"GET", configPath}} {
		if sealedPath(c.method, c.path) || !imagingSealedPath(c.method, c.path) {
			t.Errorf("%s %s: sealed list %v, imaging list %v", c.method, c.path, sealedPath(c.method, c.path), imagingSealedPath(c.method, c.path))
		}
	}
	for _, c := range []struct{ method, path string }{{"GET", pollPath}, {"POST", configPath}, {"POST", "/api/v3/x/imaging/extra/"}} {
		if imagingSealedPath(c.method, c.path) {
			t.Errorf("%s %s is on the imaging list", c.method, c.path)
		}
	}
}

func refusedImaging(t *testing.T, a *Agent, method, path string) {
	t.Helper()
	a.events = nil
	_, err := imagingTrip(a, &statusRT{status: 200, hdr: imagingHdr(imagingConfigHeader, "3"), body: []byte(`{"claim":"c"}`)}, method, path)
	if err == nil || err.Error() != "refusing an unsealed imaging answer from "+path {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if len(a.events) != 1 || a.events[0].Kind != "envelope_refused" {
		t.Fatalf("security events %+v", a.events)
	}
}

func TestRefuseUnsealedImagingNotArmed(t *testing.T) {
	a, _ := sec2Agent(t, loadVectors(t))
	a.pins.Load().Sec2 = "off"
	refusedImaging(t, a, "POST", pollPath)
	refusedImaging(t, a, "GET", configPath)
	a.sec2.kid.Store(nil)
	refusedImaging(t, a, "POST", pollPath)
	// a seal marker counts only on an answer the transport opened
	if _, err := imagingTrip(a, &statusRT{status: 200, hdr: imagingHdr(imagingConfigHeader, "3", sealMarker, "1")}, "POST", pollPath); err == nil {
		t.Fatal("an unregistered agent took a marked answer it cannot open")
	}
}

func TestRefuseUnsealedImagingArmed(t *testing.T) {
	a, _ := sec2Agent(t, loadVectors(t))
	refusedImaging(t, a, "POST", pollPath)
	refusedImaging(t, a, "GET", configPath)
}

func TestAllow204UnsealedBothArmedStates(t *testing.T) {
	a, _ := sec2Agent(t, loadVectors(t))
	for _, sec2 := range []string{"optional", "off"} {
		a.pins.Load().Sec2 = sec2
		for _, h := range []http.Header{imagingHdr(imagingConfigHeader, "3"), imagingHdr()} {
			resp, err := imagingTrip(a, &statusRT{status: 204, hdr: h}, "POST", pollPath)
			if err != nil || resp.StatusCode != 204 {
				t.Fatalf("%s %v: %v", sec2, h, err)
			}
		}
	}
	if !a.imagingHeaderSeen() {
		t.Fatal("a 204 with the version did not count as seen")
	}
}

func TestOldServerGrantAcceptedWhenArmed(t *testing.T) {
	a, _ := sec2Agent(t, loadVectors(t))
	if !a.sec2Armed() {
		t.Fatal("vector agent not armed")
	}
	resp, err := imagingTrip(a, &statusRT{status: 200, hdr: imagingHdr(), body: []byte(`{"claim":"c"}`)}, "POST", pollPath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"claim":"c"}` || resp.Header.Get(imagingOpened) != "" {
		t.Fatalf("%s marker %q", body, resp.Header.Get(imagingOpened))
	}
}

func TestNoHeaderAfterHeaderSeenRefused(t *testing.T) {
	a, _ := sec2Agent(t, loadVectors(t))
	a.pins.Load().Sec2 = "off"
	if _, err := imagingTrip(a, &statusRT{status: 204, hdr: imagingHdr(imagingConfigHeader, "1")}, "POST", pollPath); err != nil {
		t.Fatal(err)
	}
	if _, err := imagingTrip(a, &statusRT{status: 200, hdr: imagingHdr(), body: []byte(`{"claim":"c"}`)}, "POST", pollPath); err == nil {
		t.Fatal("a 200 without the version passed after the version was seen")
	}
	if _, err := imagingTrip(a, &statusRT{status: 200, hdr: imagingHdr(), body: []byte(`{}`)}, "GET", "/api/v3/x/selfheal/"); err != nil {
		t.Fatal("the rule reached another path:", err)
	}
}

func TestOpenedMarkerSetOnlyAfterSeal(t *testing.T) {
	a, cmd := sec2Agent(t, loadVectors(t))
	resp, err := imagingTrip(a, &statusRT{status: 200, hdr: imagingHdr(imagingOpened, "1")}, "POST", pollPath)
	if err != nil || resp.Header.Get(imagingOpened) != "" {
		t.Fatalf("incoming marker kept: %v %v", resp, err)
	}
	plain := []byte(`{"claim":"c","run":"r"}`)
	rt := &statusRT{status: 200, hdr: imagingHdr(imagingConfigHeader, "2", sealMarker, "1"), body: sealAnswer(t, a, cmd, pollPath, plain)}
	resp, err = imagingTrip(a, rt, "POST", pollPath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, plain) || resp.Header.Get(imagingOpened) != "1" {
		t.Fatalf("%s marker %q", body, resp.Header.Get(imagingOpened))
	}
}

func TestHeaderSeenExpires(t *testing.T) {
	a, _ := sec2Agent(t, loadVectors(t))
	grant := &statusRT{status: 200, hdr: imagingHdr(), body: []byte(`{"claim":"c"}`)}
	a.imaging.headerAt.Store(time.Now().Add(-23 * time.Hour).UnixMilli())
	if _, err := imagingTrip(a, grant, "POST", pollPath); err == nil {
		t.Fatal("a 200 without the version passed within a day of the last version")
	}
	a.imaging.headerAt.Store(time.Now().Add(-25 * time.Hour).UnixMilli())
	if _, err := imagingTrip(a, grant, "POST", pollPath); err != nil {
		t.Fatal("an old server's grant stays refused after a day:", err)
	}
}
