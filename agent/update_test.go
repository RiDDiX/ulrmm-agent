// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/ugorji/go/codec"
)

func testUpdateAgent() *Agent {
	l := logrus.New()
	l.SetOutput(new(strings.Builder))
	return &Agent{Logger: l}
}

func TestFetchFileChecksSha256(t *testing.T) {
	body := []byte("new agent build")
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
	defer ts.Close()
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	a := testUpdateAgent()
	a.Cert = writeCA(t, ts)
	dest := filepath.Join(t.TempDir(), "update")

	for _, want := range []string{good, strings.ToUpper(good), ""} {
		if err := a.fetchFile(ts.URL, dest, want, time.Minute); err != nil {
			t.Fatalf("want %q: %v", want, err)
		}
		if b, _ := os.ReadFile(dest); string(b) != string(body) {
			t.Fatalf("want %q: file holds %q", want, b)
		}
	}

	bad := strings.Repeat("0", 64)
	if err := a.fetchFile(ts.URL, dest, bad, time.Minute); err == nil {
		t.Fatal("a download with the wrong sha256 was accepted")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("the refused download is still on disk")
	}
}

func writeCA(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUpdateDownloadTrustsCustomCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("x")) }))
	defer ts.Close()
	dest := filepath.Join(t.TempDir(), "update")

	a := testUpdateAgent()
	if err := a.selfHealFetch(ts.URL, dest); err == nil {
		t.Fatal("an unknown CA was trusted without --cert")
	}
	a.Cert = writeCA(t, ts)
	if err := a.selfHealFetch(ts.URL, dest); err != nil {
		t.Fatalf("custom CA not used: %v", err)
	}
}

// NATS takes the RMM's trust: the custom CA works, an unknown one does not.
func TestNatsOptionsUseRMMTrust(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	a := testUpdateAgent()
	a.ApiURL = "127.0.0.1"
	natsTLS := func() *tls.Config {
		o := nats.GetDefaultOptions()
		for _, opt := range a.setupNatsOptions() {
			if err := opt(&o); err != nil {
				t.Fatal(err)
			}
		}
		if o.TLSConfig == nil || o.TLSConfig.MinVersion != tls.VersionTLS13 || o.TLSConfig.VerifyConnection == nil {
			t.Fatalf("NATS TLS config: %+v", o.TLSConfig)
		}
		return o.TLSConfig
	}
	if c, err := tls.Dial("tcp", ts.Listener.Addr().String(), natsTLS()); err == nil {
		c.Close()
		t.Fatal("NATS trusted an unknown CA")
	}
	a.Cert = writeCA(t, ts)
	c, err := tls.Dial("tcp", ts.Listener.Addr().String(), natsTLS())
	if err != nil {
		t.Fatalf("NATS does not trust the custom CA: %v", err)
	}
	c.Close()
}

// NATS retries refused handshakes every few seconds: the reason is logged
// once, and once more when it changes.
func TestNatsTLSRefusalLoggedOnChange(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	a := testUpdateAgent()
	a.ApiURL = "127.0.0.1"
	log := a.Logger.Out.(*strings.Builder)
	dial := func() {
		o := nats.GetDefaultOptions()
		for _, opt := range a.setupNatsOptions() {
			if err := opt(&o); err != nil {
				t.Fatal(err)
			}
		}
		if c, err := tls.Dial("tcp", ts.Listener.Addr().String(), o.TLSConfig); err == nil {
			c.Close()
		}
	}
	for i := 0; i < 3; i++ {
		dial()
	}
	if n := strings.Count(log.String(), "was refused"); n != 1 || !strings.Contains(log.String(), "unknown authority") {
		t.Fatalf("%d refusals logged: %s", n, log.String())
	}
	a.Cert = writeCA(t, ts)
	dial()
	dial()
	if n := strings.Count(log.String(), "accepted again"); n != 1 || strings.Count(log.String(), "was refused") != 1 {
		t.Fatalf("after the fix: %s", log.String())
	}
}

func TestAgentUpdateSha256FromServer(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	for _, msg := range []map[string]interface{}{
		{"func": "agentupdate", "sha256": sha, "payload": map[string]string{"url": "u"}},
		{"func": "agentupdate", "payload": map[string]string{"url": "u", "sha256": sha}},
	} {
		var b []byte
		if err := codec.NewEncoderBytes(&b, new(codec.MsgpackHandle)).Encode(msg); err != nil {
			t.Fatal(err)
		}
		var p *NatsMsg
		var mh codec.MsgpackHandle
		mh.RawToString = true
		if err := codec.NewDecoderBytes(b, &mh).Decode(&p); err != nil {
			t.Fatal(err)
		}
		if got := p.updateSha256(); got != sha {
			t.Fatalf("%v: got %q", msg, got)
		}
	}
}
