// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSelfTestHandshake(t *testing.T) {
	ca := newTestCA(t, "test agent CA")
	now := time.Now()
	valid := ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour))
	// the health view is mounted under core/, not under the agent API
	health := func(code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/core/health/" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(code)
		})
	}
	required := quietTLSServer(t, health(http.StatusOK), &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.pool})
	forbidden := quietTLSServer(t, health(http.StatusForbidden), &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool})
	down := quietTLSServer(t, health(http.StatusServiceUnavailable), &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool})

	a := testUpdateAgent()
	a.ApiURL, a.AgentID, a.Token, a.Version = "127.0.0.1", "agent-1", "tok", "2.27.10.2026"
	a.Cert = writeCA(t, required)
	a.BaseURL = required.URL
	a.clientCert.Store(valid)
	out, err := a.SelfTest(10 * time.Second)
	if err != nil || !strings.HasPrefix(out, "selftest ok 2.27.10.2026") || !strings.Contains(out, "certificate sent") {
		t.Fatalf("%q %v", out, err)
	}

	// the handshake is the test: a 403 from the health endpoint still passes
	a.Cert, a.BaseURL = writeCA(t, forbidden), forbidden.URL
	out, err = a.SelfTest(10 * time.Second)
	if err != nil || !strings.HasPrefix(out, "selftest ok") || !strings.Contains(out, "403") {
		t.Fatalf("403: %q %v", out, err)
	}
	// a 5xx and a closed port are the server's problem, not this build's
	a.Cert, a.BaseURL = writeCA(t, down), down.URL
	if _, err := a.SelfTest(10 * time.Second); err == nil || !strings.Contains(err.Error(), "503") || !errors.Is(err, ErrTransient) {
		t.Fatalf("503: %v", err)
	}
	gone := quietTLSServer(t, health(http.StatusOK), &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool})
	a.Cert, a.BaseURL = writeCA(t, gone), gone.URL
	gone.Close()
	if _, err := a.SelfTest(10 * time.Second); err == nil || !errors.Is(err, ErrTransient) {
		t.Fatalf("refused: %v", err)
	}

	a.Cert, a.BaseURL = writeCA(t, required), required.URL
	a.Token = ""
	if _, err := a.SelfTest(10 * time.Second); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("no token: %v", err)
	}
	a.Token, a.BaseURL = "tok", "http://127.0.0.1"
	if _, err := a.SelfTest(10 * time.Second); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http: %v", err)
	}
}

func TestShouldRevert(t *testing.T) {
	for _, c := range []struct{ connected, previous, want bool }{
		{false, true, true},
		{true, true, false},
		{false, false, false},
		{true, false, false},
	} {
		if got := shouldRevert(c.connected, c.previous); got != c.want {
			t.Fatalf("connected %v previous %v: %v", c.connected, c.previous, got)
		}
	}
}

func TestSelfTestRejectsWithoutClientCert(t *testing.T) {
	ca, other := newTestCA(t, "test agent CA"), newTestCA(t, "other CA")
	now := time.Now()
	required := mtlsServer(t, ca, tls.RequireAndVerifyClientCert)
	a := testUpdateAgent()
	a.ApiURL, a.AgentID, a.Token, a.Version = "127.0.0.1", "agent-1", "tok", "2.27.10.2026"
	a.Cert, a.BaseURL = writeCA(t, required), required.URL
	for name, cert := range map[string]*tls.Certificate{
		"none":     nil,
		"other CA": other.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour)),
		"expired":  ca.pair(t, "agent-1", now.Add(-2*time.Hour), now.Add(-time.Hour)),
	} {
		a.clientCert.Store(cert)
		if out, err := a.SelfTest(10 * time.Second); err == nil || errors.Is(err, ErrTransient) {
			t.Fatalf("%s: %v %q", name, err, out)
		}
	}
	// an unknown server CA fails the handshake before any request
	a.Cert = ""
	a.clientCert.Store(ca.pair(t, "agent-1", now.Add(-time.Minute), now.Add(time.Hour)))
	if _, err := a.SelfTest(10 * time.Second); err == nil || !strings.Contains(err.Error(), "handshake") || errors.Is(err, ErrTransient) {
		t.Fatalf("unknown CA: %v", err)
	}
}
