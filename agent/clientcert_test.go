// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

// A renewed certificate the config could not take is stored on a later
// heartbeat, without asking the server again.
func TestRenewedClientCertStoredLater(t *testing.T) {
	old := etcConfig
	defer func() { etcConfig = old }()
	conf := filepath.Join(t.TempDir(), "agent.json")
	etcConfig = conf
	createAgentConfig("https://api", "agent-s", "api", "token", "1", "", "", "", "", "")

	ca := newTestCA(t, "test agent CA")
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			CSR string `json:"csr"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		now := time.Now()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"cert": ca.issue(t, body.CSR, now.Add(-5*time.Minute), now.Add(180*24*time.Hour))})
	}))
	defer ts.Close()
	a := testUpdateAgent()
	a.AgentID = "agent-s"
	a.rClient = resty.New().SetBaseURL(ts.URL)

	// a directory in place of the config: the store fails
	etcConfig = t.TempDir()
	now := time.Now()
	a.renewClientCert(now)
	renewed := a.clientCert.Load()
	if calls.Load() != 1 || renewed == nil {
		t.Fatalf("renewal: %d calls", calls.Load())
	}

	etcConfig = conf
	a.renewClientCert(now.Add(5 * time.Minute))
	cfg := NewAgentConfig()
	if c, err := keyPair(cfg.TLSCert, cfg.TLSKey); err != nil || !c.Leaf.Equal(renewed.Leaf) || cfg.AuthToken != "token" {
		t.Fatalf("stored config: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("asked the server again: %d calls", calls.Load())
	}
}
