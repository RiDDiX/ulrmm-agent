// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// macConfig is a fresh install with an identity seed; confTrust starts off
// as in a new process.
func macConfig(t *testing.T) {
	t.Helper()
	old := etcConfig
	etcConfig = filepath.Join(t.TempDir(), "agent.json")
	reset := func() {
		confTrust.Lock()
		confTrust.on, confTrust.service, confTrust.renew, confTrust.vals = false, false, false, trustVals{}
		confTrust.Unlock()
	}
	reset()
	t.Cleanup(func() { etcConfig = old; reset() })
	createAgentConfig("https://api.example.com", "id", "api.example.com", "token", "1", "", "", "", "", "")
	setSeed(t, newSeed())
}

func setSeed(t *testing.T, m []byte) {
	t.Helper()
	if err := writeConfValues(map[string]string{confIdentityKey: wrapRaw + base64.StdEncoding.EncodeToString(m)}); err != nil {
		t.Fatal(err)
	}
}

func tamperedEvent(a *Agent) string {
	for _, e := range a.events {
		if e.Kind == "config_tampered" {
			return e.Detail
		}
	}
	return ""
}

func TestConfigMACKeepsTrustedValues(t *testing.T) {
	macConfig(t)
	a := New(testUpdateAgent().Logger, "v")
	startConfigMAC()
	if mac, _ := confValue(confConfigMAC); mac == "" || tamperedEvent(a) != "" {
		t.Fatalf("first start: mac %q, event %q", mac, tamperedEvent(a))
	}

	// a change behind the agent's back
	if err := writeConfValues(map[string]string{"ApiURL": "evil.example.com", "BaseURL": "https://evil.example.com", "Proxy": "http://evil:3128"}); err != nil {
		t.Fatal(err)
	}
	n := New(a.Logger, "v")
	if n.ApiURL != "api.example.com" || n.BaseURL != "https://api.example.com" || n.Proxy != "" {
		t.Fatalf("changed values used: %q %q %q", n.ApiURL, n.BaseURL, n.Proxy)
	}
	if !strings.HasSuffix(n.NatsServer, "api.example.com:443") {
		t.Fatalf("nats server %q", n.NatsServer)
	}
	if ev := tamperedEvent(n); !strings.Contains(ev, "ApiURL, BaseURL") || !strings.Contains(ev, "Proxy") {
		t.Fatalf("event %q", ev)
	}

	// a write of the service itself keeps the trusted values and renews the MAC
	if err := savePins(&pinSet{Seq: 3, Primary: []string{"cGlu"}}); err != nil {
		t.Fatal(err)
	}
	n = New(a.Logger, "v")
	if n.ApiURL != "api.example.com" || n.pins.Load() == nil || n.pins.Load().Seq != 3 {
		t.Fatalf("after a pin write: %q %+v", n.ApiURL, n.pins.Load())
	}
}

func TestConfigMACFollowsServiceWrites(t *testing.T) {
	macConfig(t)
	New(testUpdateAgent().Logger, "v")
	startConfigMAC()
	if err := savePins(&pinSet{Seq: 5, Primary: []string{"cGlu"}}); err != nil {
		t.Fatal(err)
	}
	// a new identity seed (rotation, admin reset) renews the MAC with it
	m := newSeed()
	if err := setConfValues(map[string]string{confIdentityKey: wrapRaw + base64.StdEncoding.EncodeToString(m)}); err != nil {
		t.Fatal(err)
	}
	n := New(testUpdateAgent().Logger, "v")
	if ev := tamperedEvent(n); ev != "" || n.pins.Load() == nil || n.pins.Load().Seq != 5 {
		t.Fatalf("event %q, pins %+v", ev, n.pins.Load())
	}
}

func TestConfigMACForged(t *testing.T) {
	macConfig(t)
	New(testUpdateAgent().Logger, "v")
	startConfigMAC()
	if err := writeConfValues(map[string]string{"ApiURL": "evil.example.com", confTrustSnapshot: trustVals{"evil.example.com"}.encode()}); err != nil {
		t.Fatal(err)
	}
	n := New(testUpdateAgent().Logger, "v")
	if tamperedEvent(n) != "the config MAC does not match" {
		t.Fatalf("event %q", tamperedEvent(n))
	}
	// reported once: the service renews the MAC over what is there now
	startConfigMAC()
	if n = New(n.Logger, "v"); tamperedEvent(n) != "" {
		t.Fatalf("reported again: %q", tamperedEvent(n))
	}
	// a snapshot without its MAC is no fresh install
	if err := writeConfValues(map[string]string{confConfigMAC: ""}); err != nil {
		t.Fatal(err)
	}
	if n = New(n.Logger, "v"); tamperedEvent(n) == "" {
		t.Fatal("a removed MAC went unnoticed")
	}
}

func TestConfigMACWaitsForSeed(t *testing.T) {
	macConfig(t)
	if err := writeConfValues(map[string]string{confIdentityKey: ""}); err != nil {
		t.Fatal(err)
	}
	New(testUpdateAgent().Logger, "v")
	startConfigMAC()
	if mac, _ := confValue(confConfigMAC); mac != "" {
		t.Fatal("a MAC without a seed")
	}
	if err := setConfValues(map[string]string{confIdentityKey: wrapRaw + base64.StdEncoding.EncodeToString(newSeed())}); err != nil {
		t.Fatal(err)
	}
	if mac, _ := confValue(confConfigMAC); mac == "" {
		t.Fatal("no MAC once the identity was stored")
	}
	if err := writeConfValues(map[string]string{"Cert": "/tmp/evil-ca.pem"}); err != nil {
		t.Fatal(err)
	}
	if n := New(testUpdateAgent().Logger, "v"); n.Cert != "" || !strings.Contains(tamperedEvent(n), "Cert") {
		t.Fatalf("cert %q, event %q", n.Cert, tamperedEvent(n))
	}
}

// A pin write of the service is one config write with the new snapshot
// and its MAC: no interruption leaves them apart.
func TestConfigMACOneWrite(t *testing.T) {
	macConfig(t)
	New(testUpdateAgent().Logger, "v")
	startConfigMAC()
	var writes []map[string]string
	old := confWrite
	t.Cleanup(func() { confWrite = old })
	confWrite = func(kv map[string]string) error {
		writes = append(writes, kv)
		return old(kv)
	}
	if err := savePins(&pinSet{Seq: 4, Primary: []string{"cGlu"}}); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 || writes[0][confPins] == "" || !strings.Contains(writes[0][confTrustSnapshot], "cGlu") || writes[0][confConfigMAC] == "" {
		t.Fatalf("writes %q", writes)
	}
}

// Only the service stores the MAC; another mode (selfheal, a task run)
// only reads it and applies the snapshot.
func TestConfigMACOnlyTheServiceWrites(t *testing.T) {
	macConfig(t)
	New(testUpdateAgent().Logger, "v")
	if err := setConfValues(map[string]string{"Proxy": ""}); err != nil {
		t.Fatal(err)
	}
	if mac, _ := confValue(confConfigMAC); mac != "" {
		t.Fatal("another mode stored the MAC")
	}
	startConfigMAC()
	if mac, _ := confValue(confConfigMAC); mac == "" {
		t.Fatal("the service did not store the MAC")
	}

	// a broken MAC: other modes report it, the config stays as it is
	confTrust.Lock()
	confTrust.service = false
	confTrust.Unlock()
	if err := writeConfValues(map[string]string{confConfigMAC: "AAAA"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(etcConfig)
	if n := New(testUpdateAgent().Logger, "v"); tamperedEvent(n) != "the config MAC does not match" {
		t.Fatal("event", tamperedEvent(n))
	}
	if after, _ := os.ReadFile(etcConfig); !bytes.Equal(before, after) {
		t.Fatal("another mode rewrote the config")
	}
}
