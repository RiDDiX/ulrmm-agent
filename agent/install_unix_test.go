// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
)

func TestAgentConfigIsOwnerOnly(t *testing.T) {
	old := etcConfig
	defer func() { etcConfig = old }()
	etcConfig = filepath.Join(t.TempDir(), "agent.json")

	createAgentConfig("https://api", "id", "api", "token", "1", "", "", "", "", "")
	if st, err := os.Stat(etcConfig); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("new config: %v %v", st.Mode().Perm(), err)
	}

	os.Chmod(etcConfig, 0660)
	(&Agent{}).RunMigrations()
	if st, _ := os.Stat(etcConfig); st.Mode().Perm() != 0600 {
		t.Fatalf("existing config left at %v", st.Mode().Perm())
	}
}

func TestRunScriptLogsNoOutputOrArgs(t *testing.T) {
	var log strings.Builder
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	l.SetOutput(&log)
	a := &Agent{Logger: l, UnixTmpDir: t.TempDir()}

	out, _, _, err := a.RunScript("#!/bin/sh\necho out-$1", "/bin/sh", []string{"secret-arg"}, 30, false, nil, false, "")
	if err != nil || !strings.Contains(out, "out-secret-arg") {
		t.Fatalf("script did not run: %q %v", out, err)
	}
	if strings.Contains(log.String(), "secret-arg") {
		t.Fatalf("debug log holds script output or arguments:\n%s", log.String())
	}
}

func TestUninstallCodeRoundTrip(t *testing.T) {
	old := etcConfig
	defer func() { etcConfig = old }()
	etcConfig = filepath.Join(t.TempDir(), "agent.json")

	// not installed: nothing stored, nothing to check
	if code, err := confValue(confUninstallKey); code != "" || err != nil {
		t.Fatalf("no config: %q %v", code, err)
	}

	createAgentConfig("https://api", "id", "api", "token", "1", "", "", "", "", "")
	code, sent, err := ensureUninstallCode()
	if err != nil || len(code) != uninstallCodeLen || sent {
		t.Fatalf("install wrote %q sent=%v %v", code, sent, err)
	}
	if err := checkUninstallCode(code); err != nil {
		t.Fatalf("right code refused: %v", err)
	}
	for _, bad := range []string{"", code[:31], code + "x", "wrong"} {
		if checkUninstallCode(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}

	(&Agent{Logger: logrus.New()}).startupReported(map[string]interface{}{"uninstall_code": code})
	again, sent, _ := ensureUninstallCode()
	if again != code || !sent {
		t.Fatalf("code changed or ack lost: %q %v", again, sent)
	}
	if st, _ := os.Stat(etcConfig); st.Mode().Perm() != 0600 {
		t.Fatalf("config mode %v", st.Mode().Perm())
	}
	if tok, _ := confValue("token"); tok != "token" {
		t.Fatalf("other values lost: %q", tok)
	}

	// an agent from before the code existed gets one on start
	if err := os.WriteFile(etcConfig, []byte(`{"agentid": "id", "natspinginterval": 30}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if checkUninstallCode("") != nil {
		t.Fatal("agent without a code refused")
	}
	code, sent, err = ensureUninstallCode()
	if err != nil || len(code) != uninstallCodeLen || sent || checkUninstallCode(code) != nil {
		t.Fatalf("upgrade path: %q %v %v", code, sent, err)
	}
}

// A macOS reinstall reads the old config, removes the file and
// writes the new one: the old ack must not cover the new code.
func TestReinstallSendsNewUninstallCode(t *testing.T) {
	old := etcConfig
	defer func() { etcConfig = old }()
	etcConfig = filepath.Join(t.TempDir(), "agent.json")

	createAgentConfig("https://api", "id", "api", "token", "1", "", "", "", "", "")
	first, _, _ := ensureUninstallCode()
	(&Agent{Logger: logrus.New()}).startupReported(map[string]interface{}{"uninstall_code": first})

	if _, err := readConfFile(); err != nil {
		t.Fatal(err)
	}
	os.Remove(etcConfig)
	createAgentConfig("https://api", "id2", "api", "token2", "2", "", "", "", "", "")
	code, sent, err := ensureUninstallCode()
	if err != nil || code == first || sent {
		t.Fatalf("new install: %q sent=%v %v", code, sent, err)
	}
}

func TestRenewClientCert(t *testing.T) {
	old := etcConfig
	defer func() { etcConfig = old }()
	etcConfig = filepath.Join(t.TempDir(), "agent.json")
	createAgentConfig("https://api", "agent-r", "api", "token", "1", "", "", "", "", "")

	ca := newTestCA(t, "test agent CA")
	life := 180 * 24 * time.Hour
	var calls, status atomic.Int32
	status.Store(http.StatusOK)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			CSR string `json:"csr"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/agent-r/cert/" || json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if s := int(status.Load()); s != http.StatusOK {
			w.WriteHeader(s)
			return
		}
		now := time.Now()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"cert": ca.issue(t, body.CSR, now.Add(-5*time.Minute), now.Add(life))})
	}))
	defer ts.Close()
	a := testUpdateAgent()
	a.AgentID = "agent-r"
	a.rClient = resty.New().SetBaseURL(ts.URL)
	now := time.Now()

	// an agent from before mTLS gets its first certificate
	a.renewClientCert(now)
	first := a.clientCert.Load()
	if calls.Load() != 1 || first == nil || first.Leaf.Subject.CommonName != "agent-r" {
		t.Fatalf("first issuance: %d calls", calls.Load())
	}
	cfg := NewAgentConfig()
	if c, err := keyPair(cfg.TLSCert, cfg.TLSKey); err != nil || !c.Leaf.Equal(first.Leaf) || cfg.AuthToken != "token" {
		t.Fatalf("stored config: %v", err)
	}
	if st, _ := os.Stat(etcConfig); st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", st.Mode().Perm())
	}
	if n := New(a.Logger, "v"); n.clientCert.Load() == nil || !n.clientCert.Load().Leaf.Equal(first.Leaf) {
		t.Fatal("a new process does not load the stored certificate")
	}

	a.renewClientCert(now.Add(life / 2))
	if calls.Load() != 1 {
		t.Fatal("renewed a certificate with half its lifetime left")
	}
	a.renewClientCert(now.Add(life*2/3 + time.Hour))
	if second := a.clientCert.Load(); calls.Load() != 2 || second == first || NewAgentConfig().TLSKey == cfg.TLSKey {
		t.Fatal("no renewal with a fresh key after two thirds of the lifetime")
	}

	late := now.Add(10 * life)
	for _, code := range []int32{409, 403, 404} {
		status.Store(code)
		a.certRetry = time.Time{}
		n := calls.Load()
		a.renewClientCert(late)
		a.renewClientCert(late.Add(certRetryAfter - time.Minute))
		if calls.Load() != n+1 {
			t.Fatalf("%d: asked again during the backoff", code)
		}
		a.renewClientCert(late.Add(certRetryAfter + time.Minute))
		if calls.Load() != n+2 {
			t.Fatalf("%d: no new request after the backoff", code)
		}
	}
	status.Store(http.StatusInternalServerError)
	a.certRetry = time.Time{}
	n := calls.Load()
	a.renewClientCert(late)
	a.renewClientCert(late.Add(5 * time.Minute))
	if calls.Load() != n+2 {
		t.Fatal("a server error must not pause the renewal")
	}
}

// A newer pin document goes into the config of the service; the next
// process starts with it.
func TestPinsStoredInConfig(t *testing.T) {
	key := testEnrollKey(t)
	old := etcConfig
	defer func() { etcConfig = old }()
	etcConfig = filepath.Join(t.TempDir(), "agent.json")
	createAgentConfig("https://127.0.0.1", "id", "127.0.0.1", "token", "1", "", "", "", "", "")
	a := testUpdateAgent()
	a.ApiURL = "127.0.0.1"
	leaf := testLeaf(t, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	pin := spkiPin(leaf.Certificate[0])
	cs := &tls.ConnectionState{PeerCertificates: parsed(t, leaf.Certificate[0])}
	setService := func(on bool) {
		confTrust.Lock()
		confTrust.service = on
		confTrust.Unlock()
	}
	confTrust.Lock()
	was := confTrust.service
	confTrust.Unlock()
	t.Cleanup(func() { setService(was) })
	// another mode takes the document in memory only: only the service
	// writes the pins together with the trust snapshot
	setService(false)
	if ok, err := a.acceptPinDoc(pinDoc(key, "https://127.0.0.1", 7, pin), cs); !ok || err != nil || a.pins.Load().Seq != 7 {
		t.Fatalf("accept: %v %v", ok, err)
	}
	if v, _ := confValue(confPins); v != "" {
		t.Fatal("stored outside the service:", v)
	}
	a.pins.Store(nil)
	setService(true)
	if ok, err := a.acceptPinDoc(pinDoc(key, "https://127.0.0.1", 7, pin), cs); !ok || err != nil {
		t.Fatalf("accept: %v %v", ok, err)
	}
	if n := New(a.Logger, "v"); n.pins.Load() == nil || n.pins.Load().Seq != 7 || n.pins.Load().Primary[0] != pin {
		t.Fatalf("loaded %+v", n.pins.Load())
	}
	if ok, _ := a.acceptPinDoc(pinDoc(key, "https://127.0.0.1", 7, pin), cs); ok {
		t.Fatal("the same seq was taken again")
	}
}

// a reinstall over an install with a live keep-awake hold puts the sleep
// setting back before keepawake.json is deleted
func TestRemoveOldInstallReleasesKeepAwake(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldDir, oldUndo := awakeStateDir, undoLid
	t.Cleanup(func() { awakeStateDir, undoLid = oldDir, oldUndo })
	awakeStateDir = func() string { return dir }
	var undone string
	undoLid = func(st awakeState) error {
		if _, err := os.Stat(awakeStateFile()); err != nil {
			t.Error("state file gone before the release")
		}
		undone = st.DisableSleep
		return nil
	}
	if err := saveAwakeState(awakeState{Until: time.Now().Unix() + 600, DisableSleep: "0"}); err != nil {
		t.Fatal(err)
	}
	testUpdateAgent().removeOldInstall(dir)
	if undone != "0" {
		t.Fatalf("sleep setting not put back: %q", undone)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("old install still there: %v", err)
	}
}
