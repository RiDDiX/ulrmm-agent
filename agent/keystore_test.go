// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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

// Tests never reach the real systemd-creds or keychain of the host.
func init() {
	credsBins = nil
	securityBin = "/nonexistent/security"
}

func keystoreHost(t *testing.T, goos string) *Agent {
	t.Helper()
	oldConf, oldOS, oldRun, oldBins, oldNAS := etcConfig, keystoreOS, runTool, credsBins, onTrueNAS
	t.Cleanup(func() {
		etcConfig, keystoreOS, runTool, credsBins, onTrueNAS = oldConf, oldOS, oldRun, oldBins, oldNAS
		dropKEKCache()
	})
	etcConfig = filepath.Join(t.TempDir(), "agent.json")
	keystoreOS = goos
	dropKEKCache()
	createAgentConfig("https://api", "agent-k", "api", "legacy-token", "1", "", "", "", "", "")
	a := &Agent{Logger: logrus.New()}
	a.Logger.SetOutput(io.Discard)
	return a
}

// dropKEKCache is a new process: the KEK is read from its store again.
func dropKEKCache() {
	kekCache.Lock()
	kekCache.key = nil
	kekCache.Unlock()
}

func TestKEKSealing(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	s := sealKEK(key, "Refresh", []byte("secret"))
	if !strings.HasPrefix(s, wrapKEK) || strings.Contains(s, "secret") {
		t.Fatal(s)
	}
	if b, err := openKEK(key, "Refresh", s); err != nil || string(b) != "secret" {
		t.Fatal(b, err)
	}
	if sealKEK(key, "Refresh", []byte("secret")) == s {
		t.Error("nonce reused")
	}
	// the value name is bound: a value copied to another name does not open
	if _, err := openKEK(key, "Token", s); err == nil {
		t.Error("wrong AAD accepted")
	}
	if _, err := openKEK(bytes.Repeat([]byte{8}, 32), "Refresh", s); err == nil {
		t.Error("other key accepted")
	}
	raw, _ := base64.StdEncoding.DecodeString(s[len(wrapKEK):])
	raw[len(raw)-1] ^= 1
	if _, err := openKEK(key, "Refresh", wrapKEK+base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("tampered value accepted")
	}
	for _, bad := range []string{wrapKEK + "%%", wrapKEK + "AAAA"} {
		if _, err := openKEK(key, "Refresh", bad); err == nil {
			t.Errorf("%q opened", bad)
		}
	}
}

// One service start moves plaintext and raw1 secrets under the KEK; the
// values read the same, and a second start changes nothing.
func TestKeystoreMigratesRaw1AndPlain(t *testing.T) {
	a := keystoreHost(t, "freebsd")
	code, _, _ := ensureUninstallCode()
	seed := newSeed()
	_ = setConfValues(map[string]string{
		confClientKey:    "-----BEGIN EC PRIVATE KEY-----\nk\n-----END EC PRIVATE KEY-----\n",
		confRefresh:      wrapRaw + base64.StdEncoding.EncodeToString([]byte("refresh-1")),
		confIdentityKey:  wrapRaw + base64.StdEncoding.EncodeToString(seed),
		confUninstallAck: code, // as 3.25.10.2026 wrote it
	})
	before := map[string]string{}
	for _, n := range secretNames {
		v, _ := confValue(n)
		before[n], _ = func() (string, error) { b, err := unwrapSecret(n, v); return string(b), err }()
	}

	a.setupKeystore()
	if ks, _ := confValue(confKeyStore); ks != "file" {
		t.Fatalf("keystore %q", ks)
	}
	if st, err := os.Stat(kekFile()); err != nil || st.Mode().Perm() != 0o600 || st.Size() != kekLen {
		t.Fatalf("kek file: %v %v", st, err)
	}
	after := map[string]string{}
	for _, n := range secretNames {
		v, _ := confValue(n)
		after[n] = v
		if before[n] == "" {
			continue
		}
		if !strings.HasPrefix(v, wrapKEK) {
			t.Errorf("%s not moved: %q", n, v)
		}
		dropKEKCache()
		if b, err := unwrapSecret(n, v); err != nil || string(b) != before[n] {
			t.Errorf("%s reads %q %v", n, b, err)
		}
	}
	raw, _ := os.ReadFile(etcConfig)
	for _, plain := range []string{"legacy-token", code, "refresh-1", "BEGIN EC"} {
		if bytes.Contains(raw, []byte(plain)) {
			t.Errorf("%q still in the config", plain)
		}
	}
	if s, _ := confValue(confUninstallSum); s != codeSum(code) {
		t.Error("uninstall sum", s)
	}
	if got, sent, err := ensureUninstallCode(); got != code || !sent || err != nil {
		t.Errorf("uninstall code after the move: %v %v", sent, err)
	}
	if checkUninstallCode(code) != nil || checkUninstallCode("x") == nil {
		t.Error("uninstall code check")
	}
	if ack, _ := confValue(confUninstallAck); ack != codeSum(code) {
		t.Error("ack holds the code")
	}

	// a new process reads the token and the client key through the KEK
	dropKEKCache()
	if n := New(a.Logger, "v"); n.Token != "legacy-token" || n.Headers["Authorization"] != "Token legacy-token" {
		t.Errorf("token %q", n.Token)
	}
	cfg := NewAgentConfig()
	if err := openConfigSecrets(cfg); err != nil || cfg.TLSKey != before[confClientKey] {
		t.Error("client key", err)
	}

	a.setupKeystore()
	for _, n := range secretNames {
		if v, _ := confValue(n); v != after[n] {
			t.Errorf("second start rewrote %s", n)
		}
	}
	// new writes go under the KEK
	if s, err := wrapSecret(confRefresh, []byte("r2")); err != nil || !strings.HasPrefix(s, wrapKEK) {
		t.Error(s, err)
	}
}

func TestKeystoreMigratesDPAPI(t *testing.T) {
	a := keystoreHost(t, "freebsd")
	old := dpapiOpen
	t.Cleanup(func() { dpapiOpen = old })
	dpapiOpen = func(b []byte) ([]byte, error) {
		if string(b) != "blob" {
			return nil, errUnwrap
		}
		return []byte("seed-from-dpapi"), nil
	}
	_ = setConfValues(map[string]string{
		confRefresh:     wrapDPAPI + base64.StdEncoding.EncodeToString([]byte("blob")),
		confIdentityKey: wrapDPAPI + base64.StdEncoding.EncodeToString([]byte("other")),
	})
	a.setupKeystore()
	v, _ := confValue(confRefresh)
	if b, err := unwrapSecret(confRefresh, v); !strings.HasPrefix(v, wrapKEK) || err != nil || string(b) != "seed-from-dpapi" {
		t.Fatalf("dpapi1 not moved: %q %v", v, err)
	}
	// a value that does not open is kept as it is, never dropped
	if v, _ := confValue(confIdentityKey); v != wrapDPAPI+base64.StdEncoding.EncodeToString([]byte("other")) {
		t.Errorf("unreadable value changed: %q", v)
	}
}

// A KEK that does not open is reported, nothing is written in the clear,
// and the stored values stay for a start where it opens again.
func TestKeystoreUnreadable(t *testing.T) {
	a := keystoreHost(t, "freebsd")
	a.setupKeystore()
	tok, _ := confValue("Token")
	kek, _ := os.ReadFile(kekFile())
	os.Remove(kekFile())
	dropKEKCache()

	b := &Agent{Logger: a.Logger}
	b.setupKeystore()
	if len(b.events) != 1 || b.events[0].Kind != "identity_unreadable" || !strings.HasPrefix(b.events[0].Detail, "kek file: ") {
		t.Fatalf("events %+v", b.events)
	}
	if _, err := wrapSecret(confRefresh, []byte("r")); err == nil {
		t.Error("wrapped without the KEK")
	}
	if err := protect(confRefresh, []byte("r")); err == nil {
		t.Error("stored without the KEK")
	}
	if b.loadIdentity() != nil {
		t.Error("an identity was stored without the KEK")
	}
	if len(b.events) != 1 {
		t.Errorf("the identity reports the same reason once: %+v", b.events)
	}
	cfg := NewAgentConfig()
	if err := openConfigSecrets(cfg); err == nil || cfg.AuthToken != "" || !strings.Contains(err.Error(), "kek file") {
		t.Errorf("token %q %v", cfg.AuthToken, err)
	}
	if v, _ := confValue("Token"); v != tok {
		t.Error("the token was rewritten")
	}
	if ks, _ := confValue(confKeyStore); ks != "file" {
		t.Error("keystore replaced", ks)
	}
	// the store is back: everything opens again
	_ = os.WriteFile(kekFile(), kek, 0o600)
	dropKEKCache()
	if err := openConfigSecrets(cfg); err != nil {
		t.Error(err)
	}
}

type fakeTools struct {
	calls    []string
	ver      string
	tpm      bool
	failPut  bool
	keychain string
	stdin    []string
	// the TPM was cleared: what it sealed before does not open
	tpmCleared bool
}

func (f *fakeTools) run(stdin []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	if args[0] == "-i" {
		// security -i: one command line on stdin
		f.stdin = append(f.stdin, string(stdin))
		args = strings.Fields(string(stdin))
	}
	switch args[0] {
	case "--version":
		return []byte("systemd " + f.ver + " (" + f.ver + ".19-1)\n+PAM +AUDIT\n"), nil
	case "has-tpm2":
		if f.tpm {
			return []byte("yes\n"), nil
		}
		return []byte("partial\n"), errors.New("exit status 1")
	case "encrypt":
		if f.failPut {
			return nil, errors.New("exit status 1")
		}
		if args[2] == "--with-key=auto" {
			f.tpmCleared = false
		}
		return nil, os.WriteFile(args[len(args)-1], append([]byte("CRED"), stdin...), 0o644)
	case "decrypt":
		if f.tpmCleared && args[2] == kekCred() {
			return nil, errors.New("exit status 1 Failed to unseal secret using TPM2")
		}
		b, err := os.ReadFile(args[2])
		if err != nil || !bytes.HasPrefix(b, []byte("CRED")) || args[3] != "-" {
			return nil, errors.New("bad credential")
		}
		return b[4:], nil
	case "add-generic-password":
		if f.failPut {
			return nil, errors.New("exit status 45")
		}
		f.keychain = args[len(args)-2]
		return nil, nil
	case "find-generic-password":
		return []byte(f.keychain + "\n"), nil
	}
	return nil, errors.New("unexpected " + args[0])
}

func TestKeystoreSystemdCreds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ver    string
		tpm    bool
		bin    bool
		nas    bool
		scheme string
	}{
		{"tpm", "252", true, true, false, "creds-tpm"},
		{"host key", "255", false, true, false, "creds-host"},
		{"too old", "249", true, true, false, "file"},
		{"no systemd-creds", "252", true, false, false, "file"},
		{"truenas", "252", true, true, true, "file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := keystoreHost(t, "linux")
			onTrueNAS = tc.nas
			f := &fakeTools{ver: tc.ver, tpm: tc.tpm}
			runTool = f.run
			if tc.bin {
				bin := filepath.Join(t.TempDir(), "systemd-creds")
				_ = os.WriteFile(bin, nil, 0o755)
				credsBins = []string{bin}
			}
			a.setupKeystore()
			if ks, _ := confValue(confKeyStore); ks != tc.scheme {
				t.Fatalf("scheme %q, calls %q", ks, f.calls)
			}
			dropKEKCache()
			if tok, _ := unprotect("Token"); string(tok) != "legacy-token" {
				t.Fatal("token", tok)
			}
			if tc.scheme == "file" {
				return
			}
			if st, err := os.Stat(kekCred()); err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("credential file %v %v", st, err)
			}
			if _, err := os.Stat(kekFile()); err == nil {
				t.Error("plain KEK file written")
			}
			// no PCR binding (the default PCR 7 moves with Secure Boot
			// updates); with a TPM a copy under the host key alone
			want := []string{
				"systemd-creds --version",
				"systemd-creds has-tpm2",
				"systemd-creds encrypt --name=ulrmm-agent-kek --with-key=auto --tpm2-pcrs= - " + kekCred() + ".new",
			}
			if tc.tpm {
				want = append(want, "systemd-creds encrypt --name=ulrmm-agent-kek --with-key=host - "+kekCredHost()+".new")
			}
			want = append(want, "systemd-creds decrypt --name=ulrmm-agent-kek "+kekCred()+" -")
			if got := strings.Join(f.calls[:len(want)], "\n"); got != strings.Join(want, "\n") {
				t.Errorf("calls:\n%s", got)
			}
			if st, err := os.Stat(kekCredHost()); tc.tpm != (err == nil) || (err == nil && st.Mode().Perm() != 0o600) {
				t.Errorf("host key copy %v %v", st, err)
			}
		})
	}
}

// A TPM that no longer opens its credential: the host key copy opens the
// KEK, the loss is reported and the key is sealed to the TPM again.
func TestKeystoreTPMLostOpensCopy(t *testing.T) {
	a := keystoreHost(t, "linux")
	f := &fakeTools{ver: "257", tpm: true}
	runTool = f.run
	bin := filepath.Join(t.TempDir(), "systemd-creds")
	_ = os.WriteFile(bin, nil, 0o755)
	credsBins = []string{bin}
	a.setupKeystore()
	if ks, _ := confValue(confKeyStore); ks != "creds-tpm" {
		t.Fatal("scheme", ks)
	}

	f.tpmCleared = true
	dropKEKCache()
	// a new process: the token opens, nothing is lost
	if n := New(a.Logger, "v"); n.Token != "legacy-token" || n.notRunnable() != "" {
		t.Fatalf("token %q", n.Token)
	}
	b := &Agent{Logger: a.Logger}
	b.setupKeystore()
	if len(b.events) != 1 || b.events[0].Kind != "identity_unreadable" ||
		!strings.HasPrefix(b.events[0].Detail, "kek creds-tpm: ") || !strings.HasSuffix(b.events[0].Detail, ", opened from creds-host") {
		t.Fatalf("events %+v", b.events)
	}
	if f.tpmCleared {
		t.Fatal("not sealed to the TPM again")
	}
	dropKEKCache()
	c := &Agent{Logger: a.Logger}
	c.setupKeystore()
	if len(c.events) != 0 {
		t.Errorf("reported again: %+v", c.events)
	}
	if ks, _ := confValue(confKeyStore); ks != "creds-tpm" {
		t.Error("scheme", ks)
	}
	if tok, err := unprotect("Token"); string(tok) != "legacy-token" {
		t.Fatal(tok, err)
	}
}

// Without the copy the service names the keystore, not a missing install.
func TestNotRunnableNamesKEK(t *testing.T) {
	a := keystoreHost(t, "freebsd")
	a.setupKeystore()
	os.Remove(kekFile())
	dropKEKCache()
	n := New(a.Logger, "v")
	if why := n.notRunnable(); !strings.HasPrefix(why, "the secrets of the config do not open: kek file: ") {
		t.Fatalf("%q", why)
	}
	n.AgentID = ""
	_ = setConfValues(map[string]string{confKeyStore: ""})
	dropKEKCache()
	if why := n.notRunnable(); !strings.Contains(why, "not installed") {
		t.Fatalf("%q", why)
	}
}

func TestKeystoreKeychain(t *testing.T) {
	a := keystoreHost(t, "darwin")
	f := &fakeTools{}
	runTool = f.run
	a.setupKeystore()
	if ks, _ := confValue(confKeyStore); ks != "keychain" {
		t.Fatalf("scheme %q %q", ks, f.calls)
	}
	if k, _ := base64.StdEncoding.DecodeString(f.keychain); len(k) != kekLen {
		t.Fatal("keychain item", f.keychain)
	}
	// the key never on a command line
	if strings.Contains(strings.Join(f.calls, "\n"), f.keychain) || f.calls[0] != "security -i" ||
		f.calls[1] != "security find-generic-password -s ulrmm-agent -a kek -w /Library/Keychains/System.keychain" {
		t.Errorf("calls %q", f.calls)
	}
	if len(f.stdin) != 1 || f.stdin[0] != "add-generic-password -U -s ulrmm-agent -a kek -w "+f.keychain+" /Library/Keychains/System.keychain\n" {
		t.Errorf("stdin %q", f.stdin)
	}
	dropKEKCache()
	if tok, err := unprotect("Token"); string(tok) != "legacy-token" {
		t.Fatal(tok, err)
	}

	// a keychain that refuses the item: the root-only file
	b := keystoreHost(t, "darwin")
	runTool = (&fakeTools{failPut: true}).run
	b.setupKeystore()
	if ks, _ := confValue(confKeyStore); ks != "file" {
		t.Fatalf("fallback %q", ks)
	}
}

// A store that does not give the key back is not used.
func TestKeystoreReadBack(t *testing.T) {
	a := keystoreHost(t, "darwin")
	f := &fakeTools{}
	runTool = func(stdin []byte, name string, args ...string) ([]byte, error) {
		if args[0] == "find-generic-password" {
			return []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), nil
		}
		return f.run(stdin, name, args...)
	}
	a.setupKeystore()
	if ks, _ := confValue(confKeyStore); ks != "file" {
		t.Fatalf("scheme %q", ks)
	}
}

// The registration carries the keystore; an agent registered before it
// sends its keys once more so the server learns it.
func TestKeystoreReportedInCaps(t *testing.T) {
	f := &fakeIdentityServer{}
	a := identityAgent(t, f)
	t.Cleanup(dropKEKCache)
	oldOS := keystoreOS
	t.Cleanup(func() { keystoreOS = oldOS })
	keystoreOS = "freebsd"
	a.setupIdentity()
	if !a.registered() || strings.Join(f.caps, ",") != "sec2,ks:file" {
		t.Fatalf("caps %q", f.caps)
	}
	n := len(f.calls)
	a.reportKeyStore()
	if len(f.calls) != n {
		t.Error("reported twice")
	}
	_ = setConfValues(map[string]string{confKeyStoreSent: ""})
	f.regCode = 200
	a.reportKeyStore()
	if len(f.calls) != n+1 || f.calls[n] != "POST /api/v3/agent1/identity/" {
		t.Fatalf("not reported: %q", f.calls[n:])
	}
	if s, _ := confValue(confKeyStoreSent); s != "ks:file" {
		t.Error("sent", s)
	}
}

func TestCertDueRenewPct(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(100 * 24 * time.Hour)}
	for _, tc := range []struct {
		pct  int
		day  int
		want bool
	}{
		{75, 74, false}, {75, 76, true},
		{50, 49, false}, {50, 51, true},
		{0, 66, false}, {0, 67, true},
		{95, 67, true}, {5, 60, false},
	} {
		if got := certDue(leaf, nb.Add(time.Duration(tc.day)*24*time.Hour), tc.pct); got != tc.want {
			t.Errorf("pct %d day %d: %v", tc.pct, tc.day, got)
		}
	}
}

// The share the certificate answer names is stored and used for the next
// renewal; the new key goes under the KEK.
func TestRenewClientCertTakesRenewPct(t *testing.T) {
	keystoreHost(t, "freebsd")
	ca := newTestCA(t, "test agent CA")
	life := 100 * 24 * time.Hour
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			CSR string `json:"csr"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		now := time.Now()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"cert": ca.issue(t, body.CSR, now, now.Add(life)), "renew_pct": 50})
	}))
	defer ts.Close()
	a := testUpdateAgent()
	a.AgentID = "agent-k"
	a.rClient = resty.New().SetBaseURL(ts.URL)
	a.setupKeystore()
	now := time.Now()
	a.renewClientCert(now)
	if p, _ := confValue(confCertRenewPct); p != "50" || calls.Load() != 1 {
		t.Fatalf("renew_pct %q", p)
	}
	if k, _ := confValue(confClientKey); !strings.HasPrefix(k, wrapKEK) {
		t.Error("client key stored as", k[:10])
	}
	dropKEKCache()
	if n := New(a.Logger, "v"); n.clientCert.Load() == nil {
		t.Error("a new process does not load the certificate")
	}
	a.renewClientCert(now.Add(life * 45 / 100))
	if calls.Load() != 1 {
		t.Fatal("renewed before the share")
	}
	a.renewClientCert(now.Add(life * 55 / 100))
	if calls.Load() != 2 {
		t.Fatal("no renewal after the share the server named")
	}
}
