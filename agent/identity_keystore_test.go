// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// credsHostAgent has its KEK in systemd-creds; failOnce makes the next
// decrypt fail once, as a busy TPM or a failing systemd-creds run.
func credsHostAgent(t *testing.T) (a *Agent, failOnce func()) {
	t.Helper()
	a = keystoreHost(t, "linux")
	onTrueNAS = false
	f := &fakeTools{ver: "255"}
	runTool = f.run
	bin := filepath.Join(t.TempDir(), "systemd-creds")
	_ = os.WriteFile(bin, nil, 0o755)
	credsBins = []string{bin}
	a.setupKeystore()
	if ks, _ := confValue(confKeyStore); ks != "creds-host" {
		t.Fatal("scheme", ks)
	}
	return a, func() {
		dropKEKCache()
		failed := false
		runTool = func(stdin []byte, name string, args ...string) ([]byte, error) {
			if args[0] == "decrypt" && !failed {
				failed = true
				return nil, errors.New("exit status 1")
			}
			return f.run(stdin, name, args...)
		}
	}
}

// A keystore that does not open once keeps the stored seed: the service
// goes on without the identity and the next start opens the same one.
func TestLoadIdentityKeystoreFailsOnce(t *testing.T) {
	a, failOnce := credsHostAgent(t)
	id := a.loadIdentity()
	if id == nil {
		t.Fatal("no identity")
	}
	seed, _ := confValue(confIdentityKey)

	failOnce()
	b := &Agent{Logger: a.Logger}
	if b.loadIdentity() != nil {
		t.Error("an identity without the stored seed")
	}
	if s, _ := confValue(confIdentityKey); s != seed {
		t.Fatal("the seed was replaced")
	}
	if len(b.events) != 1 || b.events[0].Kind != "identity_unreadable" {
		t.Errorf("events %+v", b.events)
	}
	c := &Agent{Logger: a.Logger}
	if n := c.loadIdentity(); n == nil || n.kid != id.kid {
		t.Fatal("the stored seed is not used")
	}
}

// The pending rotation seed survives a keystore that does not open once:
// the server may have taken it already.
func TestRotateIdentityKeystoreFailsOnce(t *testing.T) {
	a, failOnce := credsHostAgent(t)
	id := a.loadIdentity()
	if id == nil {
		t.Fatal("no identity")
	}
	a.sec2.kid.Store(&id.kid)
	if err := protect(confIdentityNext, newSeed()); err != nil {
		t.Fatal(err)
	}
	next, _ := confValue(confIdentityNext)
	failOnce()
	if a.rotateIdentity() {
		t.Error("rotated without the pending seed")
	}
	if n, _ := confValue(confIdentityNext); n != next {
		t.Fatal("the pending seed was replaced")
	}
}

// A refresh token the keystore cannot open now is still there: no grant.
// One that does not open at all is none.
func TestHaveRefreshKeystoreFailsOnce(t *testing.T) {
	a, failOnce := credsHostAgent(t)
	if a.haveRefresh() {
		t.Error("none stored")
	}
	if err := protect(confRefresh, []byte("r")); err != nil {
		t.Fatal(err)
	}
	failOnce()
	if !a.haveRefresh() {
		t.Error("a keystore that does not open once dropped the refresh token")
	}
	_ = setConfValues(map[string]string{confRefresh: wrapKEK + "broken"})
	if a.haveRefresh() {
		t.Error("an unreadable refresh token counts")
	}
}

// A DPAPI seed copied to another system is replaced like any unreadable one.
func TestLoadIdentityReplacesForeignDPAPI(t *testing.T) {
	a := keystoreHost(t, "freebsd")
	blob := wrapDPAPI + base64.StdEncoding.EncodeToString([]byte("blob"))
	_ = setConfValues(map[string]string{confIdentityKey: blob})
	if a.loadIdentity() == nil {
		t.Fatal("the seed was not replaced")
	}
	if s, _ := confValue(confIdentityKey); s == blob {
		t.Error("the DPAPI seed is still stored")
	}
}
