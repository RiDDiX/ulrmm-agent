// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// Host keystore: one random key-encryption key per host, kept by the OS
// (TPM, DPAPI, systemd-creds, keychain or a root-only file). Every secret of
// the config is stored as "kek1:" + base64(nonce || ChaCha20-Poly1305), the
// value name as additional data, so a value moved to another name does not
// open. KeyStore names where the KEK lives; the service picks it once.

const (
	wrapKEK          = "kek1:"
	confKeyStore     = "KeyStore"
	confKeyStoreSent = "KeyStoreSent"
	confUninstallSum = "UninstallCodeSum"
	kekLen           = 32
)

// secretNames are the config values under the KEK. The first three were
// stored as they are before the keystore, the others raw1/dpapi1 wrapped.
var secretNames = []string{"Token", confClientKey, confUninstallKey, confRefresh, confIdentityKey, confIdentityNext}

func plainBefore(name string) bool {
	return name == "Token" || name == confClientKey || name == confUninstallKey
}

var dpapiOpen = unprotectDPAPI

// the KEK of this process, read once; at is the config it belongs to, lost
// why the store failed when the key came from its copy
var kekCache struct {
	sync.Mutex
	key    []byte
	scheme string
	at     string
	lost   string
}

// errNoKEKCopy: the store of the scheme has no copy next to it.
var errNoKEKCopy = errors.New("no copy of the key")

// currentKEK is nil, "", nil while the host has no keystore. The error of a
// keystore that does not open names it: "kek <scheme>: <reason>".
func currentKEK() ([]byte, string, error) {
	kekCache.Lock()
	defer kekCache.Unlock()
	if kekCache.key != nil && kekCache.at == etcConfig {
		return kekCache.key, kekCache.scheme, nil
	}
	scheme, err := confValue(confKeyStore)
	if err != nil || scheme == "" {
		return nil, "", err
	}
	k, err := kekGet(scheme)
	if err == nil && len(k) != kekLen {
		err = errors.New("the key is not 32 bytes")
	}
	lost := ""
	if err != nil {
		err = fmt.Errorf("kek %s: %v", scheme, err)
		c, from, cerr := kekCopy(scheme)
		if cerr != nil || len(c) != kekLen {
			return nil, scheme, err
		}
		k, lost = c, err.Error()+", opened from "+from
	}
	kekCache.key, kekCache.scheme, kekCache.at, kekCache.lost = k, scheme, etcConfig, lost
	return k, scheme, nil
}

func sealKEK(key []byte, name string, b []byte) string {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return wrapKEK + base64.StdEncoding.EncodeToString(append(nonce, seal(key, nonce, b, []byte(name))...))
}

func openKEK(key []byte, name, s string) ([]byte, error) {
	c, err := base64.StdEncoding.DecodeString(s[len(wrapKEK):])
	if err != nil || len(c) < 12 {
		return nil, errUnwrap
	}
	b, err := unseal(key, c[:12], c[12:], []byte(name))
	if err != nil {
		return nil, errUnwrap
	}
	return b, nil
}

// wrapSecret is how b is stored under name. A keystore that does not open
// is an error: nothing is written in the clear then. Before the host has a
// keystore the values are stored as before it.
func wrapSecret(name string, b []byte) (string, error) {
	key, _, err := currentKEK()
	switch {
	case err != nil:
		return "", err
	case key != nil:
		return sealKEK(key, name, b), nil
	case plainBefore(name):
		return string(b), nil
	}
	return legacyWrap(b)
}

func unwrapSecret(name, s string) ([]byte, error) {
	switch {
	case s == "":
		return nil, nil
	case strings.HasPrefix(s, wrapKEK):
		key, _, err := currentKEK()
		if err != nil {
			return nil, err
		}
		if key == nil {
			return nil, errUnwrap
		}
		return openKEK(key, name, s)
	case strings.HasPrefix(s, wrapRaw):
		b, err := base64.StdEncoding.DecodeString(s[len(wrapRaw):])
		if err != nil {
			return nil, errUnwrap
		}
		return b, nil
	case strings.HasPrefix(s, wrapDPAPI):
		b, err := base64.StdEncoding.DecodeString(s[len(wrapDPAPI):])
		if err != nil {
			return nil, errUnwrap
		}
		return dpapiOpen(b)
	case plainBefore(name):
		return []byte(s), nil
	}
	return nil, errUnwrap
}

// sealValues wraps the secrets among kv in place.
func sealValues(kv map[string]string) error {
	for _, name := range secretNames {
		if v, ok := kv[name]; ok && v != "" {
			s, err := wrapSecret(name, []byte(v))
			if err != nil {
				return err
			}
			kv[name] = s
		}
	}
	return nil
}

// openConfigSecrets opens the token and the client key New() reads. A value
// that does not open is dropped and named in the error.
func openConfigSecrets(cfg *rmm.LocalConfig) error {
	var errs []error
	for _, v := range []struct {
		name string
		p    *string
	}{{"Token", &cfg.AuthToken}, {confClientKey, &cfg.TLSKey}} {
		b, err := unwrapSecret(v.name, *v.p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", v.name, err))
		}
		*v.p = string(b)
	}
	return errors.Join(errs...)
}

// newKeyStore makes the KEK and keeps it in the first store of the host
// that gives it back.
func newKeyStore() (string, error) {
	k := make([]byte, kekLen)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return storeKEK(k)
}

func storeKEK(k []byte) (string, error) {
	var errs []error
	for _, s := range kekSchemes() {
		scheme, err := kekPut(s, k)
		if err == nil {
			var got []byte
			if got, err = kekGet(scheme); err == nil && !bytes.Equal(got, k) {
				err = errors.New("reads back a different key")
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", s, err))
			continue
		}
		if err := setConfValues(map[string]string{confKeyStore: scheme}); err != nil {
			return "", err
		}
		kekCache.Lock()
		kekCache.key, kekCache.scheme, kekCache.at, kekCache.lost = k, scheme, etcConfig, ""
		kekCache.Unlock()
		return scheme, nil
	}
	return "", errors.Join(errs...)
}

// setupKeystore runs at service start before anything reads a secret: it
// makes the keystore once and moves the secrets of the config under it.
// A keystore that does not open is reported and left as it is; the
// secrets stay where they are for a start where it opens again.
func (a *Agent) setupKeystore() {
	key, scheme, err := currentKEK()
	if err == nil && key == nil {
		if scheme, err = newKeyStore(); err != nil {
			a.Logger.Errorln("keystore: none of the stores works:", err)
			return
		}
		a.Logger.Infoln("Keystore:", scheme)
		key, _, err = currentKEK()
	}
	if err != nil {
		a.Logger.Errorln("keystore:", err)
		a.queueSecurityEvent("identity_unreadable", err.Error())
		return
	}
	kekCache.Lock()
	lost := kekCache.lost
	kekCache.Unlock()
	if lost != "" {
		// the copy opened: reported, and the key goes into a store again
		a.Logger.Errorln("keystore:", lost)
		a.queueSecurityEvent("identity_unreadable", lost)
		if scheme, err := storeKEK(key); err != nil {
			a.Logger.Errorln("keystore: storing the key again:", err)
		} else {
			a.Logger.Infoln("Keystore:", scheme)
		}
	}
	if err := fixUninstallSum(); err != nil {
		a.Logger.Errorln("keystore: uninstall code:", err)
	}
	if err := migrateSecrets(key); err != nil {
		a.Logger.Errorln("keystore: moving the secrets:", err)
	}
}

// migrateSecrets rewrites every secret that is not under the KEK yet in one
// config write. A value that does not open stays as it is.
func migrateSecrets(key []byte) error {
	kv := map[string]string{}
	for _, name := range secretNames {
		s, err := confValue(name)
		if err != nil {
			return err
		}
		if s == "" || strings.HasPrefix(s, wrapKEK) {
			continue
		}
		b, err := unwrapSecret(name, s)
		if err != nil {
			continue
		}
		kv[name] = sealKEK(key, name, b)
	}
	if len(kv) == 0 {
		return nil
	}
	return setConfValues(kv)
}

func codeSum(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// fixUninstallSum keeps UninstallCodeSum, which the Windows uninstaller
// compares the given code with, and the ack as sums of the code. It runs
// before the code goes under the KEK.
func fixUninstallSum() error {
	code, err := storedUninstallCode()
	if err != nil || code == "" {
		return err
	}
	kv := map[string]string{}
	if s, _ := confValue(confUninstallSum); s != codeSum(code) {
		kv[confUninstallSum] = codeSum(code)
	}
	if ack, _ := confValue(confUninstallAck); ack == code {
		kv[confUninstallAck] = codeSum(code)
	}
	if len(kv) == 0 {
		return nil
	}
	return setConfValues(kv)
}

// keyStoreCap is the capability the identity registration reports.
func keyStoreCap() string {
	if s, _ := confValue(confKeyStore); s != "" {
		return "ks:" + s
	}
	return ""
}
