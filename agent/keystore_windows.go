// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// KEK stores on Windows: a machine RSA key of the Microsoft Platform Crypto
// Provider (the TPM; its keys never leave it) wraps the KEK with OAEP
// SHA-256, else DPAPI of the service account. The wrapped KEK is the
// registry value KeyStoreKEK. Next to a TPM-wrapped one KeyStoreKEKDpapi
// keeps a DPAPI copy: a cleared TPM, an fTPM reset by a BIOS update or a VM
// moved without its vTPM state would lose the key otherwise.

const (
	confKeyStoreKEK      = "KeyStoreKEK"
	confKeyStoreKEKDpapi = "KeyStoreKEKDpapi"
)

var (
	ncrypt                        = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptEncrypt             = ncrypt.NewProc("NCryptEncrypt")
	procNCryptDecrypt             = ncrypt.NewProc("NCryptDecrypt")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")

	tpmKeyName = IdentWinRegKey + " Agent KEK"
)

const (
	ncryptPadOAEP    = 0x4
	ncryptSilent     = 0x40
	ncryptMachineKey = 0x20
	ncryptOverwrite  = 0x80
)

// BCRYPT_OAEP_PADDING_INFO
type oaepPadding struct {
	alg   *uint16
	label *byte
	n     uint32
}

// ncryptFind loads the procedures before the first call: Call panics on a
// missing one.
func ncryptFind() error {
	for _, p := range []*windows.LazyProc{procNCryptOpenStorageProvider, procNCryptCreatePersistedKey, procNCryptOpenKey,
		procNCryptSetProperty, procNCryptFinalizeKey, procNCryptEncrypt, procNCryptDecrypt, procNCryptFreeObject, procNCryptDeleteKey} {
		if err := p.Find(); err != nil {
			return err
		}
	}
	return nil
}

func nerr(p *windows.LazyProc, r uintptr) error {
	if r != 0 {
		return fmt.Errorf("%s: 0x%08x", p.Name, uint32(r))
	}
	return nil
}

func u16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// tpmKey opens the machine key, or makes it with create. The pointers go
// to Call directly, which keeps them alive and in place.
func tpmKey(create bool) (uintptr, error) {
	if err := ncryptFind(); err != nil {
		return 0, err
	}
	var prov, key uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(u16("Microsoft Platform Crypto Provider"))), 0)
	if err := nerr(procNCryptOpenStorageProvider, r); err != nil {
		return 0, err
	}
	defer procNCryptFreeObject.Call(prov)
	if !create {
		r, _, _ = procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(u16(tpmKeyName))), 0, ncryptMachineKey|ncryptSilent)
		return key, nerr(procNCryptOpenKey, r)
	}
	r, _, _ = procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(u16("RSA"))),
		uintptr(unsafe.Pointer(u16(tpmKeyName))), 0, ncryptMachineKey|ncryptOverwrite)
	if err := nerr(procNCryptCreatePersistedKey, r); err != nil {
		return 0, err
	}
	bits := uint32(2048)
	r, _, _ = procNCryptSetProperty.Call(key, uintptr(unsafe.Pointer(u16("Length"))), uintptr(unsafe.Pointer(&bits)), 4, ncryptSilent)
	err := nerr(procNCryptSetProperty, r)
	if err == nil {
		// no export policy set: the key is not exportable
		r, _, _ = procNCryptFinalizeKey.Call(key, ncryptSilent)
		err = nerr(procNCryptFinalizeKey, r)
	}
	if err != nil {
		procNCryptFreeObject.Call(key)
		return 0, err
	}
	return key, nil
}

func tpmCrypt(p *windows.LazyProc, key uintptr, in []byte) ([]byte, error) {
	pad := &oaepPadding{alg: u16("SHA256")}
	out := make([]byte, 512)
	var n uint32
	r, _, _ := p.Call(key, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)), uintptr(unsafe.Pointer(pad)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), ncryptPadOAEP|ncryptSilent)
	runtime.KeepAlive(pad)
	if err := nerr(p, r); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func kekSchemes() []string { return []string{"tpm", "dpapi"} }

func kekPut(s string, k []byte) (string, error) {
	var w, c []byte
	var err error
	switch s {
	case "tpm":
		var key uintptr
		if key, err = tpmKey(true); err != nil {
			return "", err
		}
		w, err = tpmCrypt(procNCryptEncrypt, key, k)
		procNCryptFreeObject.Call(key)
		if err == nil {
			c, err = protectDPAPI(k)
		}
	case "dpapi":
		w, err = protectDPAPI(k)
	default:
		return "", fmt.Errorf("no store %q here", s)
	}
	if err != nil {
		return "", err
	}
	kv := map[string]string{confKeyStoreKEK: base64.StdEncoding.EncodeToString(w), confKeyStoreKEKDpapi: ""}
	if c != nil {
		kv[confKeyStoreKEKDpapi] = base64.StdEncoding.EncodeToString(c)
	}
	return s, setConfValues(kv)
}

// kekCopy opens the copy of the KEK kept next to the store of scheme, and
// names where it is.
func kekCopy(scheme string) ([]byte, string, error) {
	if scheme != "tpm" {
		return nil, "", errNoKEKCopy
	}
	v, err := confValue(confKeyStoreKEKDpapi)
	if err != nil {
		return nil, "", err
	}
	c, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(c) == 0 {
		return nil, "", errNoKEKCopy
	}
	k, err := unprotectDPAPI(c)
	return k, "dpapi", err
}

func kekGet(scheme string) ([]byte, error) {
	v, err := confValue(confKeyStoreKEK)
	if err != nil {
		return nil, err
	}
	w, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(w) == 0 {
		return nil, fmt.Errorf("%s is missing or broken", confKeyStoreKEK)
	}
	switch scheme {
	case "tpm":
		key, err := tpmKey(false)
		if err != nil {
			return nil, err
		}
		defer procNCryptFreeObject.Call(key)
		return tpmCrypt(procNCryptDecrypt, key, w)
	case "dpapi":
		return unprotectDPAPI(w)
	}
	return nil, fmt.Errorf("unknown keystore %q", scheme)
}

// deleteKEKStore removes the TPM key and the wrapped KEK (uninstall). No
// key, no provider or no value is nothing to remove.
func deleteKEKStore() error {
	var errs []error
	if key, err := tpmKey(false); err == nil {
		// frees the handle when it succeeds
		r, _, _ := procNCryptDeleteKey.Call(key, ncryptSilent)
		if err := nerr(procNCryptDeleteKey, r); err != nil {
			procNCryptFreeObject.Call(key)
			errs = append(errs, err)
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.SET_VALUE)
	if err == nil {
		for _, name := range []string{confKeyStoreKEK, confKeyStoreKEKDpapi} {
			if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		k.Close()
	} else if !errors.Is(err, registry.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
