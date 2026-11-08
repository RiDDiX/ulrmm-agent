// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/base64"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI in the scope of the account that runs the service (LocalSystem),
// not the machine scope: other processes of the machine cannot open it.
var dpapiEntropy = []byte("ulrmm-identity-v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func blobBytes(d *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(d.Data)))
	return append([]byte(nil), unsafe.Slice(d.Data, d.Size)...)
}

func protectDPAPI(b []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(b), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return blobBytes(&out), nil
}

func legacyWrap(b []byte) (string, error) {
	p, err := protectDPAPI(b)
	if err != nil {
		return "", err
	}
	return wrapDPAPI + base64.StdEncoding.EncodeToString(p), nil
}

func unprotectDPAPI(b []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(b), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		// broken data or a key of another machine or reset: unreadable for
		// good; anything else (LSA busy, low memory) may pass
		switch err {
		case windows.ERROR_INVALID_DATA, windows.Errno(windows.NTE_BAD_DATA), windows.Errno(windows.NTE_BAD_KEY_STATE), windows.Errno(windows.CRYPT_E_BAD_ENCODE):
			return nil, errUnwrap
		}
		return nil, err
	}
	return blobBytes(&out), nil
}
