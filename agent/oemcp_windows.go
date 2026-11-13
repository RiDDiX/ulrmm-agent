// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package agent

import (
	"strconv"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// console programs and PowerShell write in the OEM code page when their
// output is redirected, some programs in the ANSI one; text that is not
// UTF-8 is decoded with whichever fits (decodeLines). Windows itself
// decodes, so every code page it knows works, double-byte ones included.
var legacyDecoders = sync.OnceValue(func() []func(string) (string, error) {
	oem, ansi := 850, 1252
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Nls\CodePage`, registry.QUERY_VALUE); err == nil {
		oem = codePage(k, "OEMCP", oem)
		ansi = codePage(k, "ACP", ansi)
		k.Close()
	}
	decoders := []func(string) (string, error){codePageDecoder(uint32(oem))}
	if ansi != oem {
		decoders = append(decoders, codePageDecoder(uint32(ansi)))
	}
	return decoders
})

// codePageDecoder decodes text of code page cp. Without MB_ERR_INVALID_CHARS
// bytes the page does not map are replaced instead of failing the line.
func codePageDecoder(cp uint32) func(string) (string, error) {
	return func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		b := []byte(s)
		n, err := windows.MultiByteToWideChar(cp, 0, &b[0], int32(len(b)), nil, 0)
		if err != nil {
			return "", err
		}
		u := make([]uint16, n)
		if n, err = windows.MultiByteToWideChar(cp, 0, &b[0], int32(len(b)), &u[0], n); err != nil {
			return "", err
		}
		return string(utf16.Decode(u[:n])), nil
	}
}

func codePage(k registry.Key, name string, fallback int) int {
	if v, _, err := k.GetStringValue(name); err == nil {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}
