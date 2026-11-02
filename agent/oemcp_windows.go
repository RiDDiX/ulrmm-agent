// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package agent

import (
	"strconv"
	"sync"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding"
)

// console programs and PowerShell write in the OEM code page when their
// output is redirected, some programs in the ANSI one; text that is not
// UTF-8 is decoded with whichever fits (decodeLines)
var legacyDecoders = sync.OnceValue(func() []*encoding.Decoder {
	oem, ansi := 850, 1252
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Nls\CodePage`, registry.QUERY_VALUE); err == nil {
		oem = codePage(k, "OEMCP", oem)
		ansi = codePage(k, "ACP", ansi)
		k.Close()
	}
	decoders := []*encoding.Decoder{oemCharmap(oem).NewDecoder()}
	if oemCharmap(ansi) != oemCharmap(oem) {
		decoders = append(decoders, oemCharmap(ansi).NewDecoder())
	}
	return decoders
})

func codePage(k registry.Key, name string, fallback int) int {
	if v, _, err := k.GetStringValue(name); err == nil {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
