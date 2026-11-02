// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"testing"

	"golang.org/x/text/encoding"
)

func TestDecodeLines(t *testing.T) {
	german := []*encoding.Decoder{oemCharmap(850).NewDecoder(), oemCharmap(1252).NewDecoder()}
	russian := []*encoding.Decoder{oemCharmap(866).NewDecoder(), oemCharmap(1251).NewDecoder()}
	cases := []struct {
		name     string
		decoders []*encoding.Decoder
		in, want string
	}{
		// pnputil writes in the ANSI code page: ö is 0xF6, ÷ in 850
		{"ansi", german, "Ver\xf6ffentlichter Name: oem7.inf", "Veröffentlichter Name: oem7.inf"},
		{"oem", german, "Datentr\x84ger gel\x94scht", "Datenträger gelöscht"},
		{"ansi ue", german, "Ger\xe4t \xfcberpr\xfcft", "Gerät überprüft"},
		// ß (OEM) and á (ANSI) are both letters: the OEM page wins the tie
		{"tie", german, "Stra\xe1e", "Straße"},
		// ä (ANSI) reads õ in OEM; the other line decides
		{"tie by output", german, "Ger\xe4t\r\nVer\xf6ffentlicht\r\n", "Gerät\r\nVeröffentlicht\r\n"},
		{"tree", german, "\xc3\xc4\xc4\xc4Windows\r\n\xb3   \xc0\xc4\xc4System32", "├───Windows\r\n│   └──System32"},
		{"ansi capital", german, "\xc4RGER", "ÄRGER"},
		{"french ansi", german, "P\xe9riph\xe9rique", "Périphérique"},
		{"french oem", german, "P\x82riph\x82rique", "Périphérique"},
		{"mixed", german, "Datentr\x84ger\r\nVer\xf6ffentlicht\r\nok ä\n", "Datenträger\r\nVeröffentlicht\r\nok ä\n"},
		{"cyrillic oem", russian, "\x8f\xe0\xa8\xa2\xa5\xe2", "Привет"},
		{"cyrillic ansi", russian, "\xcf\xf0\xe8\xe2\xe5\xf2", "Привет"},
		{"no decoders", nil, "a\xffb", "a\xffb"},
	}
	for _, c := range cases {
		if got := decodeLines(c.in, c.decoders); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
