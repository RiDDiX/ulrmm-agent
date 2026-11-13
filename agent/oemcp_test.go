// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"testing"

	"golang.org/x/text/encoding/charmap"
)

// stand-ins for the decoders Windows provides
func charmapDecoders(pages ...*charmap.Charmap) []func(string) (string, error) {
	var ds []func(string) (string, error)
	for _, p := range pages {
		ds = append(ds, p.NewDecoder().String)
	}
	return ds
}

func TestDecodeLines(t *testing.T) {
	german := charmapDecoders(charmap.CodePage850, charmap.Windows1252)
	russian := charmapDecoders(charmap.CodePage866, charmap.Windows1251)
	failing := func(string) (string, error) { return "", errors.New("no mapping") }
	cases := []struct {
		name     string
		decoders []func(string) (string, error)
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
		// a decoder that fails loses against one that works, and alone keeps the line
		{"failing first", append([]func(string) (string, error){failing}, german[1]), "Ger\xe4t\nok\n", "Gerät\nok\n"},
		{"failing only", []func(string) (string, error){failing}, "a\xffb", "a\xffb"},
	}
	for _, c := range cases {
		if got := decodeLines(c.in, c.decoders); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
