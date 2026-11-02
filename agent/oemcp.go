// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
)

// decodeLines decodes text that is not UTF-8 line by line. Windows console
// programs write in the OEM code page, some (pnputil) in the ANSI one, and
// one output can hold both. Each line keeps the decoding with the fewest odd
// runes; on a tie the decoding that fits the whole output best wins, then
// the first decoder (OEM).
func decodeLines(s string, decoders []*encoding.Decoder) string {
	if len(decoders) == 0 {
		return s
	}
	lines := strings.SplitAfter(s, "\n")
	outs := make([][]string, len(lines))
	odd := make([][]int, len(lines))
	total := make([]int, len(decoders))
	for i, line := range lines {
		if utf8.ValidString(line) {
			continue
		}
		outs[i] = make([]string, len(decoders))
		odd[i] = make([]int, len(decoders))
		for d, dec := range decoders {
			out, err := dec.String(line)
			n := oddRunes(out)
			if err != nil {
				out, n = line, len(line)+1
			}
			outs[i][d], odd[i][d] = out, n
			total[d] += n
		}
	}
	for i := range lines {
		if outs[i] == nil {
			continue
		}
		best := 0
		for d := 1; d < len(decoders); d++ {
			if n, m := odd[i][d], odd[i][best]; n < m || n == m && total[d] < total[best] {
				best = d
			}
		}
		lines[i] = outs[i][best]
	}
	return strings.Join(lines, "")
}

// oddRunes counts runes unlikely in real text. A wrong code page turns
// letters into symbols (ö into ÷), into box drawing next to letters (Ä into
// ─) or into capitals inside words (é into Ú). Box drawing in runs or next
// to spaces is console output (tree, tables).
func oddRunes(s string) int {
	rs := []rune(s)
	at := func(i int) rune {
		if i < 0 || i >= len(rs) {
			return 0
		}
		return rs[i]
	}
	n := 0
	for i, r := range rs {
		prev, next := at(i-1), at(i+1)
		switch {
		case r < utf8.RuneSelf, unicode.IsSpace(r):
		case unicode.IsLetter(r):
			if unicode.IsUpper(r) && unicode.IsLetter(prev) && unicode.IsLower(next) {
				n++
			}
		case isBox(r):
			if !isBox(prev) && !isBox(next) && (unicode.IsLetter(prev) || unicode.IsLetter(next)) {
				n++
			}
		default:
			n++
		}
	}
	return n
}

func isBox(r rune) bool { return r >= 0x2500 && r <= 0x257f }

func oemCharmap(cp int) *charmap.Charmap {
	switch cp {
	case 437:
		return charmap.CodePage437
	case 852:
		return charmap.CodePage852
	case 855:
		return charmap.CodePage855
	case 858:
		return charmap.CodePage858
	case 860:
		return charmap.CodePage860
	case 862:
		return charmap.CodePage862
	case 863:
		return charmap.CodePage863
	case 865:
		return charmap.CodePage865
	case 866:
		return charmap.CodePage866
	case 1250:
		return charmap.Windows1250
	case 1251:
		return charmap.Windows1251
	case 1252:
		return charmap.Windows1252
	case 1253:
		return charmap.Windows1253
	case 1254:
		return charmap.Windows1254
	case 1257:
		return charmap.Windows1257
	}
	return charmap.CodePage850
}
