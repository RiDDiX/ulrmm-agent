// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"reflect"
	"testing"
)

func TestSplitRegPath(t *testing.T) {
	cases := []struct {
		in, hive, sub string
		err           error
	}{
		{`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`, "HKEY_LOCAL_MACHINE", `SOFTWARE\Microsoft`, nil},
		{`HKEY_LOCAL_MACHINE\`, "HKEY_LOCAL_MACHINE", "", nil},
		{`HKEY_CURRENT_CONFIG\System\\`, "HKEY_CURRENT_CONFIG", "System", nil},
		{`HKEY_USERS\.DEFAULT`, "HKEY_USERS", ".DEFAULT", nil},
		{`HKEY_LOCAL_MACHINE`, "", "", errRegPath},
		{`hkey_local_machine\x`, "", "", errRegHive},
		{`HKLM\SOFTWARE`, "", "", errRegHive},
		{"HKEY_LOCAL_MACHINE\\a\x00b", "", "", errRegPath},
	}
	for _, c := range cases {
		h, s, err := splitRegPath(c.in)
		if h != c.hive || s != c.sub || err != c.err {
			t.Errorf("splitRegPath(%q) = %q %q %v, want %q %q %v", c.in, h, s, err, c.hive, c.sub, c.err)
		}
	}
	if errRegPath.Error() != "Invalid registry path, Please enter a valid path" || errRegHive.Error() != "unknown registry hive" {
		t.Error("path error texts changed")
	}
	// the dashboard shows the hives in this order
	want := []string{"HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CURRENT_CONFIG"}
	if !reflect.DeepEqual(regHives, want) {
		t.Errorf("regHives = %v, want %v", regHives, want)
	}
}

func TestRegRootName(t *testing.T) {
	for in, want := range map[string]string{
		"HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE", `HKEY_LOCAL_MACHINE\`: "HKEY_LOCAL_MACHINE",
		"hkey_users": "hkey_users", "Computer": "Computer", `computer\`: "computer",
		`HKEY_LOCAL_MACHINE\SOFTWARE`: "", "": "",
	} {
		if got := regRootName(in); got != want {
			t.Errorf("regRootName(%q) = %q, want %q", in, got, want)
		}
	}
	if !isRegComputer("COMPUTER") || isRegComputer(`Computer\HKEY_USERS`) {
		t.Error("isRegComputer")
	}
}

func TestRegPage(t *testing.T) {
	cases := []struct {
		n, page, size, start, end int
		more                      bool
	}{
		{450, 1, 200, 0, 200, true},
		{450, 2, 200, 200, 400, true},
		{450, 3, 200, 400, 450, false},
		{450, 4, 200, 0, 0, false},
		{400, 2, 200, 200, 400, false},
		{400, 3, 200, 0, 0, false},
		{0, 1, 200, 0, 0, false},
		{5, 0, 200, 0, 0, false},
		{5, 1, 0, 0, 0, false},
		{5, int(^uint(0) >> 1), 1000, 0, 0, false},
	}
	for _, c := range cases {
		s, e, m := regPage(c.n, c.page, c.size)
		if s != c.start || e != c.end || m != c.more {
			t.Errorf("regPage(%d,%d,%d) = %d %d %v", c.n, c.page, c.size, s, e, m)
		}
	}
}

func utf16le(s string) []byte {
	b, err := regEncodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRegDisplay(t *testing.T) {
	cases := []struct {
		typ  uint32
		data []byte
		tt   string
		want interface{}
	}{
		{regSZ, utf16le("hello"), "REG_SZ", "hello"},
		{regSZ, append(utf16le("a"), utf16le("b")...), "REG_SZ", "a"},
		{regSZ, nil, "REG_SZ", ""},
		{regExpandSZ, utf16le(`%SystemRoot%\x`), "REG_EXPAND_SZ", `%SystemRoot%\x`},
		{regMultiSZ, []byte{'a', 0, 0, 0, 'b', 0, 0, 0, 0, 0}, "REG_MULTI_SZ", []string{"a", "b"}},
		{regMultiSZ, nil, "REG_MULTI_SZ", []string{}},
		{regDWord, []byte{0x7b, 0, 0, 0}, "REG_DWORD", "0x0000007B (123)"},
		{regDWord, []byte{0xff, 0xff, 0xff, 0xff}, "REG_DWORD", "0xFFFFFFFF (4294967295)"},
		{regDWord, []byte{1, 2}, "REG_DWORD", "<invalid DWORD>"},
		{regQWord, []byte{0x7b, 0, 0, 0, 0, 0, 0, 0}, "REG_QWORD", "0x0000007B (123)"},
		{regQWord, []byte{0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0}, "REG_QWORD", "0x1FFFFFFFF (8589934591)"},
		{regQWord, []byte{1, 2, 3, 4}, "REG_QWORD", "<invalid QWORD>"},
		{regBinary, []byte{0x0a, 0x0b, 0xfc}, "REG_BINARY", "0A 0B FC"},
		{regBinary, nil, "REG_BINARY", ""},
		{0, nil, "UNKNOWN_0", "<unsupported>"},
		{regLink, []byte{1}, "UNKNOWN_6", "<unsupported>"},
		{5, []byte{0, 0, 0, 1}, "UNKNOWN_5", "<unsupported>"},
	}
	for _, c := range cases {
		tt, d := regDisplay(c.typ, c.data)
		if tt != c.tt || !reflect.DeepEqual(d, c.want) {
			t.Errorf("regDisplay(%d, %v) = %q %#v, want %q %#v", c.typ, c.data, tt, d, c.tt, c.want)
		}
	}
}

func TestRegEncode(t *testing.T) {
	cases := []struct {
		typ     string
		data    interface{}
		tt      string
		code    uint32
		raw     []byte
		display interface{}
	}{
		{"REG_DWORD", "123", "REG_DWORD", regDWord, []byte{0x7b, 0, 0, 0}, "0x0000007B (123)"},
		{" reg_dword ", "0x7B", "REG_DWORD", regDWord, []byte{0x7b, 0, 0, 0}, "0x0000007B (123)"},
		{"REG_DWORD", "", "REG_DWORD", regDWord, []byte{0, 0, 0, 0}, "0x00000000 (0)"},
		{"REG_DWORD", nil, "REG_DWORD", regDWord, []byte{0, 0, 0, 0}, "0x00000000 (0)"},
		{"REG_DWORD", 7.0, "REG_DWORD", regDWord, []byte{7, 0, 0, 0}, "0x00000007 (7)"},
		{"REG_QWORD", "8589934591", "REG_QWORD", regQWord, []byte{0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0}, "0x1FFFFFFFF (8589934591)"},
		{"REG_QWORD", "0x7B", "REG_QWORD", regQWord, []byte{0x7b, 0, 0, 0, 0, 0, 0, 0}, "0x0000007B (123)"},
		{"REG_MULTI_SZ", "a,b", "REG_MULTI_SZ", regMultiSZ, []byte{'a', 0, 0, 0, 'b', 0, 0, 0, 0, 0}, []string{"a", "b"}},
		{"REG_MULTI_SZ", `["a","b"]`, "REG_MULTI_SZ", regMultiSZ, []byte{'a', 0, 0, 0, 'b', 0, 0, 0, 0, 0}, []string{"a", "b"}},
		{"REG_MULTI_SZ", "one", "REG_MULTI_SZ", regMultiSZ, []byte{'o', 0, 'n', 0, 'e', 0, 0, 0, 0, 0}, []string{"one"}},
		{"REG_MULTI_SZ", "a,,b", "REG_MULTI_SZ", regMultiSZ, []byte{'a', 0, 0, 0, 'b', 0, 0, 0, 0, 0}, []string{"a", "b"}},
		{"REG_MULTI_SZ", "", "REG_MULTI_SZ", regMultiSZ, []byte{0, 0}, []string{}},
		{"REG_MULTI_SZ", []interface{}{"x"}, "REG_MULTI_SZ", regMultiSZ, []byte{'x', 0, 0, 0, 0, 0}, []string{"x"}},
		{"REG_BINARY", "0A 0B 0C", "REG_BINARY", regBinary, []byte{0x0a, 0x0b, 0x0c}, "0A 0B 0C"},
		{"REG_BINARY", "0a0b0c", "REG_BINARY", regBinary, []byte{0x0a, 0x0b, 0x0c}, "0A 0B 0C"},
		{"REG_BINARY", "", "REG_BINARY", regBinary, []byte{}, ""},
		{"REG_BINARY", []interface{}{10.0, 267.0}, "REG_BINARY", regBinary, []byte{10, 11}, "0A 0B"},
		{"REG_SZ", "hi", "REG_SZ", regSZ, []byte{'h', 0, 'i', 0, 0, 0}, "hi"},
		{"REG_SZ", "", "REG_SZ", regSZ, []byte{0, 0}, ""},
		{"rEg_ExPaNd_Sz", `%TEMP%`, "REG_EXPAND_SZ", regExpandSZ, utf16le(`%TEMP%`), `%TEMP%`},
	}
	for _, c := range cases {
		tt, code, raw, display, err := regEncode(c.typ, c.data)
		if err != nil || tt != c.tt || code != c.code || !reflect.DeepEqual(raw, c.raw) || !reflect.DeepEqual(display, c.display) {
			t.Errorf("regEncode(%q, %#v) = %q %d %v %#v %v", c.typ, c.data, tt, code, raw, display, err)
			continue
		}
		// what browse shows afterwards equals the reply of the write
		if _, shown := regDisplay(code, raw); !reflect.DeepEqual(shown, display) {
			t.Errorf("regEncode(%q, %#v): browse shows %#v, reply %#v", c.typ, c.data, shown, display)
		}
	}
}

func TestRegEncodeErrors(t *testing.T) {
	cases := []struct {
		typ  string
		data interface{}
		want string
	}{
		{"REG_DWORD", "abc", "invalid REG_DWORD value 'abc': must be decimal or hex"},
		{"REG_DWORD", "-1", "invalid REG_DWORD value '-1': must be decimal or hex"},
		{"REG_DWORD", "4294967296", "invalid REG_DWORD value '4294967296': must be decimal or hex"},
		{"REG_DWORD", "0x", "invalid REG_DWORD value '0x': must be decimal or hex"},
		{"REG_DWORD", -1, "invalid REG_DWORD value '-1': must be decimal or hex"},
		{"REG_DWORD", 1.5, "invalid REG_DWORD value '1.5': must be decimal or hex"},
		{"REG_DWORD", true, "expected numeric value for REG_DWORD, got bool"},
		{"REG_QWORD", "18446744073709551616", "invalid REG_QWORD value '18446744073709551616': must be decimal or hex"},
		{"REG_BINARY", "0x0A", "invalid REG_BINARY value '0x0A': use hex bytes such as 0A 0B 0C"},
		{"REG_BINARY", "ABC", "invalid REG_BINARY value 'ABC': use hex bytes such as 0A 0B 0C"},
		{"REG_BINARY", 5, "expected hex text for REG_BINARY, got int"},
		{"REG_MULTI_SZ", 5, "expected []string or JSON array for REG_MULTI_SZ, got int"},
		{"REG_MULTI_SZ", []interface{}{1.0}, "expected []string or JSON array for REG_MULTI_SZ, got []interface {}"},
		{"REG_SZ", "a\x00b", errRegNUL.Error()},
		{"REG_MULTI_SZ", "a\x00b", errRegNUL.Error()},
		{"reg_none ", "", "unsupported registry value type: reg_none "},
	}
	for _, c := range cases {
		_, _, _, _, err := regEncode(c.typ, c.data)
		if err == nil || err.Error() != c.want {
			t.Errorf("regEncode(%q, %#v) error = %v, want %q", c.typ, c.data, err, c.want)
		}
	}
}

func TestRegValueName(t *testing.T) {
	if n, err := regValueName("  Run  "); n != "Run" || err != nil {
		t.Errorf("regValueName = %q %v", n, err)
	}
	// a blank name is the default value, except for a rename
	if n, err := regValueName("   "); n != "" || err != nil {
		t.Errorf("blank name: %q %v", n, err)
	}
	if _, err := regNamedValue("   "); err != errRegName || err.Error() != "registry value name is required" {
		t.Errorf("blank rename: %v", err)
	}
	if _, err := regValueName("a\x00"); err != errRegNUL {
		t.Errorf("NUL name: %v", err)
	}
	for typ, ok := range map[uint32]bool{regSZ: true, regExpandSZ: true, regMultiSZ: true, regDWord: true, regQWord: true, regBinary: true, 0: false, regLink: false, 5: false} {
		if regRenamable(typ) != ok {
			t.Errorf("regRenamable(%d) != %v", typ, ok)
		}
	}
}

func TestSameRegTree(t *testing.T) {
	tree := func(sub string, data byte) *regNode {
		return &regNode{
			values: []regRaw{{"A", regDWord, []byte{data, 0, 0, 0}}, {"", regSZ, utf16le("x")}},
			subs:   []regChild{{sub, &regNode{values: []regRaw{{"B", regBinary, nil}}}}},
		}
	}
	a := tree("Child", 1)
	reordered := &regNode{values: []regRaw{a.values[1], a.values[0]}, subs: a.subs}
	if !sameRegTree(a, tree("Child", 1)) || !sameRegTree(a, reordered) {
		t.Error("equal trees differ")
	}
	extra := tree("Child", 1)
	extra.subs = append(extra.subs, regChild{"New", &regNode{}})
	typ := tree("Child", 1)
	typ.values[0].typ = regBinary
	for name, b := range map[string]*regNode{"data": tree("Child", 2), "subkey name": tree("Other", 1), "extra subkey": extra, "type": typ, "nil": nil} {
		if sameRegTree(a, b) {
			t.Errorf("trees with a different %s compare equal", name)
		}
	}
}
