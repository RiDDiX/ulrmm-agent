// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Registry editor: path rules, value conversions and the tree comparison
// used by key moves. The Windows calls are in registry_windows.go.

// Windows value type numbers (winnt.h).
const (
	regSZ       = 1
	regExpandSZ = 2
	regBinary   = 3
	regDWord    = 4
	regLink     = 6
	regMultiSZ  = 7
	regQWord    = 11
)

// regBrowseMaxData is the largest value browse sends to the dashboard.
const regBrowseMaxData = 4 << 20

var regHives = []string{"HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CURRENT_CONFIG"}

var (
	errRegPath = errors.New("Invalid registry path, Please enter a valid path")
	errRegHive = errors.New("unknown registry hive")
	errRegName = errors.New("registry value name is required")
	errRegNUL  = errors.New("registry names and text values cannot contain NUL characters")
)

func isRegComputer(path string) bool {
	return strings.EqualFold(strings.TrimRight(path, `\`), "Computer")
}

// splitRegPath splits `<HIVE>\<subpath>` at the first backslash. The hive
// name is case-sensitive; trailing backslashes of the subpath are dropped,
// an empty subpath is the hive root.
func splitRegPath(path string) (hive, sub string, err error) {
	i := strings.IndexByte(path, '\\')
	if i < 0 || strings.IndexByte(path, 0) >= 0 {
		return "", "", errRegPath
	}
	hive = path[:i]
	for _, h := range regHives {
		if h == hive {
			return hive, strings.TrimRight(path[i+1:], `\`), nil
		}
	}
	return "", "", errRegHive
}

// regRootName returns the hive (or "Computer") that path names on its own,
// ignoring case and trailing backslashes, or "".
func regRootName(path string) string {
	p := strings.TrimRight(path, `\`)
	if strings.EqualFold(p, "Computer") {
		return p
	}
	for _, h := range regHives {
		if strings.EqualFold(p, h) {
			return p
		}
	}
	return ""
}

// regValueName trims a value name; a blank name is the key's default
// value.
func regValueName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if strings.IndexByte(n, 0) >= 0 {
		return "", errRegNUL
	}
	return n, nil
}

// regNamedValue is regValueName for a rename, where the default value
// has no name to give or take.
func regNamedValue(name string) (string, error) {
	n, err := regValueName(name)
	if err == nil && n == "" {
		err = errRegName
	}
	return n, err
}

// regProtected lists the keys the registry funcs refuse, upper case; "*"
// stands for any control set. The agent's configuration key holds its
// token, SAM and SECURITY hold password hashes and LSA secrets: no func
// touches them. The agent's service key may be read but not changed (its
// ImagePath runs as SYSTEM).
var regProtected = []struct {
	key       string
	writeOnly bool
}{
	{strings.ToUpper(`HKEY_LOCAL_MACHINE\SOFTWARE\` + IdentWinRegKey), false},
	{strings.ToUpper(`HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\` + IdentWinRegKey), false},
	{`HKEY_LOCAL_MACHINE\SAM`, false},
	{`HKEY_LOCAL_MACHINE\SECURITY`, false},
	{strings.ToUpper(`HKEY_LOCAL_MACHINE\SYSTEM\*\Services\` + IdentWinSvcName), true},
}

// regDenied reports whether a registry func on path is refused. write is
// set for every func but browse; parents is set when deleting or renaming
// path, where a parent of a protected key would take it along.
func regDenied(path string, write, parents bool) bool {
	p := normRegPath(path)
	if p == "" {
		return false
	}
	got := strings.Split(p, `\`)
	for _, r := range regProtected {
		if r.writeOnly && !write {
			continue
		}
		want := strings.Split(r.key, `\`)
		if len(got) < len(want) && !parents {
			continue
		}
		n := min(len(got), len(want))
		match := true
		for i := 0; i < n && match; i++ {
			match = got[i] == want[i] || want[i] == "*" && isControlSet(got[i])
		}
		if match {
			return true
		}
	}
	return false
}

// isControlSet matches CURRENTCONTROLSET and CONTROLSET001 and the like.
func isControlSet(name string) bool {
	if name == "CURRENTCONTROLSET" {
		return true
	}
	d, ok := strings.CutPrefix(name, "CONTROLSET")
	return ok && d != "" && strings.Trim(d, "0123456789") == ""
}

func normRegPath(path string) string {
	p := strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(path, "/", `\`)))
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	p = strings.Trim(p, `\`)
	p = strings.TrimPrefix(p, `COMPUTER\`)
	if p == "HKLM" || strings.HasPrefix(p, `HKLM\`) {
		p = "HKEY_LOCAL_MACHINE" + strings.TrimPrefix(p, "HKLM")
	}
	return p
}

func regParent(sub string) (parent, base string) {
	i := strings.LastIndexByte(sub, '\\')
	if i < 0 {
		return "", sub
	}
	return sub[:i], sub[i+1:]
}

// regPage returns the slice bounds of a page of n entries. A page past the
// end is empty.
func regPage(n, page, size int) (start, end int, more bool) {
	if n <= 0 || page < 1 || size < 1 || page-1 >= (n+size-1)/size {
		return 0, 0, false
	}
	start = (page - 1) * size
	end = start + size
	if end > n {
		end = n
	}
	return start, end, end < n
}

func regTypeText(typ uint32) string {
	switch typ {
	case regSZ:
		return "REG_SZ"
	case regExpandSZ:
		return "REG_EXPAND_SZ"
	case regBinary:
		return "REG_BINARY"
	case regDWord:
		return "REG_DWORD"
	case regMultiSZ:
		return "REG_MULTI_SZ"
	case regQWord:
		return "REG_QWORD"
	}
	return fmt.Sprintf("UNKNOWN_%d", typ)
}

func regUTF16(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return u
}

func regString(b []byte) string {
	u := regUTF16(b)
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u))
}

func regStrings(b []byte) []string {
	out := []string{}
	for _, part := range strings.Split(string(utf16.Decode(regUTF16(b))), "\x00") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func regDWordText(v uint32) string { return fmt.Sprintf("0x%08X (%d)", v, v) }

func regQWordText(v uint64) string {
	if v <= math.MaxUint32 {
		return fmt.Sprintf("0x%08X (%d)", v, v)
	}
	return fmt.Sprintf("0x%X (%d)", v, v)
}

// regDisplay renders stored value data the way the registry browser shows it.
func regDisplay(typ uint32, b []byte) (string, interface{}) {
	switch typ {
	case regSZ, regExpandSZ:
		return regTypeText(typ), regString(b)
	case regMultiSZ:
		return regTypeText(typ), regStrings(b)
	case regDWord:
		if len(b) < 4 {
			return regTypeText(typ), "<invalid DWORD>"
		}
		return regTypeText(typ), regDWordText(binary.LittleEndian.Uint32(b))
	case regQWord:
		if len(b) < 8 {
			return regTypeText(typ), "<invalid QWORD>"
		}
		return regTypeText(typ), regQWordText(binary.LittleEndian.Uint64(b))
	case regBinary:
		return regTypeText(typ), fmt.Sprintf("% X", b)
	}
	return regTypeText(typ), "<unsupported>"
}

func regTooLargeText(n int) string {
	return fmt.Sprintf("<value too large to display (%d bytes)>", n)
}

func regEncodeString(s string) ([]byte, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errRegNUL
	}
	return regBytes(append(utf16.Encode([]rune(s)), 0)), nil
}

func regBytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// regMultiList turns create/modify data into the list of a REG_MULTI_SZ.
// Text is a JSON array of strings, else comma separated, else one item.
// Empty items are dropped: Windows ends the list at the first one.
func regMultiList(data interface{}) ([]string, error) {
	var list []string
	switch v := data.(type) {
	case nil:
	case string:
		if json.Unmarshal([]byte(v), &list) != nil {
			list = strings.Split(v, ",")
		}
	case []string:
		list = v
	case []interface{}:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("expected []string or JSON array for REG_MULTI_SZ, got %T", data)
			}
			list = append(list, s)
		}
	default:
		return nil, fmt.Errorf("expected []string or JSON array for REG_MULTI_SZ, got %T", data)
	}
	out := []string{}
	for _, s := range list {
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// regUint parses DWORD/QWORD data: decimal or 0x-prefixed hex text, or a
// non-negative whole number.
func regUint(data interface{}, bits int, typText string) (uint64, error) {
	bad := func() (uint64, error) {
		return 0, fmt.Errorf("invalid %s value '%v': must be decimal or hex", typText, data)
	}
	limit := uint64(math.MaxUint64)
	if bits == 32 {
		limit = math.MaxUint32
	}
	if data == nil {
		return 0, nil
	}
	if s, ok := data.(string); ok {
		t := strings.TrimSpace(s)
		if t == "" {
			return 0, nil
		}
		var v uint64
		var err error
		if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
			v, err = strconv.ParseUint(t[2:], 16, bits)
		} else {
			v, err = strconv.ParseUint(t, 10, bits)
		}
		if err != nil {
			return bad()
		}
		return v, nil
	}
	rv := reflect.ValueOf(data)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if rv.Int() < 0 || uint64(rv.Int()) > limit {
			return bad()
		}
		return uint64(rv.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if rv.Uint() > limit {
			return bad()
		}
		return rv.Uint(), nil
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if f < 0 || f != math.Trunc(f) || f >= float64(limit)+1 {
			return bad()
		}
		return uint64(f), nil
	}
	return 0, fmt.Errorf("expected numeric value for %s, got %T", typText, data)
}

func regBinaryData(data interface{}) ([]byte, error) {
	switch v := data.(type) {
	case nil:
		return []byte{}, nil
	case string:
		b, err := hex.DecodeString(strings.Join(strings.Fields(v), ""))
		if err != nil {
			return nil, fmt.Errorf("invalid REG_BINARY value '%s': use hex bytes such as 0A 0B 0C", v)
		}
		return b, nil
	case []byte:
		return v, nil
	case []interface{}:
		b := make([]byte, 0, len(v))
		for _, e := range v {
			n, err := regUint(e, 64, "REG_BINARY")
			if err != nil {
				return nil, err
			}
			if n > 255 {
				return nil, fmt.Errorf("invalid REG_BINARY byte %v", e)
			}
			b = append(b, byte(n))
		}
		return b, nil
	}
	return nil, fmt.Errorf("expected hex text for REG_BINARY, got %T", data)
}

// regEncode converts create/modify data of the sent type text into the
// stored type and bytes, plus the type text and display data of the reply.
func regEncode(sentType string, data interface{}) (typText string, typ uint32, raw []byte, display interface{}, err error) {
	typText = strings.ToUpper(strings.TrimSpace(sentType))
	switch typText {
	case "REG_SZ", "REG_EXPAND_SZ":
		typ = regSZ
		if typText == "REG_EXPAND_SZ" {
			typ = regExpandSZ
		}
		s := ""
		switch v := data.(type) {
		case nil:
		case string:
			s = v
		default:
			return typText, 0, nil, nil, fmt.Errorf("expected text for %s, got %T", typText, data)
		}
		raw, err = regEncodeString(s)
		return typText, typ, raw, s, err
	case "REG_MULTI_SZ":
		list, err := regMultiList(data)
		if err != nil {
			return typText, 0, nil, nil, err
		}
		for _, s := range list {
			if strings.IndexByte(s, 0) >= 0 {
				return typText, 0, nil, nil, errRegNUL
			}
		}
		var u []uint16
		for _, s := range list {
			u = append(append(u, utf16.Encode([]rune(s))...), 0)
		}
		return typText, regMultiSZ, regBytes(append(u, 0)), list, nil
	case "REG_DWORD":
		v, err := regUint(data, 32, typText)
		if err != nil {
			return typText, 0, nil, nil, err
		}
		raw = binary.LittleEndian.AppendUint32(nil, uint32(v))
		return typText, regDWord, raw, regDWordText(uint32(v)), nil
	case "REG_QWORD":
		v, err := regUint(data, 64, typText)
		if err != nil {
			return typText, 0, nil, nil, err
		}
		raw = binary.LittleEndian.AppendUint64(nil, v)
		return typText, regQWord, raw, regQWordText(v), nil
	case "REG_BINARY":
		raw, err = regBinaryData(data)
		if err != nil {
			return typText, 0, nil, nil, err
		}
		return typText, regBinary, raw, fmt.Sprintf("% X", raw), nil
	}
	return typText, 0, nil, nil, fmt.Errorf("unsupported registry value type: %s", sentType)
}

// regRenamable lists the value types registry_rename_value accepts.
func regRenamable(typ uint32) bool {
	switch typ {
	case regSZ, regExpandSZ, regMultiSZ, regDWord, regQWord, regBinary:
		return true
	}
	return false
}

// regNode is a snapshot of a key tree: values with their raw type and bytes,
// subkeys by name.
type regNode struct {
	values []regRaw
	subs   []regChild
}

type regRaw struct {
	name string
	typ  uint32
	data []byte
}

type regChild struct {
	name string
	node *regNode
}

// sameRegTree compares two snapshots; names compare without case as the
// registry does.
func sameRegTree(a, b *regNode) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.values) != len(b.values) || len(a.subs) != len(b.subs) {
		return false
	}
	vals := make(map[string]regRaw, len(b.values))
	for _, v := range b.values {
		vals[strings.ToLower(v.name)] = v
	}
	for _, v := range a.values {
		w, ok := vals[strings.ToLower(v.name)]
		if !ok || w.name != v.name || w.typ != v.typ || !bytes.Equal(w.data, v.data) {
			return false
		}
	}
	subs := make(map[string]regChild, len(b.subs))
	for _, c := range b.subs {
		subs[strings.ToLower(c.name)] = c
	}
	for _, c := range a.subs {
		d, ok := subs[strings.ToLower(c.name)]
		if !ok || d.name != c.name || !sameRegTree(c.node, d.node) {
			return false
		}
	}
	return true
}
