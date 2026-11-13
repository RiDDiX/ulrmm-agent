// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	regAPI            = windows.NewLazySystemDLL("advapi32.dll")
	procRegSetValueEx = regAPI.NewProc("RegSetValueExW")
	procRegRenameKey  = regAPI.NewProc("RegRenameKey")
	procRegDeleteKey  = regAPI.NewProc("RegDeleteKeyExW")
)

const (
	regOpenLink = 0x8 // REG_OPTION_OPEN_LINK: open a link key itself, not its target
	regReadKey  = registry.ENUMERATE_SUB_KEYS | registry.QUERY_VALUE
	// the native view also from a 386 build on 64-bit Windows, where SOFTWARE
	// would otherwise be redirected to WOW6432Node; 32-bit Windows ignores it
	regView = registry.WOW64_64KEY
	// regMoveLimit caps what a key move between parents or a value rename
	// holds in memory.
	regMoveLimit = 64 << 20
)

var (
	errRegDenied   = errors.New(regKeyDenied)
	errRegTooLarge = errors.New("registry data too large")
)

func regLocate(path string) (registry.Key, string, error) {
	hive, sub, err := splitRegPath(path)
	if err != nil {
		return 0, "", err
	}
	switch hive {
	case "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, sub, nil
	case "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, sub, nil
	case "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, sub, nil
	case "HKEY_USERS":
		return registry.USERS, sub, nil
	}
	return registry.CURRENT_CONFIG, sub, nil
}

// regOpenNoFollow opens sub without following it when it is a link.
func regOpenNoFollow(k registry.Key, sub string, access uint32) (registry.Key, error) {
	p, err := windows.UTF16PtrFromString(sub)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.Handle(k), p, regOpenLink, access|regView, &h); err != nil {
		return 0, err
	}
	return registry.Key(h), nil
}

// regDeleteKey deletes an empty key in the regView view; registry.DeleteKey
// cannot choose one.
func regDeleteKey(root registry.Key, sub string) error {
	p, err := windows.UTF16PtrFromString(sub)
	if err != nil {
		return err
	}
	if r, _, _ := procRegDeleteKey.Call(uintptr(root), uintptr(unsafe.Pointer(p)), regView, 0); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regIsLink(k registry.Key) bool {
	_, typ, err := k.GetValue("SymbolicLinkValue", nil)
	return err == nil && typ == regLink
}

// regReadRaw reads a value's type and bytes. Data above limit gives
// errRegTooLarge with the type and the size.
func regReadRaw(k registry.Key, name string, limit int) (typ uint32, data []byte, size int, err error) {
	for try := 0; try < 3; try++ {
		n, t, err := k.GetValue(name, nil)
		if err != nil {
			return 0, nil, 0, err
		}
		if n > limit {
			return t, nil, n, errRegTooLarge
		}
		buf := make([]byte, n)
		m, t, err := k.GetValue(name, buf)
		if err == nil {
			return t, buf[:m], m, nil
		}
		if !errors.Is(err, syscall.ERROR_MORE_DATA) {
			return 0, nil, 0, err
		}
	}
	return 0, nil, 0, syscall.ERROR_MORE_DATA
}

func regSetRaw(k registry.Key, name string, typ uint32, data []byte) error {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var d *byte
	if len(data) > 0 {
		d = &data[0]
	}
	r, _, _ := procRegSetValueEx.Call(uintptr(k), uintptr(unsafe.Pointer(p)), 0, uintptr(typ),
		uintptr(unsafe.Pointer(d)), uintptr(len(data)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regHasSubkeys(k registry.Key, name string) bool {
	c, err := registry.OpenKey(k, name, registry.QUERY_VALUE|regView)
	if err != nil {
		return false
	}
	defer c.Close()
	st, err := c.Stat()
	return err == nil && st.SubKeyCount > 0
}

// BrowseRegistry lists one page of subkeys of path and all of its values.
func BrowseRegistry(path string, page, size int) ([]map[string]interface{}, []map[string]interface{}, bool, error) {
	if isRegComputer(path) {
		hives := make([]map[string]interface{}, 0, len(regHives))
		for _, h := range regHives {
			hives = append(hives, map[string]interface{}{"name": h, "hasSubkeys": true})
		}
		return hives, []map[string]interface{}{}, false, nil
	}
	if regDenied(path, false, false) {
		return nil, nil, false, errRegDenied
	}
	root, sub, err := regLocate(path)
	if err != nil {
		return nil, nil, false, err
	}
	k, err := registry.OpenKey(root, sub, regReadKey|regView)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to open key %s: %v", path, err)
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(0)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to read subkeys for %s: %v", path, err)
	}
	start, end, more := regPage(len(names), page, size)
	subkeys := make([]map[string]interface{}, 0, end-start)
	for _, n := range names[start:end] {
		subkeys = append(subkeys, map[string]interface{}{"name": n, "hasSubkeys": regHasSubkeys(k, n)})
	}

	valueNames, err := k.ReadValueNames(0)
	if err != nil {
		return nil, nil, false, err
	}
	values := make([]map[string]interface{}, 0, len(valueNames))
	for _, n := range valueNames {
		typ, data, sz, err := regReadRaw(k, n, regBrowseMaxData)
		switch {
		case errors.Is(err, errRegTooLarge):
			values = append(values, map[string]interface{}{"name": n, "type": regTypeText(typ), "data": regTooLargeText(sz)})
			continue
		case errors.Is(err, registry.ErrNotExist):
			continue // removed while listing
		case err != nil:
			return nil, nil, false, err
		}
		t, d := regDisplay(typ, data)
		values = append(values, map[string]interface{}{"name": n, "type": t, "data": d})
	}
	return subkeys, values, more, nil
}

func CreateRegistryKey(path string) error {
	if regDenied(path, true, false) {
		return errRegDenied
	}
	root, sub, err := regLocate(path)
	if err != nil {
		return fmt.Errorf("parsing registry path: %v", err)
	}
	k, existed, err := registry.CreateKey(root, sub, registry.QUERY_VALUE|regView)
	if err != nil {
		return fmt.Errorf("failed to create registry key '%s': %v", path, err)
	}
	k.Close()
	if existed {
		return fmt.Errorf("registry key '%s' already exists", path)
	}
	return nil
}

func DeleteRegistryKey(path string) error {
	path = strings.TrimRight(path, `\`)
	if r := regRootName(path); r != "" {
		return fmt.Errorf("deleting root hive '%s' is not allowed", r)
	}
	if regDenied(path, true, true) {
		return errRegDenied
	}
	root, sub, err := regLocate(path)
	if err != nil {
		return err
	}
	return regDeleteTree(root, sub, path)
}

// regDeleteTree deletes sub depth-first. Link keys are refused, so the
// delete never continues into the tree a link points to.
func regDeleteTree(root registry.Key, sub, full string) error {
	k, err := regOpenNoFollow(root, sub, regReadKey)
	if err != nil {
		return fmt.Errorf("failed to open key %s: %v", full, err)
	}
	if regIsLink(k) {
		k.Close()
		return fmt.Errorf("%s is a registry link; links are not deleted", full)
	}
	names, err := k.ReadSubKeyNames(0)
	k.Close()
	if err != nil {
		return fmt.Errorf("failed to read subkeys for %s: %v", full, err)
	}
	for _, n := range names {
		if err := regDeleteTree(root, sub+`\`+n, full+`\`+n); err != nil {
			return err
		}
	}
	if err := regDeleteKey(root, sub); err != nil {
		return fmt.Errorf("failed to delete registry key %s: %v", full, err)
	}
	return nil
}

// RenameRegistryKey renames a key in place when only its last name
// changes, otherwise copies the tree by raw type and bytes, checks the copy
// and then deletes the source.
func RenameRegistryKey(oldPath, newPath string) error {
	oldPath, newPath = strings.TrimRight(oldPath, `\`), strings.TrimRight(newPath, `\`)
	if regDenied(oldPath, true, true) || regDenied(newPath, true, false) {
		return errRegDenied
	}
	if r := regRootName(oldPath); r != "" {
		return fmt.Errorf("renaming root hive '%s' is not allowed", r)
	}
	oh, osub, err := splitRegPath(oldPath)
	if err != nil {
		return err
	}
	nh, nsub, err := splitRegPath(newPath)
	if err != nil {
		return err
	}
	sameHive := oh == nh
	if sameHive && osub == nsub {
		return errors.New("Old and new path cannot be the same")
	}
	if sameHive && strings.HasPrefix(strings.ToLower(nsub), strings.ToLower(osub)+`\`) {
		return errors.New("a key cannot be moved below itself")
	}
	oroot, _, _ := regLocate(oldPath)
	nroot, _, _ := regLocate(newPath)

	src, err := regOpenNoFollow(oroot, osub, regReadKey)
	if err != nil {
		return fmt.Errorf("failed to open key %s: %v", oldPath, err)
	}
	link := regIsLink(src)
	src.Close()

	exists := func() error {
		if k, err := registry.OpenKey(nroot, nsub, registry.QUERY_VALUE|regView); err == nil {
			k.Close()
			return fmt.Errorf("registry key '%s' already exists", newPath)
		}
		return nil
	}
	opar, _ := regParent(osub)
	npar, nbase := regParent(nsub)
	if sameHive && strings.EqualFold(opar, npar) && procRegRenameKey.Find() == nil {
		if !strings.EqualFold(osub, nsub) {
			if err := exists(); err != nil {
				return err
			}
		}
		return regRenameInPlace(oroot, osub, nbase, oldPath)
	}
	if link {
		return fmt.Errorf("%s is a registry link; links are only renamed within their parent key", oldPath)
	}
	if err := exists(); err != nil {
		return err
	}
	return regMoveTree(oroot, osub, oldPath, nroot, nsub, newPath)
}

func regRenameInPlace(root registry.Key, sub, newName, full string) error {
	k, err := regOpenNoFollow(root, sub, registry.WRITE)
	if err != nil {
		return fmt.Errorf("failed to open key %s: %v", full, err)
	}
	defer k.Close()
	p, err := windows.UTF16PtrFromString(newName)
	if err != nil {
		return err
	}
	if r, _, _ := procRegRenameKey.Call(uintptr(k), 0, uintptr(unsafe.Pointer(p))); r != 0 {
		return fmt.Errorf("failed to rename registry key '%s': %v", full, syscall.Errno(r))
	}
	return nil
}

func regMoveTree(oroot registry.Key, osub, oldPath string, nroot registry.Key, nsub, newPath string) error {
	budget := regMoveLimit
	snap, err := regSnapshot(oroot, osub, oldPath, &budget)
	if err != nil {
		return err
	}
	dst, existed, err := registry.CreateKey(nroot, nsub, registry.WRITE|regView)
	if err != nil {
		return fmt.Errorf("failed to create registry key '%s': %v", newPath, err)
	}
	if existed {
		dst.Close()
		return fmt.Errorf("registry key '%s' already exists", newPath)
	}
	err = regWriteTree(dst, snap)
	dst.Close()
	if err == nil {
		// Read both trees back: the copy must match, and the source must be
		// unchanged (it changed if the target is an alias inside it).
		var got, again *regNode
		budget = regMoveLimit
		if got, err = regSnapshot(nroot, nsub, newPath, &budget); err == nil {
			budget = regMoveLimit
			if again, err = regSnapshot(oroot, osub, oldPath, &budget); err == nil &&
				(!sameRegTree(snap, got) || !sameRegTree(snap, again)) {
				err = errors.New("the copy does not match the source")
			}
		}
	}
	if err != nil {
		_ = regDeleteTree(nroot, nsub, newPath)
		return fmt.Errorf("failed to copy %s to %s: %v", oldPath, newPath, err)
	}
	if err := regDeleteTree(oroot, osub, oldPath); err != nil {
		return fmt.Errorf("copied to %s, but the old key was not removed: %v", newPath, err)
	}
	return nil
}

func regSnapshot(root registry.Key, sub, full string, budget *int) (*regNode, error) {
	k, err := regOpenNoFollow(root, sub, regReadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to open key %s: %v", full, err)
	}
	defer k.Close()
	if regIsLink(k) {
		return nil, fmt.Errorf("%s is a registry link; links are not copied", full)
	}
	tooLarge := fmt.Errorf("%s is too large to move", full)
	if *budget -= 256; *budget < 0 {
		return nil, tooLarge
	}
	node := &regNode{}
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read values of %s: %v", full, err)
	}
	for _, n := range names {
		typ, data, _, err := regReadRaw(k, n, *budget)
		if errors.Is(err, errRegTooLarge) {
			return nil, tooLarge
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read value '%s' of %s: %v", n, full, err)
		}
		if *budget -= len(data) + 2*len(n); *budget < 0 {
			return nil, tooLarge
		}
		node.values = append(node.values, regRaw{name: n, typ: typ, data: data})
	}
	subs, err := k.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read subkeys for %s: %v", full, err)
	}
	for _, s := range subs {
		c, err := regSnapshot(root, sub+`\`+s, full+`\`+s, budget)
		if err != nil {
			return nil, err
		}
		node.subs = append(node.subs, regChild{name: s, node: c})
	}
	return node, nil
}

func regWriteTree(dst registry.Key, n *regNode) error {
	for _, v := range n.values {
		if err := regSetRaw(dst, v.name, v.typ, v.data); err != nil {
			return fmt.Errorf("failed to write value '%s': %v", v.name, err)
		}
	}
	for _, c := range n.subs {
		k, _, err := registry.CreateKey(dst, c.name, registry.WRITE|regView)
		if err != nil {
			return fmt.Errorf("failed to create subkey '%s': %v", c.name, err)
		}
		err = regWriteTree(k, c.node)
		k.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateRegistryValue(path, name, typ string, data interface{}) (map[string]interface{}, error) {
	return regPutValue(path, name, typ, data, true)
}

func ModifyRegistryValue(path, name, typ string, data interface{}) (map[string]interface{}, error) {
	return regPutValue(path, name, typ, data, false)
}

// regPutValue writes a value; create refuses an existing name, modify
// creates or overwrites it, also with another type.
func regPutValue(path, name, sentType string, data interface{}, create bool) (map[string]interface{}, error) {
	if regDenied(path, true, false) {
		return nil, errRegDenied
	}
	n, err := regValueName(name)
	if err != nil {
		return nil, err
	}
	typText, typ, raw, display, err := regEncode(sentType, data)
	if err != nil {
		return nil, err
	}
	root, sub, err := regLocate(path)
	if err != nil {
		return nil, err
	}
	verb, access := "modify", uint32(registry.SET_VALUE)
	if create {
		verb, access = "create", registry.SET_VALUE|registry.QUERY_VALUE
	}
	k, err := registry.OpenKey(root, sub, access|regView)
	if err != nil {
		return nil, fmt.Errorf("failed to open key for writing '%s': %v", path, err)
	}
	defer k.Close()
	if create {
		if _, _, err := k.GetValue(n, nil); err == nil {
			return nil, fmt.Errorf("registry value '%s' already exists under '%s'", n, path)
		}
	}
	if err := regSetRaw(k, n, typ, raw); err != nil {
		return nil, fmt.Errorf("failed to %s %s value '%s': %v", verb, typText, n, err)
	}
	return map[string]interface{}{"name": n, "type": typText, "data": display}, nil
}

func DeleteRegistryValue(path, name string) error {
	path = strings.TrimRight(path, `\`)
	if regDenied(path, true, false) {
		return errRegDenied
	}
	n, err := regValueName(name)
	if err != nil {
		return err
	}
	root, sub, err := regLocate(path)
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.SET_VALUE|regView)
	if err != nil {
		return fmt.Errorf("failed to open key for writing '%s': %v", path, err)
	}
	defer k.Close()
	if _, _, err := k.GetValue(n, nil); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("value '%s' does not exist under %s", n, path)
		}
		return err
	}
	if err := k.DeleteValue(n); err != nil {
		return fmt.Errorf("failed to delete value '%s': %v", n, err)
	}
	return nil
}

// RenameRegistryValue copies the value's raw type and bytes to the new
// name, then deletes the old one. An existing target name is refused.
func RenameRegistryValue(path, oldName, newName string) (string, error) {
	path = strings.TrimRight(path, `\`)
	if regDenied(path, true, false) {
		return "", errRegDenied
	}
	o, err := regNamedValue(oldName)
	if err != nil {
		return "", err
	}
	nn, err := regNamedValue(newName)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(o, nn) {
		return "", errors.New("old and new name are the same")
	}
	root, sub, err := regLocate(path)
	if err != nil {
		return "", err
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.SET_VALUE|regView)
	if err != nil {
		return "", fmt.Errorf("failed to open key for writing '%s': %v", path, err)
	}
	defer k.Close()
	typ, data, _, err := regReadRaw(k, o, regMoveLimit)
	if err != nil {
		return "", fmt.Errorf("failed to read old value: %v", err)
	}
	if !regRenamable(typ) {
		return "", fmt.Errorf("unsupported registry type: %d", typ)
	}
	if _, _, err := k.GetValue(nn, nil); err == nil {
		return "", fmt.Errorf("registry value '%s' already exists under '%s'", nn, path)
	}
	if err := regSetRaw(k, nn, typ, data); err != nil {
		return "", fmt.Errorf("failed to write new value: %v", err)
	}
	if err := k.DeleteValue(o); err != nil {
		_ = k.DeleteValue(nn)
		return "", fmt.Errorf("failed to delete old value: %v", err)
	}
	return nn, nil
}
