// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"runtime"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const uninstallKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// softwareViews: the 64-bit and the 32-bit (WOW6432Node) registry views on
// a 64-bit Windows, also for the 386 build; a 32-bit Windows has only one.
func softwareViews() []uint32 {
	if runtime.GOARCH == "386" {
		var wow64 bool
		if err := windows.IsWow64Process(windows.CurrentProcess(), &wow64); err != nil || !wow64 {
			return []uint32{0}
		}
	}
	return []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY}
}

// Machine-wide Uninstall keys that have a display name. A subkey that cannot
// be read is skipped.
func (a *Agent) GetInstalledSoftware() []rmm.InstalledApp {
	ret := []rmm.InstalledApp{}
	for _, view := range softwareViews() {
		entries, err := uninstallEntries(view)
		if err != nil {
			a.Logger.Debugln("GetInstalledSoftware():", err)
			continue
		}
		for _, e := range entries {
			ret = append(ret, e.record())
		}
	}
	return ret
}

func uninstallEntries(view uint32) ([]uninstallEntry, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKeyPath, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|view)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var ret []uninstallEntry
	for _, name := range names {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		if e, ok := readUninstallEntry(sk); ok {
			ret = append(ret, e)
		}
		sk.Close()
	}
	return ret, nil
}

func readUninstallEntry(k registry.Key) (uninstallEntry, bool) {
	str := func(name string) string {
		v, _, err := k.GetStringValue(name)
		if err != nil {
			return ""
		}
		return v
	}
	e := uninstallEntry{name: str("DisplayName")}
	if e.name == "" {
		return e, false
	}
	e.version = str("DisplayVersion")
	e.publisher = str("Publisher")
	e.installDate = str("InstallDate")
	e.source = str("InstallSource")
	e.location = str("InstallLocation")
	e.uninstall = str("UninstallString")
	if size, _, err := k.GetIntegerValue("EstimatedSize"); err == nil {
		e.sizeKiB = size
	}
	return e, true
}
