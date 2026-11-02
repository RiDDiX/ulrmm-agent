// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package agent

import (
	"errors"
	"reflect"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/StackExchange/wmi"
)

const wmiClassTimeout = 60 * time.Second

// wmiFixed selects the properties of T by name; the struct name is the
// class. Properties listed in wmiReadAs are read in WMI's own type and
// converted back. Any other type mismatch keeps the rows; the library stops
// filling that instance at the mismatched field.
func wmiFixed[T any]() ([]interface{}, error) {
	return wmiBounded(wmiClassTimeout, func() ([]interface{}, error) {
		var proto []T
		t := reflect.TypeOf(proto).Elem()
		as := wmiReadAs[t.Name()]
		dst := reflect.New(reflect.SliceOf(wmiMirror(t, as)))
		err := wmi.Query(wmi.CreateQuery(&proto, ""), dst.Interface())
		var mismatch *wmi.ErrFieldMismatch
		if err != nil && !errors.As(err, &mismatch) {
			return nil, err
		}
		rows := wmiRows(dst.Elem().Interface())
		for name := range as {
			if f, ok := t.FieldByName(name); ok {
				wmiConvertRows(rows, name, f.Type)
			}
		}
		return rows, nil
	})
}

// wmiExtended tries SELECT * into the extended struct first. Any error,
// including a property older Windows lacks, falls back to the base struct,
// whose name is the class.
func wmiExtended[EX, Base any]() ([]interface{}, error) {
	class := reflect.TypeOf((*Base)(nil)).Elem().Name()
	rows, err := wmiBounded(wmiClassTimeout, func() ([]interface{}, error) {
		var dst []EX
		if err := wmi.Query("SELECT * FROM "+class, &dst); err != nil {
			return nil, err
		}
		return wmiRows(dst), nil
	})
	if err == nil || errors.Is(err, errWMITimeout) || errors.Is(err, errWMIBusy) {
		return rows, err
	}
	return wmiFixed[Base]()
}

// Every key is present. A class that fails or times out is an empty list.
func (a *Agent) GetWMIInfo() map[string]interface{} {
	classes := []struct {
		key   string
		query func() ([]interface{}, error)
	}{
		{"comp_sys_prod", wmiFixed[rmm.Win32_ComputerSystemProduct]},
		{"comp_sys", wmiExtended[rmm.Win32_ComputerSystemEX, rmm.Win32_ComputerSystem]},
		{"network_config", wmiFixed[rmm.Win32_NetworkAdapterConfiguration]},
		{"mem", wmiExtended[rmm.Win32_PhysicalMemoryEX, rmm.Win32_PhysicalMemory]},
		{"os", wmiFixed[rmm.Win32_OperatingSystem]},
		{"base_board", wmiFixed[rmm.Win32_BaseBoard]},
		{"bios", wmiExtended[rmm.Win32_BIOSEX, rmm.Win32_BIOS]},
		{"disk", wmiFixed[rmm.Win32_DiskDrive]},
		{"network_adapter", wmiFixed[rmm.Win32_NetworkAdapter]},
		{"desktop_monitor", wmiFixed[rmm.Win32_DesktopMonitor]},
		{"cpu", wmiExtended[rmm.Win32_ProcessorEX, rmm.Win32_Processor]},
		{"usb", wmiFixed[rmm.Win32_USBController]},
		{"graphics", wmiFixed[rmm.Win32_VideoController]},
	}

	ret := make(map[string]interface{}, len(classes)+2)
	for _, c := range classes {
		rows, err := c.query()
		if err != nil {
			a.Logger.Debugln("wmi", c.key, err)
			rows = []interface{}{}
		}
		ret[c.key] = rows
	}
	ret["nics"] = withWoL(nics())
	ret["health"] = a.Health()
	return ret
}
