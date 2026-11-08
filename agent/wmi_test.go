// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type wmiSample struct {
	Name        string
	AdapterRAM  uint32
	Size        uint64
	Depth       float32
	PoweredOn   bool
	IPAddress   []string
	InstallDate time.Time
	DriverDate  time.Time
}

func TestWMIRows(t *testing.T) {
	drv := time.Date(2020, 11, 20, 0, 0, 0, 0, time.UTC)
	rows := wmiRows([]wmiSample{
		{Name: "GPU", AdapterRAM: 2147483648, Size: 512110190592, PoweredOn: true, DriverDate: drv},
		{Name: "NIC", IPAddress: []string{"10.0.0.5", "fe80::1"}},
	})
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	for i, r := range rows {
		inner, ok := r.([]interface{})
		if !ok || len(inner) != 1 {
			t.Fatalf("row %d is %#v, want a one-element list", i, r)
		}
	}
	o := rows[0].([]interface{})[0].(map[string]interface{})
	want := map[string]interface{}{
		"Name":        "GPU",
		"AdapterRAM":  float64(2147483648),
		"Size":        float64(512110190592),
		"Depth":       float64(0),
		"PoweredOn":   true,
		"InstallDate": "0001-01-01T00:00:00Z",
		"DriverDate":  "2020-11-20T00:00:00Z",
	}
	for k, v := range want {
		if o[k] != v {
			t.Errorf("%s = %#v, want %#v", k, o[k], v)
		}
	}
	if ip, ok := o["IPAddress"]; !ok || ip != nil {
		t.Errorf("unset list = %#v (present %v), want null", ip, ok)
	}
	if len(o) != 8 {
		t.Errorf("keys = %d, want 8 (property names untouched)", len(o))
	}
	o2 := rows[1].([]interface{})[0].(map[string]interface{})
	if ips, _ := o2["IPAddress"].([]interface{}); len(ips) != 2 || ips[0] != "10.0.0.5" {
		t.Errorf("IPAddress = %#v", o2["IPAddress"])
	}

	for _, empty := range []interface{}{nil, []wmiSample(nil), []wmiSample{}} {
		if r := wmiRows(empty); r == nil || len(r) != 0 {
			t.Errorf("wmiRows(%#v) = %#v, want an empty non-nil list", empty, r)
		}
	}
}

func TestWMIStuck(t *testing.T) {
	release := make(chan struct{})
	if _, err := wmiBounded(20*time.Millisecond, func() (int, error) { <-release; return 1, nil }); err != errWMITimeout {
		t.Fatalf("timeout case: %v", err)
	}
	defer func() {
		close(release)
		for deadline := time.Now().Add(2 * time.Second); wmiAbandoned.Load() != 0 && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if _, err := wmiBounded(time.Second, func() (int, error) { return 1, nil }); err != errWMIBusy {
		t.Fatalf("fresh hang: %v", err)
	}
	wmiBusySince.Store(time.Now().Add(-31 * time.Minute).UnixNano())
	if _, err := wmiBounded(time.Second, func() (int, error) { return 1, nil }); err != errWMIStuck || !errors.Is(err, errWMIBusy) {
		t.Fatalf("hang over 30 min: %v", err)
	}
}

func TestWMIBounded(t *testing.T) {
	v, err := wmiBounded(time.Second, func() (int, error) { return 7, nil })
	if v != 7 || err != nil {
		t.Fatalf("ok case: %v %v", v, err)
	}
	boom := errors.New("boom")
	if _, err := wmiBounded(time.Second, func() (int, error) { return 0, boom }); err != boom {
		t.Fatalf("error case: %v", err)
	}
	if _, err := wmiBounded(time.Second, func() (int, error) { panic("bad array") }); err == nil {
		t.Fatal("panic was not turned into an error")
	}

	release := make(chan struct{})
	if _, err := wmiBounded(20*time.Millisecond, func() (int, error) { <-release; return 1, nil }); err != errWMITimeout {
		t.Fatalf("timeout case: %v", err)
	}
	ran := false
	if _, err := wmiBounded(time.Second, func() (int, error) { ran = true; return 1, nil }); err != errWMIBusy || ran {
		t.Fatalf("query behind a hung one: err %v, ran %v", err, ran)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for wmiAbandoned.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if v, err := wmiBounded(time.Second, func() (int, error) { return 2, nil }); v != 2 || err != nil {
		t.Fatalf("after the hung query returned: %v %v", v, err)
	}
}

type wmiBoard struct {
	Product string
	Weight  int32
	Caps    []string
}

func TestWMIReadAs(t *testing.T) {
	as := map[string]reflect.Type{"Weight": reflect.TypeOf(float32(0)), "Caps": reflect.TypeOf([]int32(nil))}
	mt := wmiMirror(reflect.TypeOf(wmiBoard{}), as)
	if mt.Field(1).Type.Kind() != reflect.Float32 || mt.Field(0).Type.Kind() != reflect.String {
		t.Fatalf("mirror %v", mt)
	}
	// what the WMI library fills in WMI's own types
	rows := reflect.MakeSlice(reflect.SliceOf(mt), 2, 2)
	rows.Index(0).Field(0).SetString("Board")
	rows.Index(0).Field(1).SetFloat(2.75)
	rows.Index(0).Field(2).Set(reflect.ValueOf([]int32{3, 7}))
	got := wmiRows(rows.Interface())
	wt := reflect.TypeOf(wmiBoard{})
	for name := range as {
		f, _ := wt.FieldByName(name)
		wmiConvertRows(got, name, f.Type)
	}
	m := got[0].([]interface{})[0].(map[string]interface{})
	if m["Product"] != "Board" || m["Weight"] != 2.0 || !reflect.DeepEqual(m["Caps"], []interface{}{"3", "7"}) {
		t.Fatalf("converted %#v", m)
	}
	if n := got[1].([]interface{})[0].(map[string]interface{}); n["Caps"] != nil || n["Weight"] != 0.0 {
		t.Fatalf("unset values %#v", n)
	}
	if k := wmiReadAs["Win32_VideoController"]["AcceleratorCapabilities"].Elem().Kind(); k != reflect.Int32 {
		t.Errorf("AcceleratorCapabilities read as []%v, WMI sends VT_I4", k)
	}
	for class, fields := range wmiReadAs {
		if len(fields) == 0 {
			t.Errorf("%s: empty list", class)
		}
	}
}
