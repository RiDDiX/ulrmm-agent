// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWSCState(t *testing.T) {
	// measured: ESET on, Defender off (ESET active), Defender on
	for state, want := range map[uint32][2]bool{
		0x041000: {true, true},
		0x060100: {false, true},
		0x061100: {true, true},
		0x061110: {true, false},
	} {
		on, fresh := wscState(state)
		if on != want[0] || fresh != want[1] {
			t.Fatalf("%#x: got %v %v", state, on, fresh)
		}
	}
}

func TestWoLDecode(t *testing.T) {
	// supported pumbg, wolopts g / d / none
	if got := ethtoolWoL(0x2f, 0x20); got != "on" {
		t.Fatal(got)
	}
	if got := ethtoolWoL(0x2f, 0); got != "off" {
		t.Fatal(got)
	}
	if got := ethtoolWoL(0x0f, 0); got != "unsupported" {
		t.Fatal(got)
	}
	for v, want := range map[uint32]string{0: "unsupported", 1: "off", 2: "on", 7: ""} {
		if got := winWoL(v); got != want {
			t.Fatalf("%d: %q", v, got)
		}
	}
}

func TestSaneC(t *testing.T) {
	if saneC(65261.85, true) != nil || saneC(-50, false) != nil || saneC(0, true) != nil {
		t.Fatal("bogus value kept")
	}
	if c := saneC(83.85, true); c == nil || *c != 84 {
		t.Fatal(c)
	}
	if c := saneC(0, false); c == nil || *c != 0 {
		t.Fatal("0 C is a valid reading")
	}
}

func TestWQLEscape(t *testing.T) {
	if got := wqlEscape(`{1}\\H\x.ObjectId="{a}"`); got != `{1}\\\\H\\x.ObjectId=\"{a}\"` {
		t.Fatal(got)
	}
	if wqlEscape(`a"b`) != `a\"b` || wqlEscape(`a\b`) != `a\\b` {
		t.Fatal("escape")
	}
}

func TestParseNvmeLog(t *testing.T) {
	b := make([]byte, 512)
	binary.LittleEndian.PutUint16(b[1:3], 318) // 45 C
	b[3], b[5] = 100, 7
	binary.LittleEndian.PutUint64(b[128:136], 6312)
	d, ok := parseNvmeLog(b)
	if !ok || d.Health != "ok" || *d.TempC != 45 || *d.WearPct != 7 || *d.POH != 6312 || *d.MediaErrors != 0 {
		t.Fatalf("%+v", d)
	}
	// bit 1 (temperature threshold) alone is no failing drive
	b[0] = 0x02
	if d, _ := parseNvmeLog(b); d.Health != "ok" || d.Smart != "passed" || *d.CriticalWarning != 0 {
		t.Fatalf("%+v", d)
	}
	b[0] = 0x04
	if d, _ := parseNvmeLog(b); d.Health != "failing" || d.Smart != "failed" || *d.CriticalWarning != 4 {
		t.Fatalf("%+v", d)
	}
	b[0] = 0x06
	if d, _ := parseNvmeLog(b); d.Health != "failing" || d.Smart != "failed" || *d.CriticalWarning != 4 {
		t.Fatalf("%+v", d)
	}
	if _, ok := parseNvmeLog(b[:100]); ok {
		t.Fatal("short buffer accepted")
	}
}

func TestParseSmartctl(t *testing.T) {
	standby := `{"smartctl":{"exit_status":2,"messages":[{"string":"Device is in STANDBY mode, exit(2)"}]},"device":{"protocol":"ATA"}}`
	d, err := parseSmartctl([]byte(standby))
	if err != nil || d.Smart != "standby" || d.TempC != nil {
		t.Fatalf("%+v %v", d, err)
	}
	ok := `{"smartctl":{"exit_status":0},"device":{"protocol":"SCSI"},"smart_status":{"passed":true},"temperature":{"current":0},"serial_number":"X"}`
	d, _ = parseSmartctl([]byte(ok))
	if d.Smart != "passed" || d.Health != "ok" || d.TempC != nil || d.Bus != "scsi" {
		t.Fatalf("%+v", d)
	}
	bad := `{"smartctl":{"exit_status":8},"device":{"protocol":"ATA"},"model_name":"TOSHIBA MG08","serial_number":"S3CR3T","rotation_rate":7200,"smart_status":{"passed":false},"temperature":{"current":41},"power_on_time":{"hours":19310}}`
	d, _ = parseSmartctl([]byte(bad))
	if d.Smart != "failed" || d.Health != "failing" || *d.TempC != 41 || *d.POH != 19310 || d.Media != "hdd" || d.Name != "TOSHIBA MG08" {
		t.Fatalf("%+v", d)
	}
	if b, _ := json.Marshal(d); strings.Contains(string(b), "S3CR3T") {
		t.Fatal(string(b))
	}
	if _, err := parseSmartctl([]byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSmartctlType(t *testing.T) {
	for in, want := range map[string]string{"scsi": "sat,auto", "sat": "sat", "nvme": "nvme", "megaraid,0": "megaraid,0"} {
		if got := smartctlType(in); got != want {
			t.Fatalf("%s: %s", in, got)
		}
	}
}

func TestParseSmartScan(t *testing.T) {
	out := "/dev/sda -d sat # /dev/sda [SAT], ATA device\n/dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n" +
		"/dev/sdb -d scsi; rm -rf / # nope\n/etc/passwd -d sat # no\n/dev/bus/0 -d megaraid,0 # raid\n"
	got := parseSmartScan(out)
	want := [][2]string{{"/dev/sda", "sat"}, {"/dev/nvme0", "nvme"}, {"/dev/bus/0", "megaraid,0"}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

func TestNftHasInputChain(t *testing.T) {
	docker := `{"nftables":[{"metainfo":{}},{"chain":{"family":"ip","table":"filter","name":"FORWARD","hook":"forward","policy":"drop"}}]}`
	aegis := `{"nftables":[{"chain":{"family":"inet","table":"aegis","name":"eingang","hook":"input","policy":"accept"}}]}`
	if nftHasInputChain([]byte(docker)) || !nftHasInputChain([]byte(aegis)) || nftHasInputChain([]byte("x")) {
		t.Fatal("nft")
	}
}

func TestMacParsers(t *testing.T) {
	ac, batt := parsePmsetWomp("Battery Power:\n lidwake 1\n womp                 0\nAC Power:\n womp                 1\n")
	if ac == nil || !*ac || batt == nil || *batt {
		t.Fatalf("%v %v", ac, batt)
	}
	v, inst := parseXProtect("Version: 5360 Installed: 2026-09-17 22:58:51 +0000\n")
	if v != "5360" || inst != "2026-09-17 22:58:51 +0000" {
		t.Fatalf("%q %q", v, inst)
	}
	if s := socketFWState("Firewall is enabled. (State = 1)\n"); s == nil || !*s {
		t.Fatal("state 1")
	}
	if s := socketFWState("Firewall is blocking all non-essential incoming connections. (State = 2)"); s == nil || !*s {
		t.Fatal("state 2")
	}
	if s := socketFWState("Firewall is disabled. (State = 0)"); s == nil || *s {
		t.Fatal("state 0")
	}
	if p := lastInt("com.apple.system.thermalpressurelevel 0\n"); p == nil || *p != 0 {
		t.Fatal("thermal")
	}
}

func TestParseSystemProfiler(t *testing.T) {
	out := `{"SPNVMeDataType":[{"_items":[{"_name":"APPLE SSD AP0512Z","device_serial":"SECRET","smart_status":"Verified"}]}],
	"SPPowerDataType":[{"_name":"spbattery_information","sppower_battery_health_info":{"sppower_battery_cycle_count":40,"sppower_battery_health":"Good","sppower_battery_health_maximum_capacity":"100%"},"sppower_battery_model_info":{"sppower_battery_serial_number":"SECRET"}}],
	"SPSerialATADataType":[]}`
	bat, disks, err := parseSystemProfiler([]byte(out))
	if err != nil || bat == nil || *bat.MaxCapacityPct != 100 || *bat.Cycles != 40 || bat.Condition != "Good" {
		t.Fatalf("%+v %v", bat, err)
	}
	if len(disks) != 1 || disks[0].Health != "ok" || disks[0].Bus != "nvme" {
		t.Fatalf("%+v", disks)
	}
	b, _ := json.Marshal(Health{Battery: bat, Disks: disks})
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("serial leaked")
	}
}

func TestHealthCaps(t *testing.T) {
	h := &Health{}
	for i := 0; i < 100; i++ {
		h.addDisk(HDisk{})
		h.addTemp(HTemp{})
		h.errf("%s", strings.Repeat("x", 500))
	}
	if len(h.Disks) != healthMaxList || len(h.Temps) != healthMaxList || len(h.Errors) != 16 || len(h.Errors[0]) != 128 {
		t.Fatalf("%d %d %d", len(h.Disks), len(h.Temps), len(h.Errors))
	}
}

// A stage that overruns the deadline costs only its own sections; it keeps
// writing after the report is returned without touching it.
func TestRunHealthKeepsFinishedSectionsOnTimeout(t *testing.T) {
	release, slowDone := make(chan struct{}), make(chan struct{})
	h := runHealth([]healthStage{
		func(_ context.Context, h *Health) {
			h.AV = []HAV{{Name: "ClamAV"}}
			h.errf("ufw: gone")
		},
		func(ctx context.Context, h *Health) {
			<-ctx.Done()
			<-release
			h.Disks = append(h.Disks, HDisk{Name: "late"})
			h.errf("late")
			close(slowDone)
		},
		func(_ context.Context, h *Health) { h.Temps = []HTemp{{Name: "never"}} },
	}, 200*time.Millisecond)
	close(release)
	<-slowDone
	if len(h.Errors) != 2 || h.Errors[0] != "collection timed out" || h.Errors[1] != "ufw: gone" {
		t.Fatalf("errors %q", h.Errors)
	}
	if len(h.AV) != 1 || h.Disks != nil || h.Temps != nil || h.V != 1 {
		t.Fatalf("%+v", h)
	}
}

func TestRunHealthMergesAllStages(t *testing.T) {
	h := runHealth([]healthStage{
		func(_ context.Context, h *Health) { h.Power.S3 = ptr(true) },
		func(_ context.Context, h *Health) { h.Power.ModernStandby = ptr(false); h.AV = []HAV{} },
		func(_ context.Context, h *Health) { panic("boom") },
		func(_ context.Context, h *Health) { h.Disks = []HDisk{{Name: "a"}}; h.Firewall = &HFirewall{} },
	}, time.Minute)
	if h.Power.S3 == nil || !*h.Power.S3 || h.Power.ModernStandby == nil || len(h.Disks) != 1 || h.Firewall == nil {
		t.Fatalf("%+v", h)
	}
	// [] and null mean different things to the server
	if h.AV == nil || h.Temps != nil {
		t.Fatalf("av %v temps %v", h.AV, h.Temps)
	}
	if len(h.Errors) != 1 || !strings.Contains(h.Errors[0], "collector panic: boom") {
		t.Fatalf("errors %q", h.Errors)
	}
}

// fillNonZero gives every field reachable from v a non-zero value.
func fillNonZero(t *testing.T, v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fillNonZero(t, v.Field(i))
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillNonZero(t, v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillNonZero(t, v.Index(0))
	case reflect.Map:
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fillNonZero(t, k)
		fillNonZero(t, e)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(k, e)
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	default:
		t.Fatalf("no filler for %s", v.Type())
	}
}

// A section added to Health (or HPower) must also be taken over by merge,
// or every report drops it.
func TestHealthMergeTakesEveryField(t *testing.T) {
	var src, dst Health
	stamps := map[string]bool{"V": true, "TS": true, "MS": true}
	sv := reflect.ValueOf(&src).Elem()
	for i := 0; i < sv.NumField(); i++ {
		if !stamps[sv.Type().Field(i).Name] {
			fillNonZero(t, sv.Field(i))
		}
	}
	dst.merge(&src)
	dv := reflect.ValueOf(dst)
	for i := 0; i < sv.NumField(); i++ {
		f := sv.Type().Field(i)
		if !stamps[f.Name] && !reflect.DeepEqual(dv.Field(i).Interface(), sv.Field(i).Interface()) {
			t.Errorf("merge drops %s: got %+v, want %+v", f.Name, dv.Field(i).Interface(), sv.Field(i).Interface())
		}
	}
}

func TestForEachParallel(t *testing.T) {
	var running, peak atomic.Int32
	got := make([]int, 20)
	forEachParallel(len(got), smartctlWorkers, func(i int) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		got[i] = i * i
		running.Add(-1)
	})
	for i, v := range got {
		if v != i*i {
			t.Fatalf("slot %d holds %d", i, v)
		}
	}
	if p := peak.Load(); p > smartctlWorkers {
		t.Fatalf("%d at once", p)
	}
	forEachParallel(0, smartctlWorkers, func(int) { t.Fatal("called for no work") })
}

// A panic on a worker reaches the caller after every index was handed out,
// and through runHealth costs only its own stage.
func TestForEachParallelPanic(t *testing.T) {
	var calls atomic.Int32
	got := func() (p interface{}) {
		defer func() { p = recover() }()
		forEachParallel(20, smartctlWorkers, func(i int) {
			calls.Add(1)
			if i == 3 {
				panic("disk 3")
			}
		})
		return nil
	}()
	if got != "disk 3" || calls.Load() != 20 {
		t.Fatalf("panic %v after %d calls", got, calls.Load())
	}

	h := runHealth([]healthStage{
		func(_ context.Context, h *Health) { h.AV = []HAV{{Name: "ClamAV"}} },
		func(_ context.Context, h *Health) {
			h.Disks = []HDisk{{Name: "lost"}}
			forEachParallel(8, smartctlWorkers, func(i int) {
				if i == 5 {
					panic("disk 5")
				}
			})
		},
		func(_ context.Context, h *Health) { h.Temps = []HTemp{{Name: "cpu"}} },
	}, time.Minute)
	if len(h.AV) != 1 || len(h.Temps) != 1 || h.Disks != nil {
		t.Fatalf("%+v", h)
	}
	if len(h.Errors) != 1 || h.Errors[0] != "collector panic: disk 5" {
		t.Fatalf("errors %q", h.Errors)
	}
}
