// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
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
	b[0] = 0x04
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
