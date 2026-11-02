// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"math"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	gnet "github.com/shirou/gopsutil/v3/net"
)

func stateFixture(t *testing.T, name string) string {
	t.Helper()
	return fixture(t, filepath.Join("state", name))
}

func TestStateIntervalDefault(t *testing.T) {
	inRange(t, "state", sanitizeIntervals(AgentCheckInConfig{}).State, 270, 330)
	if c := sanitizeIntervals(AgentCheckInConfig{State: 600}); c.State != 600 {
		t.Fatalf("server value lost: %d", c.State)
	}
	var c AgentCheckInConfig
	json.Unmarshal([]byte(`{"checkin_state": 120}`), &c)
	if c.State != 120 {
		t.Fatalf("checkin_state not decoded: %+v", c)
	}
}

func TestParseMountinfo(t *testing.T) {
	ms := parseMountinfo(stateFixture(t, "mountinfo.txt"))
	var got []string
	for _, m := range ms {
		got = append(got, m.Mount+"|"+m.FS+"|"+m.Device)
	}
	want := []string{
		"/|ext4|/dev/sda2",
		"/boot/efi|vfat|/dev/sda1",
		"/srv/archive|xfs|/dev/sdb1",
		"/mnt/nas|nfs4|nas.example.lan:/export/backup",
		"/mnt/share one|cifs|//files.example.lan/share",
		"/home|btrfs|/dev/sdc1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts\n got %q\nwant %q", got, want)
	}
	if ms[0].RO || !ms[2].RO {
		t.Fatalf("ro flags: %+v", ms)
	}
}

func TestStatMountsStale(t *testing.T) {
	stateMem.Lock()
	stateMem.stale = map[string]time.Time{"/hung": time.Now().Add(time.Minute)}
	stateMem.Unlock()
	dir := t.TempDir()
	ms := statMounts([]SMount{{Mount: dir}, {Mount: "/hung"}, {Mount: filepath.Join(dir, "missing")}})
	if ms[0].Stale || ms[0].Size == nil || ms[0].UsedPct == nil {
		t.Fatalf("temp dir: %+v", ms[0])
	}
	if !ms[1].Stale || ms[1].Size != nil {
		t.Fatalf("skipped mount must stay stale without numbers: %+v", ms[1])
	}
	if ms[2].Stale || ms[2].Size != nil {
		t.Fatalf("a failing statfs is not stale: %+v", ms[2])
	}
	stateMem.Lock()
	stateMem.stale = nil
	stateMem.Unlock()
}

func TestParseMdstat(t *testing.T) {
	type row struct {
		name, level, state, health string
		devs, failed               int
		sync                       float64
	}
	flat := func(rs []SRaid) []row {
		var ret []row
		for _, r := range rs {
			x := row{r.Name, r.Level, r.State, r.Health, *r.Devices, *r.Failed, -1}
			if r.SyncPct != nil {
				x.sync = *r.SyncPct
			}
			ret = append(ret, x)
		}
		return ret
	}
	cases := map[string][]row{
		"mdstat_clean.txt": {{"md0", "raid1", "active", "ok", 2, 0, -1}},
		"mdstat_degraded.txt": {
			{"md1", "raid5", "active", "degraded", 3, 1, -1},
			{"md2", "", "inactive", "failed", 1, 0, -1},
		},
		"mdstat_resync.txt": {
			{"md3", "raid1", "resync", "ok", 2, 0, 27.4},
			{"md4", "raid1", "recovery", "degraded", 2, 1, 3.1},
		},
	}
	for f, want := range cases {
		if got := flat(parseMdstat(stateFixture(t, f))); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s\n got %+v\nwant %+v", f, got, want)
		}
	}
	if parseMdstat("Personalities : \nunused devices: <none>\n") != nil {
		t.Fatal("no arrays must give nothing")
	}
}

func TestParseZpoolStorcli(t *testing.T) {
	z := parseZpool(stateFixture(t, "zpool_list.txt"))
	if len(z) != 3 || z[0].Health != "ok" || z[1].Health != "degraded" || z[2].Health != "failed" || z[1].State != "degraded" {
		t.Fatalf("zpool: %+v", z)
	}
	s, err := parseStorcli([]byte(stateFixture(t, "storcli_vall.json")))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range s {
		got = append(got, r.Name+"|"+r.Level+"|"+r.State+"|"+r.Health)
	}
	want := []string{"c0/v0 system|raid1|Optl|ok", "c0/v1 data|raid6|Dgrd|degraded", "c1/v0|raid10|OfLn|failed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("storcli\n got %q\nwant %q", got, want)
	}
	if _, err := parseStorcli([]byte("not json")); err == nil {
		t.Fatal("bad JSON accepted")
	}
}

func TestParseIpmiSdr(t *testing.T) {
	s := parseIpmiSdr(stateFixture(t, "ipmitool_sdr.csv"))
	var got []string
	for _, x := range s {
		got = append(got, x.Kind+"|"+x.Name+"|"+x.Unit+"|"+x.Status)
	}
	want := []string{"temp|CPU1 Temp|C|ok", "temp|CPU2 Temp|C|cr", "fan|System Fan 1|rpm|ok", "volt|12V|V|ok"}
	if !reflect.DeepEqual(got, want) || s[1].Value != 88 || s[3].Value != 12.19 || s[0].Source != "ipmi" {
		t.Fatalf("ipmi\n got %q %+v\nwant %q", got, s, want)
	}
}

func TestParseTimeSources(t *testing.T) {
	c, ok := parseChronyTracking(stateFixture(t, "chronyc_tracking.csv"))
	if !ok || c.Source != "chrony" || c.Server != "ntp1.example.lan" || !*c.Synced || math.Abs(*c.OffsetMs+0.231456) > 1e-9 {
		t.Fatalf("chrony: %+v", c)
	}
	c, ok = parseChronyTracking(stateFixture(t, "chronyc_tracking_unsynced.csv"))
	if !ok || *c.Synced {
		t.Fatalf("chrony unsynced: %+v", c)
	}
	if _, ok := parseChronyTracking("506 Cannot talk to daemon"); ok {
		t.Fatal("error text parsed")
	}
	ts, ok := parseTimesync(stateFixture(t, "timedatectl_show_timesync.txt"), stateFixture(t, "timedatectl_timesync_status.txt"))
	if !ok || ts.Source != "timesyncd" || ts.Server != "1.pool.example.org" || ts.OffsetMs == nil || *ts.OffsetMs != -1.523 {
		t.Fatalf("timesyncd: %+v", ts)
	}
	if _, ok := parseTimesync("FallbackNTPServers=x\n", ""); ok {
		t.Fatal("no server must fall back to the kernel")
	}
	for in, want := range map[string]float64{"+194us": 0.194, "-2.5ms": -2.5, "1.2s": 1200, "800ns": 0.0008} {
		if got := parseDurMs(in); got == nil || math.Abs(*got-want) > 1e-9 {
			t.Fatalf("%s: %v", in, got)
		}
	}
	if parseDurMs("n/a") != nil {
		t.Fatal("garbage parsed")
	}
}

func TestCPUBusyAndTop(t *testing.T) {
	a := cpu.TimesStat{User: 100, System: 50, Idle: 800, Iowait: 50}
	b := cpu.TimesStat{User: 130, System: 60, Idle: 850, Iowait: 60}
	if p := cpuBusy(a, b); p == nil || math.Abs(*p-40) > 1e-9 {
		t.Fatalf("busy: %v", p)
	}
	if cpuBusy(b, a) != nil || cpuBusy(a, a) != nil {
		t.Fatal("no time passed or counters went back: no value")
	}
	out := "Processes: 500 total\nCPU usage: 3.10% user, 5.0% sys, 91.90% idle\n\nProcesses: 501 total\nCPU usage: 12.50% user, 7.50% sys, 80.0% idle\n"
	if p := parseTopCPU(out); p == nil || math.Abs(*p-20) > 1e-9 {
		t.Fatalf("top: %v", p)
	}
	if parseTopCPU("nothing") != nil {
		t.Fatal("garbage parsed")
	}
}

func TestApplyRates(t *testing.T) {
	cur := []SIface{
		{Name: "eth0", RxBytes: 3000, TxBytes: 1500, RxPackets: 30, TxPackets: 15, RxErrors: 2, TxErrors: 1, RxDrops: 4},
		{Name: "eth1", RxBytes: 10},
		{Name: "new0", RxBytes: 1},
	}
	prev := map[string]SIface{
		"eth0": {Name: "eth0", RxBytes: 1000, TxBytes: 500, RxPackets: 10, TxPackets: 5},
		"eth1": {Name: "eth1", RxBytes: 99999}, // counter reset
	}
	// first push: nothing to compare with
	first := append([]SIface(nil), cur...)
	applyRates(first, nil, 0)
	for _, f := range first {
		if f.Rate != nil {
			t.Fatalf("first push has a rate: %+v", f)
		}
	}
	zero := append([]SIface(nil), cur...)
	applyRates(zero, prev, 0)
	if zero[0].Rate != nil {
		t.Fatal("dt 0 gave a rate")
	}
	applyRates(cur, prev, 10)
	want := SRate{RxBps: 200, TxBps: 100, RxPps: 2, TxPps: 1, ErrPs: 0.3, DropPs: 0.4}
	if cur[0].Rate == nil || *cur[0].Rate != want {
		t.Fatalf("eth0 rate %+v", cur[0].Rate)
	}
	if cur[1].Rate != nil || cur[2].Rate != nil {
		t.Fatalf("reset or new nic got a rate: %+v %+v", cur[1].Rate, cur[2].Rate)
	}
}

func TestJoinAdapters(t *testing.T) {
	ads := []winAdapter{
		{Name: "Ethernet", Speed: 1000000000, FullDuplex: true, MediaConnectState: 1, NdisPhysicalMedium: 14, MtuSize: 1500, PermanentAddress: "001122334455"},
		{Name: "WLAN", Speed: 9223372036854775807, MediaConnectState: 2, NdisPhysicalMedium: 9, PermanentAddress: "A0B1C2D3E4F5"},
	}
	ctr := map[string]gnet.IOCountersStat{"Ethernet": {Name: "Ethernet", BytesRecv: 10, BytesSent: 20, Errin: 1, Dropout: 2}}
	list := []gnet.InterfaceStat{{Name: "Ethernet", HardwareAddr: "00:11:22:33:44:66", Addrs: gnet.InterfaceAddrList{{Addr: "192.0.2.5/24"}}}}
	got := joinAdapters(ads, ctr, list)
	e, w := got[0], got[1]
	if e.Kind != "ether" || e.State != "up" || *e.SpeedMbps != 1000 || *e.Duplex != "full" || e.MAC != "00:11:22:33:44:66" ||
		e.RxBytes != 10 || e.TxBytes != 20 || e.RxErrors != 1 || e.TxDrops != 2 || *e.MTU != 1500 || e.Addrs[0] != "192.0.2.5/24" {
		t.Fatalf("ethernet %+v", e)
	}
	if w.Kind != "wifi" || w.State != "down" || w.SpeedMbps != nil || w.Duplex != nil || w.MAC != "a0:b1:c2:d3:e4:f5" {
		t.Fatalf("wlan %+v", w)
	}
}

func TestSclip(t *testing.T) {
	if got := sclip(" a\x00b\x1bcä\n ", 64); got != "abcä" {
		t.Fatalf("%q", got)
	}
	if got := sclip("ääää", 3); got != "ä" {
		t.Fatalf("cut inside a rune: %q", got)
	}
	if got := sclip("ok\xff", 8); got != "ok" {
		t.Fatalf("invalid utf-8 kept: %q", got)
	}
}

func maxState() *State {
	long := func(n int) string { return strings.Repeat("x", n+20) }
	f := ptr(1.5)
	s := &State{V: 1, Errors: []string{}, Perf: &SPerf{CPUPct: ptr(math.NaN()), SwapPct: ptr(250.0), Load: []float64{1, 2, 3}}}
	y := &SSystem{Manager: "systemd", Time: &STime{Source: "chrony", Server: long(255), OffsetMs: ptr(math.Inf(1))}}
	for i := 0; i < 200; i++ {
		y.Units = append(y.Units, SUnit{Name: long(255), Active: long(24), Sub: long(24), Enabled: ptr(true), Description: long(128)})
		y.Mounts = append(y.Mounts, SMount{Mount: long(255), Device: long(255), FS: long(32), Size: ptr(int64(1)), Used: ptr(int64(1)), UsedPct: f, InodePct: f})
		y.RAID = append(y.RAID, SRaid{Kind: "md", Name: long(64), Level: long(32), State: long(32), Health: "ok", Devices: ptr(1), Failed: ptr(0), SyncPct: f})
		y.Sensors = append(y.Sensors, SSensor{Kind: "temp", Source: "hwmon", Name: long(64), Value: 40, Unit: "C", Warn: f, Crit: f, Status: long(16)})
	}
	y.Sensors = append([]SSensor{{Kind: "temp", Name: "bogus", Value: 65261}}, y.Sensors...)
	s.System = y
	n := &SNet{}
	for i := 0; i < 64; i++ {
		x := SIface{Name: long(64), Kind: "ether", State: "up", SpeedMbps: ptr(1000), Duplex: ptr("full"), MAC: long(32), MTU: ptr(1500), Master: ptr(long(64)),
			Rate: &SRate{RxBps: 1, TxBps: 1, RxPps: 1, TxPps: 1, ErrPs: 1, DropPs: 1}}
		for k := 0; k < 40; k++ {
			x.Addrs = append(x.Addrs, long(64))
			x.Members = append(x.Members, long(64))
		}
		n.Ifaces = append(n.Ifaces, x)
	}
	s.Net = n
	c := &SContainers{Sources: map[string]string{"docker": "ok", "pve-qemu": "ok"}, Cluster: &SCluster{Name: long(64)}}
	for i := 0; i < 300; i++ {
		c.Items = append(c.Items, SContainer{Kind: "docker", ID: long(64), Name: long(128), Image: long(255), State: "running", Status: long(128),
			Restarts: ptr(1), CPUPct: f, MemUsed: ptr(int64(1)), MemLimit: ptr(int64(1)), NetRx: ptr(int64(1)), NetTx: ptr(int64(1)), Uptime: ptr(int64(1)), Node: ptr(long(64))})
	}
	s.Containers = c
	return s
}

func TestStateCapsAndSize(t *testing.T) {
	s := maxState()
	s.capAll()
	y := s.System
	if len(y.Units) != 128 || len(y.Mounts) != 32 || len(y.RAID) != 32 || len(y.Sensors) != 64 || len(s.Net.Ifaces) != 32 || len(s.Containers.Items) != 128 {
		t.Fatalf("list caps: units %d mounts %d raid %d sensors %d ifaces %d items %d", len(y.Units), len(y.Mounts), len(y.RAID), len(y.Sensors), len(s.Net.Ifaces), len(s.Containers.Items))
	}
	if y.Sensors[0].Name == "bogus" || len(y.Units[0].Name) != 255 || len(y.Units[0].Description) != 128 || len(s.Net.Ifaces[0].Addrs) != 16 ||
		len(s.Net.Ifaces[0].Members) != 32 || len(s.Containers.Items[0].Image) != 255 || len(*s.Containers.Items[0].Node) != 64 {
		t.Fatal("string or item caps not applied")
	}
	if s.Perf.CPUPct != nil || *s.Perf.SwapPct != 100 || y.Time.OffsetMs != nil {
		t.Fatalf("float rules: %+v %+v", s.Perf, y.Time)
	}
	b, err := encodeState(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > stateMaxBody {
		t.Fatalf("body %d bytes", len(b))
	}
	if s.Errors[len(s.Errors)-1] != "state trimmed to fit" {
		t.Fatalf("trim not reported: %v", s.Errors)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}

	small := &State{V: 1, Errors: []string{}, Net: &SNet{Ifaces: []SIface{{Name: "eth0"}}}}
	b, _ = encodeState(small)
	if strings.Contains(string(b), "trimmed") || !strings.Contains(string(b), `"dt":null`) || !strings.Contains(string(b), `"rate":null`) {
		t.Fatalf("small state: %s", b)
	}
	if strings.Contains(string(b), "perf") || strings.Contains(string(b), "speed_mbps") {
		t.Fatalf("unknown keys must be left out: %s", b)
	}
}

func TestStateBackoff(t *testing.T) {
	calls, status := 0, http.StatusNotFound
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/agent1/state/" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s %v", r.Method, r.URL.Path, r.Header)
		}
		w.WriteHeader(status)
	})
	defer func() {
		stateMem.Lock()
		stateMem.backoff = time.Time{}
		stateMem.Unlock()
	}()
	a.postState([]byte(`{"v":1}`))
	stateMem.Lock()
	until := stateMem.backoff
	stateMem.Unlock()
	if d := time.Until(until); d < stateBackoff-time.Minute || d > stateBackoff {
		t.Fatalf("404 must back off 6 h, got %v", d)
	}
	a.SendState(false)
	if calls != 1 {
		t.Fatalf("pushed during the back-off: %d calls", calls)
	}

	stateMem.Lock()
	stateMem.backoff = time.Time{}
	stateMem.Unlock()
	status = http.StatusInternalServerError
	a.postState([]byte(`{"v":1}`))
	stateMem.Lock()
	until = stateMem.backoff
	stateMem.Unlock()
	if !until.IsZero() {
		t.Fatal("a 500 must not back off")
	}
}

// collects on whatever host runs the tests; -v prints the document
func TestCollectStateLive(t *testing.T) {
	s := collectState(true)
	b, err := encodeState(s)
	if err != nil {
		t.Fatal(err)
	}
	if s.V != 1 || s.Errors == nil || s.Perf == nil || s.Net == nil || s.System == nil || len(b) > stateMaxBody {
		t.Fatalf("state %s", b)
	}
	time.Sleep(2 * time.Second)
	again := collectState(true)
	if again.DT == nil || *again.DT <= 0 {
		t.Fatalf("second push without dt: %v", again.DT)
	}
	if testing.Verbose() {
		b, _ = encodeState(again)
		t.Logf("%s", b)
	}
}
