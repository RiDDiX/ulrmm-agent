// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
)

// POST /api/v3/<agent>/state/ every checkin_state seconds from the service.
// A key the agent cannot fill is left out; the server caps everything again.
type State struct {
	V          int          `json:"v"`
	TS         int64        `json:"ts"`
	DT         *float64     `json:"dt"`
	Errors     []string     `json:"errors"`
	Perf       *SPerf       `json:"perf,omitempty"`
	System     *SSystem     `json:"system,omitempty"`
	Net        *SNet        `json:"net,omitempty"`
	Containers *SContainers `json:"containers,omitempty"`
}

type SPerf struct {
	CPUPct   *float64  `json:"cpu_pct,omitempty"`
	MemTotal *int64    `json:"mem_total,omitempty"`
	MemUsed  *int64    `json:"mem_used,omitempty"`
	SwapPct  *float64  `json:"swap_pct,omitempty"`
	Load     []float64 `json:"load,omitempty"`
}

type SSystem struct {
	Manager     string    `json:"manager"`
	UnitsTotal  *int      `json:"units_total,omitempty"`
	UnitsFailed *int      `json:"units_failed,omitempty"`
	Units       []SUnit   `json:"units,omitempty"`
	Mounts      []SMount  `json:"mounts,omitempty"`
	Time        *STime    `json:"time,omitempty"`
	RAID        []SRaid   `json:"raid,omitempty"`
	Sensors     []SSensor `json:"sensors,omitempty"`
}

type SUnit struct {
	Name        string `json:"name"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Enabled     *bool  `json:"enabled"`
	Description string `json:"description,omitempty"`
}

type SMount struct {
	Mount    string   `json:"mount"`
	Device   string   `json:"device"`
	FS       string   `json:"fs"`
	RO       bool     `json:"ro"`
	Stale    bool     `json:"stale"`
	Size     *int64   `json:"size,omitempty"`
	Used     *int64   `json:"used,omitempty"`
	UsedPct  *float64 `json:"used_pct,omitempty"`
	InodePct *float64 `json:"inode_pct"`
	key      string   // device and root inside it, for bind mounts
}

type STime struct {
	Synced   *bool    `json:"synced"`
	Source   string   `json:"source"`
	Server   string   `json:"server,omitempty"`
	OffsetMs *float64 `json:"offset_ms"`
}

type SRaid struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	Level   string   `json:"level,omitempty"`
	State   string   `json:"state"`
	Health  string   `json:"health"`
	Devices *int     `json:"devices"`
	Failed  *int     `json:"failed"`
	SyncPct *float64 `json:"sync_pct"`
}

type SSensor struct {
	Kind   string   `json:"kind"`
	Source string   `json:"source"`
	Name   string   `json:"name"`
	Value  float64  `json:"value"`
	Unit   string   `json:"unit"`
	Warn   *float64 `json:"warn"`
	Crit   *float64 `json:"crit"`
	Status string   `json:"status,omitempty"`
}

type SNet struct {
	Ifaces []SIface `json:"ifaces"`
}

// speed and duplex are left out when unknown (always on macOS)
type SIface struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	State     string   `json:"state"`
	SpeedMbps *int     `json:"speed_mbps,omitempty"`
	Duplex    *string  `json:"duplex,omitempty"`
	MAC       string   `json:"mac"`
	MTU       *int     `json:"mtu"`
	Addrs     []string `json:"addrs,omitempty"`
	Master    *string  `json:"master"`
	Members   []string `json:"members,omitempty"`
	RxBytes   int64    `json:"rx_bytes"`
	TxBytes   int64    `json:"tx_bytes"`
	RxPackets int64    `json:"rx_packets"`
	TxPackets int64    `json:"tx_packets"`
	RxErrors  int64    `json:"rx_errors"`
	TxErrors  int64    `json:"tx_errors"`
	RxDrops   int64    `json:"rx_drops"`
	TxDrops   int64    `json:"tx_drops"`
	Rate      *SRate   `json:"rate"`
}

type SRate struct {
	RxBps  float64 `json:"rx_bps"`
	TxBps  float64 `json:"tx_bps"`
	RxPps  float64 `json:"rx_pps"`
	TxPps  float64 `json:"tx_pps"`
	ErrPs  float64 `json:"err_ps"`
	DropPs float64 `json:"drop_ps"`
}

type SContainers struct {
	Sources map[string]string `json:"sources"`
	Items   []SContainer      `json:"items"`
	Cluster *SCluster         `json:"cluster"`
	// engine error text for the container check, not sent
	msgs map[string]string
}

type SContainer struct {
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Image    string   `json:"image,omitempty"`
	State    string   `json:"state"`
	Status   string   `json:"status,omitempty"`
	Restarts *int     `json:"restarts"`
	CPUPct   *float64 `json:"cpu_pct"`
	MemUsed  *int64   `json:"mem_used"`
	MemLimit *int64   `json:"mem_limit"`
	NetRx    *int64   `json:"net_rx"`
	NetTx    *int64   `json:"net_tx"`
	Uptime   *int64   `json:"uptime"`
	Node     *string  `json:"node"`
}

type SCluster struct {
	Name    string `json:"name"`
	Quorate bool   `json:"quorate"`
	Nodes   int    `json:"nodes"`
	Online  int    `json:"online"`
}

const (
	stateDeadline = 45 * time.Second
	stateMaxBody  = 256 << 10
	stateBackoff  = 6 * time.Hour
	staleSkip     = 30 * time.Minute
	statfsWait    = 2 * time.Second
)

// what the next push needs from this one; lives as long as the service process
var stateMem struct {
	sync.Mutex
	at      time.Time
	cpu     *cpu.TimesStat
	nics    map[string]SIface
	nicsAt  time.Time
	stale   map[string]time.Time
	backoff time.Time
}

type errs []string

func (e *errs) add(format string, args ...interface{}) {
	if len(*e) < 16 {
		*e = append(*e, sclip(fmt.Sprintf(format, args...), 128))
	}
}

// valid UTF-8 without control characters, cut to n bytes on a rune boundary
func sclip(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "")))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func i64(u uint64) int64 {
	if u > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(u)
}

func (a *Agent) SendState(stats bool) {
	stateMem.Lock()
	off := time.Now().Before(stateMem.backoff)
	stateMem.Unlock()
	if off {
		return
	}
	b, err := encodeState(collectState(stats))
	if err != nil {
		a.Logger.Debugln("SendState():", err)
		return
	}
	a.postState(b)
}

func (a *Agent) postState(b []byte) {
	r, err := a.rClient.R().SetHeader("Content-Type", "application/json").SetBody(b).Post(fmt.Sprintf("/api/v3/%s/state/", a.AgentID))
	if err != nil {
		a.Logger.Debugln("SendState():", err)
		return
	}
	if r.StatusCode() == http.StatusNotFound {
		// server without the endpoint
		stateMem.Lock()
		stateMem.backoff = time.Now().Add(stateBackoff)
		stateMem.Unlock()
	}
	if r.IsError() {
		a.Logger.Debugln("SendState(): server answered", r.StatusCode())
	}
}

// Sections run side by side under one deadline; one that overruns is
// reported in errors and left out, its commands die with the context.
func collectState(stats bool) *State {
	now := time.Now()
	s := &State{V: 1, TS: now.Unix(), Errors: []string{}}
	stateMem.Lock()
	if !stateMem.at.IsZero() {
		s.DT = ptr(now.Sub(stateMem.at).Seconds())
	}
	stateMem.at = now
	stateMem.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), stateDeadline)
	defer cancel()
	type done struct {
		name string
		set  func(*State)
		e    errs
	}
	ch := make(chan done, 4)
	start := func(name string, fn func(context.Context, *errs) func(*State)) {
		go func() {
			var e errs
			defer func() {
				if r := recover(); r != nil {
					e.add("collector panic: %s: %v", name, r)
					ch <- done{name, nil, e}
				}
			}()
			set := fn(ctx, &e)
			ch <- done{name, set, e}
		}()
	}
	start("perf", func(ctx context.Context, e *errs) func(*State) {
		p := perfSection(ctx, e)
		return func(s *State) { s.Perf = p }
	})
	start("system", func(ctx context.Context, e *errs) func(*State) {
		sys := osSystem(ctx, e)
		return func(s *State) { s.System = sys }
	})
	start("net", func(ctx context.Context, e *errs) func(*State) {
		n := netSection(ctx, e)
		return func(s *State) { s.Net = n }
	})
	start("containers", func(ctx context.Context, e *errs) func(*State) {
		c := collectContainers(ctx, stats)
		for k, m := range c.msgs {
			e.add("%s: %s", k, m)
		}
		if len(c.Sources) == 0 {
			c = nil
		}
		return func(s *State) { s.Containers = c }
	})

	pending := map[string]bool{"perf": true, "system": true, "net": true, "containers": true}
	for len(pending) > 0 {
		select {
		case d := <-ch:
			delete(pending, d.name)
			if d.set != nil {
				d.set(s)
			}
			for _, m := range d.e {
				if len(s.Errors) < 16 {
					s.Errors = append(s.Errors, m)
				}
			}
		case <-ctx.Done():
			names := make([]string, 0, len(pending))
			for n := range pending {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if len(s.Errors) < 16 {
					s.Errors = append(s.Errors, n+": timed out")
				}
			}
			pending = nil
		}
	}
	s.capAll()
	return s
}

func perfSection(ctx context.Context, e *errs) *SPerf {
	p := &SPerf{}
	if c, err := osCPUPct(ctx); err != nil {
		e.add("cpu: %v", err)
	} else {
		p.CPUPct = c
	}
	// the memory check's numbers
	if total, used, err := memTotalUsed(); err == nil {
		p.MemTotal, p.MemUsed = ptr(i64(total)), ptr(i64(used))
	} else {
		e.add("memory: %v", err)
	}
	if sw, err := mem.SwapMemory(); err == nil && sw.Total > 0 {
		p.SwapPct = ptr(sw.UsedPercent)
	}
	if runtime.GOOS != "windows" {
		if l, err := load.Avg(); err == nil {
			p.Load = []float64{l.Load1, l.Load5, l.Load15}
		}
	}
	return p
}

// busy share since the previous push, the first one samples 1 s
func timesCPUPct(ctx context.Context) (*float64, error) {
	read := func() (*cpu.TimesStat, error) {
		t, err := cpu.TimesWithContext(ctx, false)
		if err != nil || len(t) == 0 {
			return nil, fmt.Errorf("cpu times: %v", err)
		}
		return &t[0], nil
	}
	cur, err := read()
	if err != nil {
		return nil, err
	}
	stateMem.Lock()
	prev := stateMem.cpu
	stateMem.cpu = cur
	stateMem.Unlock()
	if prev == nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
		prev = cur
		if cur, err = read(); err != nil {
			return nil, err
		}
		stateMem.Lock()
		stateMem.cpu = cur
		stateMem.Unlock()
	}
	return cpuBusy(*prev, *cur), nil
}

func cpuBusy(a, b cpu.TimesStat) *float64 {
	tot := func(t cpu.TimesStat) float64 {
		return t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
	}
	all := tot(b) - tot(a)
	idle := (b.Idle + b.Iowait) - (a.Idle + a.Iowait)
	if all <= 0 || idle < 0 || idle > all {
		return nil
	}
	return ptr((all - idle) / all * 100)
}

var topCPURe = regexp.MustCompile(`CPU usage:.*?([0-9.]+)% idle`)

// macOS `top -l 2 -n 0 -s 1`: the second sample covers the last second
func parseTopCPU(out string) *float64 {
	m := topCPURe.FindAllStringSubmatch(out, -1)
	if len(m) == 0 {
		return nil
	}
	idle, err := strconv.ParseFloat(m[len(m)-1][1], 64)
	if err != nil || idle < 0 || idle > 100 {
		return nil
	}
	return ptr(100 - idle)
}

func netSection(ctx context.Context, e *errs) *SNet {
	ifs := osIfaces(ctx, e)
	now := time.Now()
	stateMem.Lock()
	prev, dt := stateMem.nics, now.Sub(stateMem.nicsAt).Seconds()
	stateMem.nics, stateMem.nicsAt = map[string]SIface{}, now
	for _, i := range ifs {
		stateMem.nics[i.Name] = i
	}
	stateMem.Unlock()
	applyRates(ifs, prev, dt)
	if ifs == nil {
		ifs = []SIface{}
	}
	return &SNet{Ifaces: ifs}
}

// (cur-prev)/dt; no rate on the first push, after a counter reset or dt <= 0
func applyRates(ifs []SIface, prev map[string]SIface, dt float64) {
	for i := range ifs {
		p, ok := prev[ifs[i].Name]
		if !ok || dt <= 0 {
			continue
		}
		c := ifs[i]
		cur := []int64{c.RxBytes, c.TxBytes, c.RxPackets, c.TxPackets, c.RxErrors + c.TxErrors, c.RxDrops + c.TxDrops}
		old := []int64{p.RxBytes, p.TxBytes, p.RxPackets, p.TxPackets, p.RxErrors + p.TxErrors, p.RxDrops + p.TxDrops}
		r := make([]float64, len(cur))
		ok = true
		for k := range cur {
			if cur[k] < old[k] {
				ok = false
				break
			}
			r[k] = float64(cur[k]-old[k]) / dt
		}
		if ok {
			ifs[i].Rate = &SRate{RxBps: r[0], TxBps: r[1], RxPps: r[2], TxPps: r[3], ErrPs: r[4], DropPs: r[5]}
		}
	}
}

// gopsutil interfaces and counters (macOS, Windows without WMI)
func psIfaces(ctx context.Context, keep func(gnet.InterfaceStat) bool, e *errs) []SIface {
	list, err := gnet.InterfacesWithContext(ctx)
	if err != nil {
		e.add("interfaces: %v", err)
		return nil
	}
	ctr := ioCounters(ctx, e)
	var ret []SIface
	for _, i := range list {
		if !keep(i) {
			continue
		}
		f := SIface{Name: i.Name, Kind: "ether", State: "down", MAC: i.HardwareAddr, Addrs: ifAddrs(i)}
		if strings.HasPrefix(i.Name, "bridge") {
			f.Kind = "bridge"
		}
		for _, fl := range i.Flags {
			if fl == "up" {
				f.State = "up"
			}
		}
		if i.MTU > 0 {
			f.MTU = ptr(i.MTU)
		}
		setCounters(&f, ctr[i.Name])
		ret = append(ret, f)
	}
	return ret
}

func ioCounters(ctx context.Context, e *errs) map[string]gnet.IOCountersStat {
	m := map[string]gnet.IOCountersStat{}
	l, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		e.add("interface counters: %v", err)
	}
	for _, c := range l {
		m[c.Name] = c
	}
	return m
}

func ifAddrs(i gnet.InterfaceStat) []string {
	var ret []string
	for _, a := range i.Addrs {
		ret = append(ret, a.Addr)
	}
	return ret
}

func setCounters(f *SIface, c gnet.IOCountersStat) {
	f.RxBytes, f.TxBytes = i64(c.BytesRecv), i64(c.BytesSent)
	f.RxPackets, f.TxPackets = i64(c.PacketsRecv), i64(c.PacketsSent)
	f.RxErrors, f.TxErrors = i64(c.Errin), i64(c.Errout)
	f.RxDrops, f.TxDrops = i64(c.Dropin), i64(c.Dropout)
}

// MSFT_NetAdapter in root\StandardCimv2
type winAdapter struct {
	Name               string
	Speed              uint64
	FullDuplex         bool
	MediaConnectState  uint32
	PermanentAddress   string
	NdisPhysicalMedium uint32
	MtuSize            uint32
}

// adapters joined with counters and addresses on the name, like wolStates
func joinAdapters(ads []winAdapter, ctr map[string]gnet.IOCountersStat, list []gnet.InterfaceStat) []SIface {
	byName := map[string]gnet.InterfaceStat{}
	for _, i := range list {
		byName[i.Name] = i
	}
	var ret []SIface
	for _, a := range ads {
		f := SIface{Name: a.Name, Kind: "other", State: "unknown"}
		switch a.NdisPhysicalMedium {
		case 1, 9: // wireless LAN, native 802.11
			f.Kind = "wifi"
		case 14: // 802.3
			f.Kind = "ether"
		}
		switch a.MediaConnectState {
		case 1:
			f.State = "up"
		case 2:
			f.State = "down"
		}
		if f.State == "up" && a.Speed > 0 && a.Speed < math.MaxInt64 {
			f.SpeedMbps = ptr(int(a.Speed / 1000000))
			f.Duplex = ptr("half")
			if a.FullDuplex {
				f.Duplex = ptr("full")
			}
		}
		if i, ok := byName[a.Name]; ok {
			f.MAC, f.Addrs = i.HardwareAddr, ifAddrs(i)
		}
		if f.MAC == "" && len(a.PermanentAddress) == 12 {
			p := strings.ToLower(a.PermanentAddress)
			f.MAC = strings.Join([]string{p[0:2], p[2:4], p[4:6], p[6:8], p[8:10], p[10:12]}, ":")
		}
		if a.MtuSize > 0 {
			f.MTU = ptr(int(a.MtuSize))
		}
		setCounters(&f, ctr[a.Name])
		ret = append(ret, f)
	}
	return ret
}

var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "tmpfs": true, "devtmpfs": true, "devpts": true,
	"overlay": true, "aufs": true, "squashfs": true, "nsfs": true, "tracefs": true, "debugfs": true, "securityfs": true,
	"pstore": true, "bpf": true, "autofs": true, "mqueue": true, "hugetlbfs": true, "configfs": true, "fusectl": true,
	"binfmt_misc": true, "rpc_pipefs": true, "efivarfs": true, "ramfs": true, "selinuxfs": true, "rootfs": true,
	"fuse.lxcfs": true, "fuse.gvfsd-fuse": true, "fuse.portal": true, "fuse.snapfuse": true, "devfs": true, "nullfs": true,
	"procfs": true, "fdescfs": true, "linprocfs": true, "linsysfs": true, "mqueuefs": true,
}

func skipMount(fs, mount string) bool {
	if pseudoFS[fs] || strings.HasPrefix(mount, "/proc/") || strings.HasPrefix(mount, "/sys/") {
		return true
	}
	// macOS: the system's helper volumes; / and Data are what users fill
	return strings.HasPrefix(mount, "/System/Volumes/") && mount != "/System/Volumes/Data"
}

// /proc/self/mountinfo: id parent maj:min root mount opts [optional...] - fstype source superopts
func parseMountinfo(out string) []SMount {
	var ret []SMount
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(f) {
			continue
		}
		m := SMount{Mount: unescapeMount(f[4]), FS: f[sep+1], Device: unescapeMount(f[sep+2]), key: f[2] + " " + f[3]}
		if skipMount(m.FS, m.Mount) || seen[m.key] {
			continue
		}
		seen[m.key] = true
		for _, o := range strings.Split(f[5], ",") {
			m.RO = m.RO || o == "ro"
		}
		ret = append(ret, m)
	}
	return ret
}

// mountinfo writes space, tab, newline and backslash as \ooo
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// gopsutil partitions (macOS, Windows)
func psMounts(ctx context.Context, e *errs) []SMount {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		e.add("mounts: %v", err)
	}
	var ret []SMount
	for _, p := range parts {
		if skipMount(p.Fstype, p.Mountpoint) {
			continue
		}
		m := SMount{Mount: p.Mountpoint, Device: p.Device, FS: p.Fstype}
		for _, o := range p.Opts {
			m.RO = m.RO || o == "ro"
		}
		ret = append(ret, m)
	}
	return ret
}

// statfs per mount in its own goroutine. One that has not answered within 2 s
// is stale and left alone for 30 min, so a hung server leaks one goroutine at most.
func statMounts(ms []SMount) []SMount {
	if len(ms) > 32 {
		ms = ms[:32]
	}
	type res struct {
		i int
		u *disk.UsageStat
	}
	ch := make(chan res, len(ms))
	now := time.Now()
	stateMem.Lock()
	if stateMem.stale == nil {
		stateMem.stale = map[string]time.Time{}
	}
	waiting := 0
	for i := range ms {
		if now.Before(stateMem.stale[ms[i].Mount]) {
			ms[i].Stale = true
			continue
		}
		waiting++
		go func(i int, path string) {
			u, err := disk.Usage(path)
			if err != nil {
				u = nil
			}
			ch <- res{i, u}
		}(i, ms[i].Mount)
	}
	stateMem.Unlock()

	answered := make([]bool, len(ms))
	timer := time.NewTimer(statfsWait)
	defer timer.Stop()
wait:
	for waiting > 0 {
		select {
		case r := <-ch:
			waiting--
			answered[r.i] = true
			if u := r.u; u != nil && u.Total > 0 {
				m := &ms[r.i]
				m.Size, m.Used, m.UsedPct = ptr(i64(u.Total)), ptr(i64(u.Used)), ptr(u.UsedPercent)
				if u.InodesTotal > 0 {
					m.InodePct = ptr(u.InodesUsedPercent)
				}
			}
		case <-timer.C:
			break wait
		}
	}
	stateMem.Lock()
	for i := range ms {
		if !answered[i] && !ms[i].Stale {
			ms[i].Stale = true
			stateMem.stale[ms[i].Mount] = now.Add(staleSkip)
		}
	}
	stateMem.Unlock()
	return ms
}

var (
	mdCountRe = regexp.MustCompile(`\[(\d+)/(\d+)\]`)
	mdSyncRe  = regexp.MustCompile(`(resync|recovery|reshape|check)\s*=\s*([0-9.]+)%`)
)

// /proc/mdstat
func parseMdstat(out string) []SRaid {
	var ret []SRaid
	var cur *SRaid
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == ":" && strings.HasPrefix(f[0], "md") {
			r := SRaid{Kind: "md", Name: f[0], State: f[2], Health: "ok"}
			devs, failed := 0, 0
			for _, t := range f[3:] {
				switch {
				case strings.HasPrefix(t, "("):
				case r.Level == "" && devs == 0 && !strings.Contains(t, "["):
					r.Level = t
				default:
					devs++
					if strings.Contains(t, "(F)") {
						failed++
					}
				}
			}
			r.Devices, r.Failed = ptr(devs), ptr(failed)
			if failed > 0 {
				r.Health = "degraded"
			}
			if r.State == "inactive" {
				r.Health = "failed"
			}
			ret = append(ret, r)
			cur = &ret[len(ret)-1]
			continue
		}
		if cur == nil {
			continue
		}
		if len(f) == 0 {
			cur = nil
			continue
		}
		if m := mdCountRe.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			act, _ := strconv.Atoi(m[2])
			cur.Devices = ptr(n)
			if n-act > *cur.Failed {
				cur.Failed = ptr(n - act)
			}
			if act < n && cur.Health == "ok" {
				cur.Health = "degraded"
			}
		}
		if m := mdSyncRe.FindStringSubmatch(line); m != nil {
			if p, err := strconv.ParseFloat(m[2], 64); err == nil {
				cur.SyncPct = ptr(p)
			}
			cur.State = m[1]
		}
	}
	return ret
}

// zpool list -H -o name,health,size,alloc
func parseZpool(out string) []SRaid {
	var ret []SRaid
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		h := "unknown"
		switch strings.ToUpper(f[1]) {
		case "ONLINE":
			h = "ok"
		case "DEGRADED":
			h = "degraded"
		case "FAULTED", "UNAVAIL", "REMOVED", "SUSPENDED":
			h = "failed"
		}
		ret = append(ret, SRaid{Kind: "zfs", Name: f[0], State: strings.ToLower(f[1]), Health: h})
	}
	return ret
}

// storcli64|perccli64 /call/vall show J
func parseStorcli(out []byte) ([]SRaid, error) {
	var v struct {
		Controllers []struct {
			Status struct {
				Controller int `json:"Controller"`
			} `json:"Command Status"`
			Data map[string]json.RawMessage `json:"Response Data"`
		} `json:"Controllers"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	var ret []SRaid
	for _, c := range v.Controllers {
		keys := make([]string, 0, len(c.Data))
		for k := range c.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k != "Virtual Drives" && !(strings.HasPrefix(k, "/c") && strings.Contains(k, "/v")) {
				continue
			}
			var vds []struct {
				DGVD  string `json:"DG/VD"`
				Type  string `json:"TYPE"`
				State string `json:"State"`
				Name  string `json:"Name"`
			}
			if json.Unmarshal(c.Data[k], &vds) != nil {
				continue
			}
			for _, d := range vds {
				vd := d.DGVD
				if i := strings.Index(vd, "/"); i >= 0 {
					vd = vd[i+1:]
				}
				h := "unknown"
				switch strings.ToLower(d.State) {
				case "optl":
					h = "ok"
				case "dgrd", "pdgd", "rec":
					h = "degraded"
				case "ofln", "offline":
					h = "failed"
				}
				ret = append(ret, SRaid{Kind: "storcli", Name: strings.TrimSpace(fmt.Sprintf("c%d/v%s %s", c.Status.Controller, vd, d.Name)),
					Level: strings.ToLower(d.Type), State: d.State, Health: h})
			}
		}
	}
	return ret, nil
}

// ipmitool -c sdr elist full: name,value,unit,status[,entity...]
func parseIpmiSdr(out string) []SSensor {
	var ret []SSensor
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), ",")
		if len(f) < 4 {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(f[1]), 64)
		if err != nil {
			continue
		}
		s := SSensor{Source: "ipmi", Name: strings.TrimSpace(f[0]), Value: v, Status: strings.TrimSpace(f[3])}
		switch strings.ToLower(strings.TrimSpace(f[2])) {
		case "degrees c":
			s.Kind, s.Unit = "temp", "C"
		case "rpm":
			s.Kind, s.Unit = "fan", "rpm"
		case "volts":
			s.Kind, s.Unit = "volt", "V"
		default:
			continue
		}
		ret = append(ret, s)
	}
	return ret
}

// chronyc -c tracking: refid,name,stratum,reftime,system offset s,...,leap status
func parseChronyTracking(out string) (*STime, bool) {
	f := strings.Split(strings.TrimSpace(out), ",")
	if len(f) < 14 {
		return nil, false
	}
	off, err := strconv.ParseFloat(f[4], 64)
	if err != nil {
		return nil, false
	}
	t := &STime{Source: "chrony", Server: f[1], OffsetMs: ptr(off * 1000)}
	t.Synced = ptr(f[len(f)-1] != "Not synchronised")
	return t, true
}

// timedatectl show-timesync: server name; timesync-status: the offset line
func parseTimesync(show, status string) (*STime, bool) {
	t := &STime{Source: "timesyncd"}
	for _, line := range strings.Split(show, "\n") {
		if v, ok := strings.CutPrefix(line, "ServerName="); ok {
			t.Server = v
		}
	}
	if t.Server == "" {
		return nil, false
	}
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Offset:"); ok {
			t.OffsetMs = parseDurMs(strings.TrimSpace(v))
		}
	}
	return t, true
}

var durRe = regexp.MustCompile(`^([+-]?[0-9.]+)(ns|us|µs|ms|s|min)$`)

func parseDurMs(s string) *float64 {
	m := durRe.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil
	}
	mul := map[string]float64{"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1, "s": 1e3, "min": 6e4}[m[2]]
	return ptr(v * mul)
}

func clampPct(p *float64) *float64 {
	if p == nil || math.IsNaN(*p) || math.IsInf(*p, 0) {
		return nil
	}
	return ptr(math.Max(0, math.Min(100, *p)))
}

func finite(p *float64, lo, hi float64) *float64 {
	if p == nil || math.IsNaN(*p) || math.IsInf(*p, 0) || *p < lo || *p > hi {
		return nil
	}
	return p
}

func okFloat(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func capList[T any](l []T, n int) []T {
	if len(l) > n {
		return l[:n]
	}
	return l
}

func capStrs(l []string, n, size int) []string {
	l = capList(l, n)
	for i := range l {
		l[i] = sclip(l[i], size)
	}
	return l
}

// the server applies the same caps
func (s *State) capAll() {
	if p := s.Perf; p != nil {
		p.CPUPct, p.SwapPct = clampPct(p.CPUPct), clampPct(p.SwapPct)
		for _, v := range p.Load {
			if !okFloat(v) || v < 0 {
				p.Load = nil
			}
		}
		if len(p.Load) != 3 {
			p.Load = nil
		}
	}
	if y := s.System; y != nil {
		y.Units = capList(y.Units, 128)
		for i := range y.Units {
			u := &y.Units[i]
			u.Name, u.Active, u.Sub, u.Description = sclip(u.Name, 255), sclip(u.Active, 24), sclip(u.Sub, 24), sclip(u.Description, 128)
		}
		y.Mounts = capList(y.Mounts, 32)
		for i := range y.Mounts {
			m := &y.Mounts[i]
			m.Mount, m.Device, m.FS = sclip(m.Mount, 255), sclip(m.Device, 255), sclip(m.FS, 32)
			m.UsedPct, m.InodePct = clampPct(m.UsedPct), clampPct(m.InodePct)
		}
		if t := y.Time; t != nil {
			t.Server = sclip(t.Server, 255)
			t.OffsetMs = finite(t.OffsetMs, -1e7, 1e7)
		}
		y.RAID = capList(y.RAID, 32)
		for i := range y.RAID {
			r := &y.RAID[i]
			r.Name, r.Level, r.State = sclip(r.Name, 64), sclip(r.Level, 32), sclip(r.State, 32)
			r.SyncPct = clampPct(r.SyncPct)
		}
		var ss []SSensor
		for _, x := range y.Sensors {
			if !okFloat(x.Value) || (x.Kind == "temp" && (x.Value < -40 || x.Value > 150)) {
				continue
			}
			x.Name, x.Status = sclip(x.Name, 64), sclip(x.Status, 16)
			x.Warn, x.Crit = finite(x.Warn, -1e6, 1e6), finite(x.Crit, -1e6, 1e6)
			ss = append(ss, x)
		}
		y.Sensors = capList(ss, 64)
	}
	if n := s.Net; n != nil {
		n.Ifaces = capList(n.Ifaces, 32)
		for i := range n.Ifaces {
			f := &n.Ifaces[i]
			f.Name, f.MAC = sclip(f.Name, 64), sclip(f.MAC, 32)
			f.Addrs, f.Members = capStrs(f.Addrs, 16, 64), capStrs(f.Members, 32, 64)
			if f.Master != nil {
				f.Master = ptr(sclip(*f.Master, 64))
			}
			if r := f.Rate; r != nil {
				for _, v := range []float64{r.RxBps, r.TxBps, r.RxPps, r.TxPps, r.ErrPs, r.DropPs} {
					if !okFloat(v) || v < 0 || v > 1e12 {
						f.Rate = nil
					}
				}
			}
		}
	}
	if c := s.Containers; c != nil {
		c.Items = capList(c.Items, 128)
		for i := range c.Items {
			x := &c.Items[i]
			x.ID, x.Name, x.Image, x.Status = sclip(x.ID, 64), sclip(x.Name, 128), sclip(x.Image, 255), sclip(x.Status, 128)
			x.CPUPct = finite(x.CPUPct, 0, 1e6)
			if x.Node != nil {
				x.Node = ptr(sclip(*x.Node, 64))
			}
		}
		if c.Items == nil {
			c.Items = []SContainer{}
		}
		if c.Cluster != nil {
			c.Cluster.Name = sclip(c.Cluster.Name, 64)
		}
	}
}

// Marshals and, when over the server's 256 KB, halves the longest list
// until it fits.
func encodeState(s *State) ([]byte, error) {
	trimmed := false
	for {
		b, err := json.Marshal(s)
		if err != nil || len(b) <= stateMaxBody {
			return b, err
		}
		var lists []*int
		var cut []func(int)
		add := func(n int, f func(int)) {
			lists, cut = append(lists, &n), append(cut, f)
		}
		if c := s.Containers; c != nil {
			add(len(c.Items), func(n int) { c.Items = c.Items[:n] })
		}
		if y := s.System; y != nil {
			add(len(y.Units), func(n int) { y.Units = y.Units[:n] })
			add(len(y.Mounts), func(n int) { y.Mounts = y.Mounts[:n] })
			add(len(y.Sensors), func(n int) { y.Sensors = y.Sensors[:n] })
			add(len(y.RAID), func(n int) { y.RAID = y.RAID[:n] })
		}
		if n := s.Net; n != nil {
			add(len(n.Ifaces), func(k int) { n.Ifaces = n.Ifaces[:k] })
		}
		best := -1
		for i, n := range lists {
			if *n > 1 && (best < 0 || *n > *lists[best]) {
				best = i
			}
		}
		if best < 0 {
			return b, nil
		}
		cut[best](*lists[best] / 2)
		if !trimmed && len(s.Errors) < 16 {
			s.Errors = append(s.Errors, "state trimmed to fit")
			trimmed = true
		}
	}
}
