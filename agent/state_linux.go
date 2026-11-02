// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

func osCPUPct(ctx context.Context) (*float64, error) { return timesCPUPct(ctx) }

func osSystem(ctx context.Context, e *errs) *SSystem {
	y := &SSystem{Manager: nixManager()}
	if y.Manager == "systemd" {
		if svcs, err := systemdUnits(ctx); err != nil {
			e.add("units: %v", err)
		} else {
			total, failed, units := pickUnits(svcs)
			y.UnitsTotal, y.UnitsFailed, y.Units = &total, &failed, dropDoneOneshots(ctx, units)
		}
	}
	if b, err := os.ReadFile("/proc/self/mountinfo"); err != nil {
		e.add("mounts: %v", err)
	} else {
		y.Mounts = statMounts(parseMountinfo(string(b)))
	}
	y.Time = linuxTime(ctx)
	y.RAID = linuxRaid(ctx, e)
	y.Sensors = hwmonSensors(hwmonRoot)
	if _, err := os.Stat("/dev/ipmi0"); err == nil {
		if _, err := exec.LookPath("ipmitool"); err == nil {
			if out, err := runOut(ctx, "ipmitool", "-c", "sdr", "elist", "full"); err != nil && out == "" {
				e.add("ipmitool: %v", err)
			} else {
				y.Sensors = append(y.Sensors, parseIpmiSdr(out)...)
			}
		}
	}
	return y
}

// failed first, then units on their way up or down, then enabled ones that are not running
func pickUnits(svcs []nixSvc) (total, failed int, units []SUnit) {
	rank := func(s nixSvc) int {
		switch {
		case s.active == "failed":
			return 0
		case s.active == "activating" || s.active == "deactivating" || s.active == "reloading":
			return 1
		case s.active == "inactive" && s.OnBoot != nil && *s.OnBoot:
			return 2
		}
		return -1
	}
	var pick []nixSvc
	for _, s := range svcs {
		total++
		if s.active == "failed" {
			failed++
		}
		if rank(s) >= 0 {
			pick = append(pick, s)
		}
	}
	sort.SliceStable(pick, func(i, j int) bool { return rank(pick[i]) < rank(pick[j]) })
	for _, s := range pick {
		units = append(units, SUnit{Name: s.Unit, Active: s.active, Sub: s.sub, Enabled: s.OnBoot, Description: s.Desc})
	}
	return
}

// an enabled oneshot that ran fine is inactive by design
func dropDoneOneshots(ctx context.Context, units []SUnit) []SUnit {
	args := []string{"show", "-p", "Id", "-p", "Type", "-p", "Result", "--no-pager"}
	for _, u := range units {
		if u.Active == "inactive" && nixNameRe.MatchString(u.Name) {
			args = append(args, u.Name)
		}
	}
	if len(args) == 8 {
		return units
	}
	out, err := nixRun(ctx, "systemctl", args...)
	if err != nil {
		return units
	}
	done := doneOneshots(out)
	ret := units[:0]
	for _, u := range units {
		if !(u.Active == "inactive" && done[u.Name]) {
			ret = append(ret, u)
		}
	}
	return ret
}

func doneOneshots(out string) map[string]bool {
	m := map[string]bool{}
	for _, block := range strings.Split(out, "\n\n") {
		var id, typ, res string
		for _, line := range strings.Split(block, "\n") {
			k, v, _ := strings.Cut(line, "=")
			switch k {
			case "Id":
				id = v
			case "Type":
				typ = v
			case "Result":
				res = v
			}
		}
		if typ == "oneshot" && res == "success" {
			m[id] = true
		}
	}
	return m
}

const (
	staUnsync = 0x40
	staNano   = 0x2000
)

// kernel view read-only (modes 0); chrony or timesyncd when they answer
func linuxTime(ctx context.Context) *STime {
	if _, err := exec.LookPath("chronyc"); err == nil {
		if out, err := runOut(ctx, "chronyc", "-c", "tracking"); err == nil {
			if t, ok := parseChronyTracking(out); ok {
				return t
			}
		}
	}
	if _, err := exec.LookPath("timedatectl"); err == nil {
		if show, err := runOut(ctx, "timedatectl", "show-timesync"); err == nil {
			status, _ := runOut(ctx, "timedatectl", "timesync-status")
			if t, ok := parseTimesync(show, status); ok {
				t.Synced = kernelTime().Synced
				return t
			}
		}
	}
	return kernelTime()
}

func kernelTime() *STime {
	t := &STime{Source: "kernel"}
	var tx unix.Timex
	if _, err := unix.Adjtimex(&tx); err == nil {
		t.Synced = ptr(tx.Status&staUnsync == 0)
		off := float64(tx.Offset) / 1000
		if tx.Status&staNano != 0 {
			off = float64(tx.Offset) / 1e6
		}
		t.OffsetMs = &off
	}
	return t
}

func linuxRaid(ctx context.Context, e *errs) []SRaid {
	var ret []SRaid
	if b, err := os.ReadFile("/proc/mdstat"); err == nil {
		ret = parseMdstat(string(b))
	}
	if _, err := exec.LookPath("zpool"); err == nil {
		if out, err := runOut(ctx, "zpool", "list", "-H", "-o", "name,health,size,alloc"); err != nil {
			e.add("zpool: %v", err)
		} else {
			ret = append(ret, parseZpool(out)...)
		}
	}
	for _, tool := range []string{"storcli64", "storcli", "perccli64"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		out, _ := runOut(ctx, tool, "/call/vall", "show", "J")
		r, err := parseStorcli([]byte(out))
		if err != nil {
			e.add("%s: %v", tool, err)
		}
		ret = append(ret, r...)
		break
	}
	return ret
}

// temps first, they matter most when the list is cut
func hwmonSensors(root string) []SSensor {
	var ret []SSensor
	limit := func(path string) *float64 {
		if n, ok := readInt(path); ok && n > 0 {
			return ptr(float64(n) / 1000)
		}
		return nil
	}
	alarm := func(base string) string {
		if n, ok := readInt(base + "_alarm"); ok && n != 0 {
			return "alarm"
		}
		return "ok"
	}
	for _, in := range hwmonInputs(root, "temp") {
		s := SSensor{Kind: "temp", Source: "hwmon", Name: in.name, Value: float64(in.v) / 1000, Unit: "C",
			Warn: limit(in.base + "_max"), Crit: limit(in.base + "_crit"), Status: "ok"}
		if s.Value < -40 || s.Value > 150 {
			continue
		}
		switch {
		case s.Crit != nil && s.Value >= *s.Crit:
			s.Status = "crit"
		case s.Warn != nil && s.Value >= *s.Warn:
			s.Status = "warn"
		}
		ret = append(ret, s)
	}
	for _, in := range hwmonInputs(root, "fan") {
		ret = append(ret, SSensor{Kind: "fan", Source: "hwmon", Name: in.name, Value: float64(in.v), Unit: "rpm", Status: alarm(in.base)})
	}
	for _, in := range hwmonInputs(root, "in") {
		ret = append(ret, SSensor{Kind: "volt", Source: "hwmon", Name: in.name, Value: float64(in.v) / 1000, Unit: "V", Status: alarm(in.base)})
	}
	return ret
}

func osIfaces(ctx context.Context, e *errs) []SIface {
	return sysIfaces("/sys/class/net", func(name string) []string {
		i, err := net.InterfaceByName(name)
		if err != nil {
			return nil
		}
		addrs, _ := i.Addrs()
		var ret []string
		for _, a := range addrs {
			ret = append(ret, a.String())
		}
		return ret
	})
}

var skipIfacePrefix = []string{"veth", "tap", "fwbr", "fwpr", "fwln"}

// hardware nics plus bonds, bridges and vlans; lo, veth and the Proxmox
// firewall plumbing are left out
func sysIfaces(root string, addrs func(string) []string) []SIface {
	ents, _ := os.ReadDir(root)
	var ret []SIface
	for _, ent := range ents {
		n := ent.Name()
		if n == "lo" || hasAnyPrefix(n, skipIfacePrefix) {
			continue
		}
		d := filepath.Join(root, n)
		exists := func(p string) bool { _, err := os.Lstat(filepath.Join(d, p)); return err == nil }
		uevent, _ := os.ReadFile(filepath.Join(d, "uevent"))
		f := SIface{Name: n, Kind: "other", State: "unknown"}
		switch {
		case exists("bonding"):
			f.Kind = "bond"
		case exists("bridge"):
			f.Kind = "bridge"
		case strings.Contains(string(uevent), "DEVTYPE=vlan"):
			f.Kind = "vlan"
		case exists("wireless") || exists("phy80211"):
			f.Kind = "wifi"
		case exists("device"):
			f.Kind = "ether"
		default:
			continue
		}
		switch readStr(d + "/operstate") {
		case "up":
			f.State = "up"
		case "down", "lowerlayerdown", "notpresent":
			f.State = "down"
		}
		// speed reads EINVAL on a link that is down
		if v, ok := readInt(d + "/speed"); ok && v > 0 {
			f.SpeedMbps = ptr(int(v))
		}
		if dx := readStr(d + "/duplex"); dx == "full" || dx == "half" {
			f.Duplex = ptr(dx)
		}
		f.MAC = readStr(d + "/address")
		if v, ok := readInt(d + "/mtu"); ok && v > 0 {
			f.MTU = ptr(int(v))
		}
		if l, err := os.Readlink(d + "/master"); err == nil {
			f.Master = ptr(filepath.Base(l))
		}
		if f.Kind == "bond" {
			b, _ := os.ReadFile(d + "/bonding/slaves")
			f.Members = strings.Fields(string(b))
		} else if f.Kind == "bridge" {
			brif, _ := os.ReadDir(d + "/brif")
			for _, m := range brif {
				f.Members = append(f.Members, m.Name())
			}
		}
		st := func(k string) int64 {
			v, _ := readInt(d + "/statistics/" + k)
			return v
		}
		f.RxBytes, f.TxBytes = st("rx_bytes"), st("tx_bytes")
		f.RxPackets, f.TxPackets = st("rx_packets"), st("tx_packets")
		f.RxErrors, f.TxErrors = st("rx_errors"), st("tx_errors")
		f.RxDrops, f.TxDrops = st("rx_dropped"), st("tx_dropped")
		f.Addrs = addrs(n)
		ret = append(ret, f)
	}
	return ret
}
