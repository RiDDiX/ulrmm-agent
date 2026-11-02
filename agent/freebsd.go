// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// FreeBSD: rc.d service, cron job and the parsers for base system tools.
// Not tagged freebsd so the parsers are tested on every unix.

// rc(8) names are shell variables: ulrmm-agent.service is ulrmm_agent
func rcName() string {
	return strings.ReplaceAll(strings.TrimSuffix(IdentNixSvc, ".service"), "-", "_")
}

func rcScriptPath() string { return "/usr/local/etc/rc.d/" + rcName() }
func healCronPath() string {
	return "/etc/cron.d/" + strings.TrimSuffix(IdentNixSvc, ".service") + "-selfheal"
}

// shQuote is a single-quoted sh word.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// daemon(8) restarts the agent 5 s after it ended; stop signals the
// supervisor, which ends the agent. rc runs with PATH=/sbin:/bin:/usr/sbin:/usr/bin,
// packages (smartctl, bash) live in /usr/local.
func rcScript(bin string) string {
	n := rcName()
	return fmt.Sprintf(`#!/bin/sh

# PROVIDE: %[1]s
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name=%[1]s
desc=%[2]s
rcvar=%[1]s_enable

load_rc_config $name
: ${%[1]s_enable:="NO"}

pidfile="/var/run/${name}.pid"
procname="/usr/sbin/daemon"
command="/usr/sbin/daemon"
command_args="-R 5 -P ${pidfile} -f %[3]s -m svc"
PATH="${PATH}:/usr/local/sbin:/usr/local/bin"
export PATH

run_rc_command "$1"
`, n, shQuote(BrandAgentName), bin)
}

func healCron(healBin string) string {
	return fmt.Sprintf(`# %s self-healing check
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
*/15 * * * * root %s -m selfheal >/dev/null 2>&1
`, BrandAgentName, healBin)
}

// `service -e`: the enabled scripts as paths
func parseServiceEnabled(out string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Fields(out) {
		m[path.Base(l)] = true
	}
	return m
}

var rcPidRe = regexp.MustCompile(`is running as pid (\d+)`)

// `service <name> onestatus`. A script without status has no such line.
func parseRcdStatus(out string) (status string, pid *int) {
	if m := rcPidRe.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return "running", ptr(n)
	}
	if strings.Contains(out, " is not running") {
		return "stopped", nil
	}
	return "unknown", nil
}

var (
	rcDescRe    = regexp.MustCompile(`(?m)^desc=["']?([^"'\n]*)`)
	rcOneshotRe = regexp.MustCompile(`(?m)^\s*stop_cmd=["']?:["']?\s*$`)
)

// stop_cmd=":" is the rc.subr idiom of a script that runs once (newsyslog, ntpdate)
func rcOneshot(script string) bool { return rcOneshotRe.MatchString(script) }

func rcDesc(script string) string {
	if m := rcDescRe.FindStringSubmatch(script); m != nil {
		return clipUTF8(strings.TrimSpace(m[1]), 512)
	}
	return ""
}

// failed: enabled but not running; one-shots and scripts without a status
// do not count. The total counts the enabled scripts with a status.
func rcdFailed(svcs []nixSvc) (total, failed int, units []SUnit) {
	for _, s := range svcs {
		if s.State == "unknown" || s.oneshot {
			continue
		}
		total++
		if s.State == "stopped" && s.OnBoot != nil && *s.OnBoot {
			failed++
			units = append(units, SUnit{Name: s.Unit, Active: "failed", Sub: "dead", Enabled: s.OnBoot, Description: s.Desc})
		}
	}
	return
}

// `geom disk list`: one block per disk, "Geom name:" first
func parseGeomDisks(out string) []string {
	ret := []string{}
	var name, descr, rot string
	var size uint64
	flush := func() {
		if name != "" && size > 0 && !hasAnyPrefix(name, []string{"cd", "md"}) {
			media := ""
			switch rot {
			case "0":
				media = "SSD"
			case "", "unknown":
			default:
				media = "HDD"
			}
			ret = append(ret, diskLine("", descr, "", media, name, size))
		}
		name, descr, rot, size = "", "", "", 0
	}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Geom name":
			flush()
			name = v
		case "Mediasize":
			size, _ = strconv.ParseUint(strings.Fields(v + " 0")[0], 10, 64)
		case "descr":
			descr = v
		case "rotationrate":
			rot = v
		}
	}
	flush()
	return ret
}

var pciIDRe = regexp.MustCompile(`vendor=(0x[0-9a-f]+) device=(0x[0-9a-f]+)`)

// `pciconf -lv`: a device line, then indented vendor/device/class lines;
// the ids stand in for names the pci database does not know
func parsePciconfGPUs(out string) []string {
	ret := []string{}
	var ids, vendor, device, class string
	flush := func() {
		if class == "display" {
			if name := strings.TrimSpace(vendor + " " + device); name != "" {
				ret = append(ret, name)
			} else if ids != "" {
				ret = append(ret, ids)
			}
		}
		ids, vendor, device, class = "", "", "", ""
	}
	for _, l := range strings.Split(out, "\n") {
		if l != "" && l[0] != ' ' && l[0] != '\t' {
			flush()
			if m := pciIDRe.FindStringSubmatch(l); m != nil {
				ids = m[1] + " " + m[2]
			}
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), "'")
		switch strings.TrimSpace(k) {
		case "vendor":
			vendor = v
		case "device":
			device = v
		case "class":
			class = v
		}
	}
	flush()
	return ret
}

var ifcapRe = regexp.MustCompile(`(?m)^\s*(options|capabilities)=[0-9a-f]+<([^>]*)>`)

// `ifconfig -m <if>`: options are the enabled capabilities, capabilities the supported ones
func parseIfconfigWoL(out string) string {
	has := map[string]bool{}
	for _, m := range ifcapRe.FindAllStringSubmatch(out, -1) {
		for _, c := range strings.Split(m[2], ",") {
			if c == "WOL_MAGIC" {
				has[m[1]] = true
			}
		}
	}
	switch {
	case has["options"]:
		return "on"
	case has["capabilities"]:
		return "off"
	}
	return "unsupported"
}

var sysctlCRe = regexp.MustCompile(`^(dev\.cpu\.(\d+)\.temperature|hw\.acpi\.thermal\.(tz\d+)\.(temperature|_CRT|_HOT|_PSV))=(-?[0-9.]+)C$`)

type sysctlTemp struct {
	name       string
	c          float64
	warn, crit *float64
}

// `sysctl -e dev.cpu hw.acpi.thermal`: coretemp(4)/amdtemp(4) per cpu,
// acpi_thermal(4) per zone with its trip points
func parseSysctlTemps(out string) []sysctlTemp {
	var ret []sysctlTemp
	zones := map[string]int{}
	trips := map[string]map[string]float64{}
	for _, l := range strings.Split(out, "\n") {
		m := sysctlCRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		v, err := strconv.ParseFloat(m[5], 64)
		if err != nil || v < -40 || v > 150 {
			continue
		}
		switch {
		case m[2] != "":
			ret = append(ret, sysctlTemp{name: "cpu" + m[2], c: v})
		case m[4] == "temperature":
			zones[m[3]] = len(ret)
			ret = append(ret, sysctlTemp{name: "acpi " + m[3], c: v})
		case v > 0:
			if trips[m[3]] == nil {
				trips[m[3]] = map[string]float64{}
			}
			trips[m[3]][m[4]] = v
		}
	}
	for z, i := range zones {
		t := trips[z]
		if c, ok := t["_CRT"]; ok {
			ret[i].crit = ptr(c)
		}
		for _, k := range []string{"_HOT", "_PSV"} {
			if w, ok := t[k]; ok && ret[i].warn == nil {
				ret[i].warn = ptr(w)
			}
		}
	}
	return ret
}

func sysctlSensors(temps []sysctlTemp) []SSensor {
	var ret []SSensor
	for _, t := range temps {
		s := SSensor{Kind: "temp", Source: "sysctl", Name: t.name, Value: t.c, Unit: "C", Warn: t.warn, Crit: t.crit, Status: "ok"}
		switch {
		case s.Crit != nil && s.Value >= *s.Crit:
			s.Status = "crit"
		case s.Warn != nil && s.Value >= *s.Warn:
			s.Status = "warn"
		}
		ret = append(ret, s)
	}
	return ret
}

// `gmirror status -s` / `graid status -s`: name status component (state), one
// line per component. A component that left the mirror is not listed.
func parseGeomRaid(out, kind string) []SRaid {
	var ret []SRaid
	idx := map[string]int{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] == "Name" {
			continue
		}
		i, ok := idx[f[0]]
		if !ok {
			h := "unknown"
			switch strings.ToUpper(f[1]) {
			case "COMPLETE", "OPTIMAL":
				h = "ok"
			case "DEGRADED", "SUBOPTIMAL":
				h = "degraded"
			case "BROKEN", "FAILED":
				h = "failed"
			}
			idx[f[0]] = len(ret)
			ret = append(ret, SRaid{Kind: kind, Name: f[0], State: strings.ToLower(f[1]), Health: h, Devices: ptr(0), Failed: ptr(0)})
			i = idx[f[0]]
		}
		r := &ret[i]
		*r.Devices++
		comp := strings.ToUpper(strings.Join(f[3:], " "))
		if m := pctRe.FindStringSubmatch(comp); m != nil && geomSyncRe.MatchString(comp) {
			if p, err := strconv.ParseFloat(m[1], 64); err == nil {
				r.SyncPct = ptr(p)
			}
		}
		if geomBadRe.MatchString(comp) {
			*r.Failed++
		}
	}
	return ret
}

var (
	pctRe = regexp.MustCompile(`([0-9.]+)%`)
	// g_mirror and g_raid component states
	geomSyncRe = regexp.MustCompile(`SYNCHRONIZING|REBUILD|RESYNC`)
	geomBadRe  = regexp.MustCompile(`STALE|FAILED|OFFLINE|DISCONNECTED|BROKEN|DESTROY`)
)

// `ntpq -c rv`: the system variables of ntpd
func parseNtpqRV(out string) (*STime, bool) {
	t := &STime{Source: "ntpd"}
	vars := map[string]string{}
	for _, kv := range strings.Split(strings.ReplaceAll(out, "\n", ","), ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			vars[k] = strings.Trim(v, `"`)
		}
	}
	if _, ok := vars["leap"]; !ok {
		return nil, false
	}
	t.Synced = ptr(vars["leap"] != "11" && strings.Contains(out, "sync_ntp"))
	if off, err := strconv.ParseFloat(vars["offset"], 64); err == nil {
		t.OffsetMs = ptr(off)
	}
	if r := vars["refid"]; r != "" && *t.Synced {
		t.Server = r
	}
	return t, true
}

// `sysctl -n hw.acpi.supported_sleep_state`: "S3 S4 S5"
func parseSleepS3(out string) bool { return stringInSlice("S3", strings.Fields(out)) }

// `pfctl -s info`: "Status: Enabled for ..." or "Status: Disabled"
func parsePfInfo(out string) *bool {
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Status:"); ok {
			f := strings.Fields(v)
			return ptr(len(f) > 0 && f[0] == "Enabled")
		}
	}
	return nil
}

// `acpiconf -i 0`: capacities in mWh (or mAh), cycle count
func parseAcpiconfBattery(out string) *HBattery {
	num := func(v string) (int, bool) {
		n, err := strconv.Atoi(strings.Fields(v + " x")[0])
		return n, err == nil
	}
	var design, full int
	b := &HBattery{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Design capacity":
			design, _ = num(strings.TrimSpace(v))
		case "Last full capacity":
			full, _ = num(strings.TrimSpace(v))
		case "Cycle Count":
			if n, ok := num(strings.TrimSpace(v)); ok && n > 0 {
				b.Cycles = ptr(n)
			}
		}
	}
	if design <= 0 {
		return nil
	}
	if full > 0 {
		b.MaxCapacityPct = ptr(full * 100 / design)
	}
	return b
}
