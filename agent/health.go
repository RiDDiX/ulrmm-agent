// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// wmi_detail["health"] and the payload of the security/hwhealth checks.
// Read-only, native sources only. The server treats all of it as untrusted.
// Serials and the WoL SecureOn password are never collected.
type Health struct {
	V               int        `json:"v"`
	TS              int64      `json:"ts"`
	MS              int64      `json:"ms"`
	Errors          []string   `json:"errors"`
	Power           HPower     `json:"power"`
	AV              []HAV      `json:"av"`
	Defender        *HDefender `json:"defender"`
	Firewall        *HFirewall `json:"firewall"`
	Platform        *HPlatform `json:"platform"`
	Disks           []HDisk    `json:"disks"`
	Battery         *HBattery  `json:"battery"`
	Temps           []HTemp    `json:"temps"`
	ThermalPressure *int       `json:"thermal_pressure"`
}

type HPower struct {
	S3            *bool `json:"s3,omitempty"`
	ModernStandby *bool `json:"modern_standby,omitempty"`
	WompAC        *bool `json:"womp_ac,omitempty"`
	WompBatt      *bool `json:"womp_batt,omitempty"`
}

type HAV struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate *bool  `json:"up_to_date"`
	Src      string `json:"src"`
	Version  string `json:"version,omitempty"`
	Updated  string `json:"updated,omitempty"`
}

type HDefender struct {
	Mode       string `json:"mode"`
	AV         bool   `json:"av"`
	RTP        bool   `json:"rtp"`
	SigAgeDays *int   `json:"sig_age_days"`
	SigUpdated string `json:"sig_updated,omitempty"`
}

type HFirewall struct {
	Enabled  *bool           `json:"enabled"`
	Products []HFwProduct    `json:"products"`
	Profiles map[string]bool `json:"profiles,omitempty"`
}

type HFwProduct struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type HPlatform struct {
	Gatekeeper *bool `json:"gatekeeper"`
	SIP        *bool `json:"sip"`
	FileVault  *bool `json:"filevault"`
}

type HDisk struct {
	Name            string `json:"name"`
	Bus             string `json:"bus"`
	Media           string `json:"media"`
	Health          string `json:"health"` // ok|warning|failing|unknown
	Smart           string `json:"smart"`  // passed|failed|unknown|standby
	TempC           *int   `json:"temp_c"`
	TempWarnC       *int   `json:"temp_warn_c"`
	TempCritC       *int   `json:"temp_crit_c"`
	WearPct         *int   `json:"wear_pct"`
	POH             *int64 `json:"poh"`
	MediaErrors     *int64 `json:"media_errors"`
	CriticalWarning *int   `json:"critical_warning"`
}

type HBattery struct {
	MaxCapacityPct *int   `json:"max_capacity_pct"`
	Cycles         *int   `json:"cycles"`
	DesignCycles   *int   `json:"design_cycles"`
	Condition      string `json:"condition,omitempty"`
}

type HTemp struct {
	Name  string `json:"name"`
	C     int    `json:"c"`
	WarnC *int   `json:"warn_c"`
	CritC *int   `json:"crit_c"`
}

const (
	healthDeadline = 30 * time.Second
	healthExecMax  = 10 * time.Second
	healthMaxList  = 64
	healthMaxOut   = 4 << 20
)

// Health runs the per-OS collector with one overall deadline. A collector
// that overruns is abandoned, its commands die with the context.
func (a *Agent) Health() *Health {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), healthDeadline)
	defer cancel()

	ch := make(chan *Health, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- &Health{Errors: []string{fmt.Sprint("collector panic: ", r)}}
			}
		}()
		h := &Health{}
		collectHealth(ctx, h)
		ch <- h
	}()

	var h *Health
	select {
	case h = <-ch:
	case <-ctx.Done():
		h = &Health{Errors: []string{"collection timed out"}}
	}
	h.V, h.TS, h.MS = 1, start.Unix(), time.Since(start).Milliseconds()
	if h.Errors == nil {
		h.Errors = []string{}
	}
	return h
}

func (h *Health) errf(format string, args ...interface{}) {
	if len(h.Errors) < 16 {
		h.Errors = append(h.Errors, clip(fmt.Sprintf(format, args...), 128))
	}
}

func (h *Health) addDisk(d HDisk) {
	if len(h.Disks) < healthMaxList {
		h.Disks = append(h.Disks, d)
	}
}

func (h *Health) addTemp(t HTemp) {
	if len(h.Temps) < healthMaxList {
		h.Temps = append(h.Temps, t)
	}
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func ptr[T any](v T) *T { return &v }

var errOutputTooLarge = errors.New("output too large")

// capBuf keeps the first healthMaxOut bytes and drops the rest without
// failing the write, so the child is not cut off mid-run; over tells the
// caller. The buffer is not embedded: its ReadFrom would let io.Copy past
// the cap.
type capBuf struct {
	buf  bytes.Buffer
	over bool
}

func (b *capBuf) Write(p []byte) (int, error) {
	n := len(p)
	if room := healthMaxOut - b.buf.Len(); n > room {
		p, b.over = p[:room], true
	}
	b.buf.Write(p)
	return n, nil
}

func (b *capBuf) String() string { return b.buf.String() }

// fixed argv, no shell, 10 s per exec. stdout is returned even on a non-zero exit.
func runOut(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, healthExecMax)
	defer cancel()
	var out capBuf
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	err := cmd.Run()
	if err == nil && out.over {
		err = errOutputTooLarge
	}
	return out.String(), err
}

// sane celsius or nil; hwmon and disks report bogus limits like 65261 C
func saneC(c float64, limit bool) *int {
	if math.IsNaN(c) || c < -40 || c > 150 || (limit && c <= 0) {
		return nil
	}
	return ptr(int(math.Round(c)))
}

// Security Center productState: byte 1 bit 4 = enabled, byte 0 bit 4 = definitions outdated
func wscState(state uint32) (enabled, upToDate bool) {
	return (state>>8)&0x10 != 0, state&0x10 == 0
}

// ETHTOOL_GWOL masks, WAKE_MAGIC = 0x20
func ethtoolWoL(supported, wolopts uint32) string {
	const wakeMagic = 0x20
	switch {
	case supported&wakeMagic == 0:
		return "unsupported"
	case wolopts&wakeMagic != 0:
		return "on"
	}
	return "off"
}

// MSFT_NetAdapterPowerManagementSettingData.WakeOnMagicPacket
func winWoL(v uint32) string {
	switch v {
	case 0:
		return "unsupported"
	case 1:
		return "off"
	case 2:
		return "on"
	}
	return ""
}

// value inside a quoted WQL object path key
func wqlEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// NVMe SMART / Health log page 0x02 (NVMe base spec, 512 bytes, little endian)
func parseNvmeLog(b []byte) (HDisk, bool) {
	if len(b) < 512 {
		return HDisk{}, false
	}
	d := HDisk{Bus: "nvme", Media: "ssd", Smart: "passed", Health: "ok"}
	cw := int(b[0])
	d.CriticalWarning = ptr(cw)
	if cw != 0 {
		d.Smart, d.Health = "failed", "failing"
	}
	if k := binary.LittleEndian.Uint16(b[1:3]); k > 0 {
		d.TempC = saneC(float64(k)-273.15, false)
	}
	d.WearPct = ptr(int(b[5]))
	// 128-bit counters; the low 64 bits are plenty
	d.POH = ptr(int64(binary.LittleEndian.Uint64(b[128:136]) & math.MaxInt64))
	d.MediaErrors = ptr(int64(binary.LittleEndian.Uint64(b[160:168]) & math.MaxInt64))
	return d, true
}

type smartctlJSON struct {
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String string `json:"string"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName    string `json:"model_name"`
	RotationRate *int   `json:"rotation_rate"`
	SmartStatus  *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
}

// `smartctl -n standby -i -H -A -j`; serials are not decoded
func parseSmartctl(out []byte) (HDisk, error) {
	var s smartctlJSON
	if err := json.Unmarshal(out, &s); err != nil {
		return HDisk{}, err
	}
	d := HDisk{Name: clip(s.ModelName, 64), Bus: strings.ToLower(clip(s.Device.Protocol, 16)), Media: "unknown", Smart: "unknown", Health: "unknown"}
	if s.RotationRate != nil {
		d.Media = "ssd"
		if *s.RotationRate > 0 {
			d.Media = "hdd"
		}
	}
	for _, m := range s.Smartctl.Messages {
		if s.Smartctl.ExitStatus&2 != 0 && strings.Contains(strings.ToUpper(m.String), "STANDBY") {
			d.Smart = "standby"
			return d, nil
		}
	}
	if s.SmartStatus != nil {
		d.Smart, d.Health = "passed", "ok"
		if !s.SmartStatus.Passed {
			d.Smart, d.Health = "failed", "failing"
		}
	}
	if s.Temperature.Current > 0 {
		d.TempC = saneC(float64(s.Temperature.Current), false)
	}
	if s.PowerOnTime.Hours > 0 {
		d.POH = ptr(s.PowerOnTime.Hours)
	}
	return d, nil
}

var (
	smartDevRe  = regexp.MustCompile(`^/dev/[A-Za-z0-9/_-]{1,64}$`)
	smartTypeRe = regexp.MustCompile(`^[a-z0-9,+_-]{1,32}$`)
)

// `smartctl --scan` lines: "/dev/sda -d sat # ..."
// --scan lists libata SATA as scsi; smartctl has no health data on scsi.
// sat,auto tries ATA and falls back to scsi.
func smartctlType(t string) string {
	if t == "scsi" {
		return "sat,auto"
	}
	return t
}

func parseSmartScan(out string) [][2]string {
	ret := make([][2]string, 0)
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(strings.SplitN(l, "#", 2)[0])
		if len(f) != 3 || f[1] != "-d" || !smartDevRe.MatchString(f[0]) || !smartTypeRe.MatchString(f[2]) {
			continue
		}
		if len(ret) < 32 {
			ret = append(ret, [2]string{f[0], f[2]})
		}
	}
	return ret
}

func smartctlDisks(ctx context.Context, h *Health, skipNvme bool) {
	if _, err := exec.LookPath("smartctl"); err != nil {
		h.errf("smartctl not installed")
		return
	}
	out, err := runOut(ctx, "smartctl", "--scan")
	if err != nil {
		h.errf("smartctl --scan: %v", err)
		return
	}
	for _, dev := range parseSmartScan(out) {
		// FreeBSD lists the optical drives (cd0) as ATA devices
		if (skipNvme && dev[1] == "nvme") || strings.HasPrefix(dev[0], "/dev/cd") {
			continue
		}
		// -n standby: never spin up a sleeping disk
		o, _ := runOut(ctx, "smartctl", "-n", "standby", "-i", "-H", "-A", "-j", "-d", smartctlType(dev[1]), dev[0])
		d, err := parseSmartctl([]byte(o))
		if err != nil {
			h.errf("smartctl %s: %v", dev[0], err)
			continue
		}
		d.Name = strings.TrimSpace(d.Name + " " + dev[0])
		h.addDisk(d)
	}
}

// nft -j list chains: any chain hooked on input
func nftHasInputChain(out []byte) bool {
	var v struct {
		Nftables []struct {
			Chain *struct {
				Hook string `json:"hook"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &v) != nil {
		return false
	}
	for _, i := range v.Nftables {
		if i.Chain != nil && i.Chain.Hook == "input" {
			return true
		}
	}
	return false
}

// pmset -g custom: womp per power source
func parsePmsetWomp(out string) (ac, batt *bool) {
	var cur **bool
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "AC Power"):
			cur = &ac
		case strings.HasPrefix(t, "Battery Power"), strings.HasPrefix(t, "UPS Power"):
			cur = &batt
		default:
			f := strings.Fields(t)
			if cur != nil && len(f) == 2 && f[0] == "womp" {
				*cur = ptr(f[1] == "1")
			}
		}
	}
	return
}

// "Version: 5360 Installed: 2026-09-17 22:58:51 +0000"
func parseXProtect(out string) (version, installed string) {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "Version:":
			version = clip(f[i+1], 32)
		case "Installed:":
			installed = clip(strings.Join(f[i+1:min(len(f), i+4)], " "), 32)
		}
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type spJSON struct {
	SPPowerDataType []struct {
		Health *struct {
			CycleCount  *int   `json:"sppower_battery_cycle_count"`
			Condition   string `json:"sppower_battery_health"`
			MaxCapacity string `json:"sppower_battery_health_maximum_capacity"`
		} `json:"sppower_battery_health_info"`
	} `json:"SPPowerDataType"`
	SPNVMeDataType []struct {
		Items []struct {
			Name        string `json:"_name"`
			SmartStatus string `json:"smart_status"`
		} `json:"_items"`
	} `json:"SPNVMeDataType"`
	SPSerialATADataType []struct {
		Items []struct {
			Name        string `json:"_name"`
			SmartStatus string `json:"smart_status"`
			MediumType  string `json:"spsata_medium_type"`
		} `json:"_items"`
	} `json:"SPSerialATADataType"`
}

// system_profiler -json; typed decode so serials and everything else are dropped
func parseSystemProfiler(out []byte) (*HBattery, []HDisk, error) {
	var sp spJSON
	if err := json.Unmarshal(out, &sp); err != nil {
		return nil, nil, err
	}
	var bat *HBattery
	for _, p := range sp.SPPowerDataType {
		if p.Health == nil {
			continue
		}
		bat = &HBattery{Cycles: p.Health.CycleCount, Condition: clip(p.Health.Condition, 32)}
		if n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(p.Health.MaxCapacity), "%")); err == nil && n >= 0 && n <= 200 {
			bat.MaxCapacityPct = ptr(n)
		}
	}
	disks := make([]HDisk, 0)
	add := func(name, status, bus, media string) {
		d := HDisk{Name: clip(name, 64), Bus: bus, Media: media, Smart: "unknown", Health: "unknown"}
		switch strings.ToLower(status) {
		case "verified":
			d.Smart, d.Health = "passed", "ok"
		case "failing":
			d.Smart, d.Health = "failed", "failing"
		}
		if len(disks) < healthMaxList {
			disks = append(disks, d)
		}
	}
	for _, c := range sp.SPNVMeDataType {
		for _, i := range c.Items {
			add(i.Name, i.SmartStatus, "nvme", "ssd")
		}
	}
	for _, c := range sp.SPSerialATADataType {
		for _, i := range c.Items {
			media := "unknown"
			if strings.Contains(strings.ToLower(i.MediumType), "solid") {
				media = "ssd"
			} else if strings.Contains(strings.ToLower(i.MediumType), "rotational") {
				media = "hdd"
			}
			add(i.Name, i.SmartStatus, "sata", media)
		}
	}
	return bat, disks, nil
}

// "Firewall is enabled. (State = 1)"; 2 = block all, also on
func socketFWState(out string) *bool {
	i := strings.Index(out, "State = ")
	if i < 0 {
		return nil
	}
	n := lastInt(strings.TrimRight(out[i:], ").\n "))
	if n == nil {
		return nil
	}
	return ptr(*n > 0)
}

// last integer field of a line like "com.apple.system.thermalpressurelevel 0"
func lastInt(out string) *int {
	f := strings.Fields(out)
	if len(f) == 0 {
		return nil
	}
	n, err := strconv.Atoi(f[len(f)-1])
	if err != nil || n < 0 || n > 16 {
		return nil
	}
	return ptr(n)
}
