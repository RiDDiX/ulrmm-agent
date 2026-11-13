// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"os"
	"strings"
	"time"
)

// ifconfig -m per nic: WOL_MAGIC in options (armed) or capabilities (supported)
func wolStates(names []string) map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ret := make(map[string]string)
	for _, n := range names {
		if out, err := runOut(ctx, "ifconfig", "-m", n); err == nil {
			ret[n] = parseIfconfigWoL(out)
		}
	}
	return ret
}

func healthStages() []healthStage {
	return []healthStage{bsdPower, bsdSecurity, bsdDisks, bsdBattery, bsdTemps}
}

func bsdPower(ctx context.Context, h *Health) {
	if out, err := runOut(ctx, "sysctl", "-n", "hw.acpi.supported_sleep_state"); err == nil {
		h.Power.S3 = ptr(parseSleepS3(out))
	}
}

func bsdSecurity(ctx context.Context, h *Health) {
	h.AV = make([]HAV, 0)
	freebsdFirewall(ctx, h)
}

func bsdDisks(ctx context.Context, h *Health) {
	h.Disks = make([]HDisk, 0)
	smartctlDisks(ctx, h, false)
}

func bsdBattery(ctx context.Context, h *Health) {
	// no battery: the oid does not exist or reads 0
	if out, err := runOut(ctx, "sysctl", "-n", "hw.acpi.battery.units"); err == nil && strings.TrimSpace(out) != "0" {
		if out, err := runOut(ctx, "acpiconf", "-i", "0"); err == nil {
			h.Battery = parseAcpiconfBattery(out)
		}
	}
}

func bsdTemps(ctx context.Context, h *Health) {
	h.Temps = make([]HTemp, 0)
	out, _ := runOut(ctx, "sysctl", "-e", "dev.cpu", "hw.acpi.thermal")
	for _, t := range parseSysctlTemps(out) {
		c := saneC(t.c, false)
		if c == nil {
			continue
		}
		ht := HTemp{Name: t.name, C: *c}
		if t.warn != nil {
			ht.WarnC = saneC(*t.warn, true)
		}
		if t.crit != nil {
			ht.CritC = saneC(*t.crit, true)
		}
		h.addTemp(ht)
	}
}

// reported, not alerted: pf when its device exists, ipfw when its module is loaded
func freebsdFirewall(ctx context.Context, h *Health) {
	fw := &HFirewall{Products: make([]HFwProduct, 0)}
	if _, err := os.Stat("/dev/pf"); err == nil {
		out, _ := runOut(ctx, "pfctl", "-s", "info")
		if on := parsePfInfo(out); on != nil {
			fw.Products = append(fw.Products, HFwProduct{Name: "pf", Enabled: *on})
		}
	}
	if out, err := runOut(ctx, "sysctl", "-n", "net.inet.ip.fw.enable"); err == nil {
		fw.Products = append(fw.Products, HFwProduct{Name: "ipfw", Enabled: strings.TrimSpace(out) == "1"})
	}
	on := false
	for _, p := range fw.Products {
		on = on || p.Enabled
	}
	if len(fw.Products) > 0 {
		fw.Enabled = ptr(on)
	}
	h.Firewall = fw
}
