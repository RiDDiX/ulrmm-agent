// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"os"
	"strings"
)

// macOS arms Wake for network access per machine (pmset womp), not per nic
func wolStates(names []string) map[string]string { return nil }

func healthStages() []healthStage {
	return []healthStage{macPower, macAV, macFirewall, macPlatform, macHardware, macTemps}
}

func macPower(ctx context.Context, h *Health) {
	if out, err := runOut(ctx, "/usr/bin/pmset", "-g", "custom"); err == nil {
		h.Power.WompAC, h.Power.WompBatt = parsePmsetWomp(out)
	} else {
		h.errf("pmset: %v", err)
	}
}

func macAV(ctx context.Context, h *Health) {
	h.AV = make([]HAV, 0)
	if out, err := runOut(ctx, "/usr/bin/xprotect", "version"); err == nil {
		v, inst := parseXProtect(out)
		h.AV = append(h.AV, HAV{Name: "XProtect", Enabled: v != "", Src: "xprotect", Version: v, Updated: inst})
	} else if _, err := os.Stat("/Library/Apple/System/Library/CoreServices/XProtect.bundle"); err == nil {
		h.AV = append(h.AV, HAV{Name: "XProtect", Enabled: true, Src: "xprotect"})
	}
}

func macFirewall(ctx context.Context, h *Health) {
	if out, err := runOut(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		h.Firewall = &HFirewall{Enabled: socketFWState(out), Products: []HFwProduct{}}
	} else {
		h.errf("socketfilterfw: %v", err)
	}
}

func macPlatform(ctx context.Context, h *Health) {
	p := &HPlatform{}
	if out, err := runOut(ctx, "/usr/sbin/spctl", "--status"); err == nil || out != "" {
		p.Gatekeeper = ptr(strings.Contains(out, "assessments enabled"))
	}
	if out, err := runOut(ctx, "/usr/bin/csrutil", "status"); err == nil {
		p.SIP = ptr(strings.Contains(out, "status: enabled"))
	}
	if out, err := runOut(ctx, "/usr/bin/fdesetup", "status"); err == nil {
		p.FileVault = ptr(strings.Contains(out, "FileVault is On"))
	}
	h.Platform = p
}

func macHardware(ctx context.Context, h *Health) {
	h.Disks = make([]HDisk, 0)
	if out, err := runOut(ctx, "/usr/sbin/system_profiler", "-json", "-detailLevel", "mini", "SPPowerDataType", "SPNVMeDataType", "SPSerialATADataType"); err == nil {
		bat, disks, perr := parseSystemProfiler([]byte(out))
		if perr != nil {
			h.errf("system_profiler: %v", perr)
		}
		h.Battery, h.Disks = bat, disks
	} else {
		h.errf("system_profiler: %v", err)
	}
}

// Apple silicon has no native CPU temperature without IOKit; pressure level only
func macTemps(ctx context.Context, h *Health) {
	h.Temps = make([]HTemp, 0)
	if out, err := runOut(ctx, "/usr/bin/notifyutil", "-g", "com.apple.system.thermalpressurelevel"); err == nil {
		h.ThermalPressure = lastInt(out)
	}
}
