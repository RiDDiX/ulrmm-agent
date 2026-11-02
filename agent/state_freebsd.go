// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"os/exec"
	"strings"

	gnet "github.com/shirou/gopsutil/v3/net"
)

func osCPUPct(ctx context.Context) (*float64, error) { return timesCPUPct(ctx) }

func osSystem(ctx context.Context, e *errs) *SSystem {
	y := &SSystem{Manager: nixManager(), Mounts: statMounts(psMounts(ctx, e))}
	if svcs, err := rcdScan(ctx, true); err != nil {
		e.add("services: %v", err)
	} else {
		total, failed, units := rcdFailed(svcs)
		y.UnitsTotal, y.UnitsFailed, y.Units = &total, &failed, units
	}
	y.Time = freebsdTime(ctx)
	y.RAID = freebsdRaid(ctx, e)
	out, _ := runOut(ctx, "sysctl", "-e", "dev.cpu", "hw.acpi.thermal")
	y.Sensors = sysctlSensors(parseSysctlTemps(out))
	return y
}

func freebsdTime(ctx context.Context) *STime {
	if _, err := exec.LookPath("chronyc"); err == nil {
		if out, err := runOut(ctx, "chronyc", "-c", "tracking"); err == nil {
			if t, ok := parseChronyTracking(out); ok {
				return t
			}
		}
	}
	if out, err := runOut(ctx, "ntpq", "-c", "rv"); err == nil {
		if t, ok := parseNtpqRV(out); ok {
			return t
		}
	}
	return nil
}

func freebsdRaid(ctx context.Context, e *errs) []SRaid {
	var ret []SRaid
	if _, err := exec.LookPath("zpool"); err == nil {
		if out, err := runOut(ctx, "zpool", "list", "-H", "-o", "name,health,size,alloc"); err != nil {
			e.add("zpool: %v", err)
		} else {
			ret = append(ret, parseZpool(out)...)
		}
	}
	// exits 1 when the class is not loaded, nothing to report then
	for _, k := range []string{"gmirror", "graid"} {
		if out, err := runOut(ctx, k, "status", "-s"); err == nil {
			ret = append(ret, parseGeomRaid(out, k)...)
		}
	}
	return ret
}

// epair and tap are the host ends of jails and bhyve guests
var freebsdSkipIface = []string{"epair", "tap"}

func osIfaces(ctx context.Context, e *errs) []SIface {
	ifs := psIfaces(ctx, func(i gnet.InterfaceStat) bool {
		return len(strings.Split(i.HardwareAddr, ":")) == 6 && !hasAnyPrefix(i.Name, freebsdSkipIface)
	}, e)
	for i := range ifs {
		switch n := ifs[i].Name; {
		case strings.HasPrefix(n, "lagg"):
			ifs[i].Kind = "bond"
		case strings.HasPrefix(n, "wlan"):
			ifs[i].Kind = "wifi"
		case strings.HasPrefix(n, "vlan") || strings.Contains(n, "."):
			ifs[i].Kind = "vlan"
		}
	}
	return ifs
}
