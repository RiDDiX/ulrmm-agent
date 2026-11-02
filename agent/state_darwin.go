// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"strings"

	gnet "github.com/shirou/gopsutil/v3/net"
)

// cpu times need cgo on macOS; top's second sample covers one second
func osCPUPct(ctx context.Context) (*float64, error) {
	out, err := runOut(ctx, "/usr/bin/top", "-l", "2", "-n", "0", "-s", "1")
	if err != nil {
		return nil, err
	}
	if p := parseTopCPU(out); p != nil {
		return p, nil
	}
	return nil, errors.New("top: no CPU usage line")
}

func osSystem(ctx context.Context, e *errs) *SSystem {
	return &SSystem{Manager: nixManager(), Mounts: statMounts(psMounts(ctx, e))}
}

var darwinSkipIface = []string{"awdl", "llw", "anpi", "ap", "utun", "gif", "stf", "bridge100"}

func osIfaces(ctx context.Context, e *errs) []SIface {
	return psIfaces(ctx, func(i gnet.InterfaceStat) bool {
		return len(strings.Split(i.HardwareAddr, ":")) == 6 && !hasAnyPrefix(i.Name, darwinSkipIface)
	}, e)
}
