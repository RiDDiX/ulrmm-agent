// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"strings"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/StackExchange/wmi"
	gnet "github.com/shirou/gopsutil/v3/net"
)

func osCPUPct(ctx context.Context) (*float64, error) { return timesCPUPct(ctx) }

func osSystem(ctx context.Context, e *errs) *SSystem {
	return &SSystem{Mounts: statMounts(psMounts(ctx, e))}
}

// well inside stateDeadline, so the fallback below still has time
const netAdapterWait = 20 * time.Second

func osIfaces(ctx context.Context, e *errs) []SIface {
	ads, err := wmiBounded(netAdapterWait, func() ([]winAdapter, error) {
		var dst []winAdapter
		err := wmi.QueryNamespace("SELECT Name, Speed, FullDuplex, MediaConnectState, PermanentAddress, NdisPhysicalMedium, MtuSize FROM MSFT_NetAdapter", &dst, nsStdCimv2)
		return dst, err
	})
	if err != nil {
		e.add("MSFT_NetAdapter: %v", err)
		return psIfaces(ctx, func(i gnet.InterfaceStat) bool {
			return len(strings.Split(i.HardwareAddr, ":")) == 6
		}, e)
	}
	list, err := gnet.InterfacesWithContext(ctx)
	if err != nil {
		e.add("interfaces: %v", err)
	}
	return joinAdapters(ads, ioCounters(ctx, e), list)
}

// Hyper-V only when its management service exists
func collectContainers(ctx context.Context, stats bool) *SContainers {
	ct := newContainers()
	if _, err := GetServiceStatus("vmms"); err != nil {
		return ct
	}
	out, err := runOut(ctx, getPowershellExe(), "-NoProfile", "-NonInteractive", "-Command",
		"Get-VM | Select-Object @{n='Id';e={$_.Id.ToString()}},Name,@{n='State';e={$_.State.ToString()}},CPUUsage,MemoryAssigned,@{n='Uptime';e={[int64]$_.Uptime.TotalSeconds}} | ConvertTo-Json -Compress")
	if err == nil {
		var items []SContainer
		items, err = parseGetVM([]byte(out))
		ct.Items = append(ct.Items, items...)
	}
	ct.source("hyperv", err)
	return ct
}

func systemdUnitCheck(c rmm.CheckDef) (status, info string) {
	return systemdVerdict(c, false, unitState{}, nil, nil)
}
