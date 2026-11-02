// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	nats "github.com/nats-io/nats.go"
)

func (a *Agent) checkinPayload(mode string) interface{} {
	switch mode {
	case "agent-hello":
		return rmm.HelloReport{AgentID: a.AgentID, AgentVersion: a.Version}
	case "agent-agentinfo":
		reboot, err := a.SystemRebootRequired()
		return rmm.InfoReport{
			AgentID:       a.AgentID,
			LoggedInUser:  a.LoggedOnUser(),
			HostName:      a.Hostname,
			OSName:        a.osString(),
			Plat:          a.Platform,
			RAMTotal:      a.TotalRAM(),
			Booted:        a.BootTime(),
			PendingReboot: reboot && err == nil,
			Arch:          a.GoArch,
		}
	case "agent-winsvc":
		svcs := a.GetServices()
		if svcs == nil {
			svcs = []rmm.WinService{}
		}
		return rmm.ServicesReport{AgentID: a.AgentID, Services: svcs}
	case "agent-wmi":
		return rmm.WMIReport{AgentID: a.AgentID, Data: a.GetWMIInfo()}
	case "agent-disks":
		disks := a.GetDisks()
		if disks == nil {
			disks = []rmm.DiskUsage{}
		}
		return rmm.DisksReport{AgentID: a.AgentID, Disks: disks}
	case "agent-publicip":
		return rmm.PublicIPReport{AgentID: a.AgentID, Addr: a.PublicIP()}
	}
	return nil
}

// Check-ins go to <agent id>.checkin; the reply subject carries the mode,
// that is how the server tells the messages apart.
func (a *Agent) NatsMessage(nc *nats.Conn, mode string) {
	payload := a.checkinPayload(mode)
	if payload == nil {
		return
	}
	a.Logger.Debugln(mode, payload)
	b, err := encodeMsgpack(payload)
	if err != nil {
		a.Logger.Errorln("NatsMessage() encode", mode, err)
		return
	}
	if err := nc.PublishRequest(a.AgentID+".checkin", mode, b); err != nil {
		a.Logger.Errorf("nats publish %s failed: %v (status %v)", mode, err, nc.Status())
	}
}

// DoNatsCheckIn sends every check-in once (-m checkin, and at install).
func (a *Agent) DoNatsCheckIn() {
	nc, err := nats.Connect(a.NatsServer, a.setupNatsOptions()...)
	if err != nil {
		a.Logger.Errorln(err)
		return
	}
	defer nc.Close()
	if !nc.IsConnected() {
		a.Logger.Errorf("nats: not connected to %s (status %v), checkin data will be dropped", a.NatsServer, nc.Status())
	}
	for _, mode := range natsCheckin {
		time.Sleep(time.Duration(randRange(100, 400)) * time.Millisecond)
		a.NatsMessage(nc, mode)
	}
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		a.Logger.Errorf("nats: flushing checkin to %s failed, data was not delivered: %v", a.NatsServer, err)
	}
}

// announcePower tells the server the machine goes away on purpose, before it
// does; cancel takes that back. A shutdown or restart also marks the coming
// service stop as expected. Repeats are dropped, see powerSkip.
func (a *Agent) announcePower(nc *nats.Conn, kind, source, initiator string, budget time.Duration) error {
	powerMu.Lock()
	defer powerMu.Unlock()
	now, boot := time.Now(), a.BootTime()
	if powerSkip(loadPowerState(), kind, source, boot, now) {
		return nil
	}
	if source == "wake" {
		source = "os"
	}
	switch kind {
	case "cancel":
		clearPowerState()
		clearExpectedStop(a.dataDir())
	case "shutdown", "restart", "shutdown_or_restart":
		expectStop(a.dataDir())
	}
	b, err := encodeMsgpack(rmm.PowerReport{AgentID: a.AgentID, Kind: kind, Source: source, Initiator: powerInitiator(initiator)})
	if err == nil {
		err = nc.PublishRequest(a.AgentID+".checkin", "agent-power", b)
	}
	if err == nil {
		err = nc.FlushTimeout(budget)
	}
	if err != nil {
		a.Logger.Errorln("agent-power", kind, err)
		return err
	}
	if kind != "cancel" {
		savePowerState(powerState{Kind: kind, Source: source, Boot: boot, At: now.Unix()})
	}
	return nil
}
