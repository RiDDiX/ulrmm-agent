// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// Windows Update through the Windows Update Agent (wua_windows.go).

// A failed search sends nothing, so the server keeps what it knows.
func (a *Agent) GetWinUpdates(drivers bool) {
	updates, err := WUAUpdates(wuaScanQuery(drivers))
	if err != nil {
		a.Logger.Errorln("GetWinUpdates():", err)
		return
	}
	payload := rmm.UpdateScan{AgentID: a.AgentID, Packages: updates}
	if _, err := a.rClient.R().SetBody(payload).Post("/api/v3/winupdates/"); err != nil {
		a.Logger.Debugln("GetWinUpdates() post:", err)
	}
}

// Reports each result and, at the end, whether a restart is pending.
func (a *Agent) InstallUpdates(guids []string) {
	session, err := NewUpdateSession()
	if err != nil {
		a.Logger.Errorln("InstallUpdates() NewUpdateSession():", err)
		return
	}
	defer session.Close()

	for _, guid := range guids {
		a.installUpdate(session, guid)
	}

	time.Sleep(5 * time.Second)
	needsReboot, err := a.SystemRebootRequired()
	if err != nil {
		a.Logger.Errorln("InstallUpdates() SystemRebootRequired():", err)
	}
	body := rmm.RebootState{AgentID: a.AgentID, Pending: needsReboot}
	if _, err := a.rClient.R().SetBody(body).Put("/api/v3/winupdates/"); err != nil {
		a.Logger.Debugln("InstallUpdates() put:", err)
	}
}

func (a *Agent) installUpdate(s *IUpdateSession, guid string) {
	report := func(ok bool) {
		body := rmm.UpdateInstallResult{AgentID: a.AgentID, GUID: guid, OK: ok}
		if _, err := a.rClient.R().SetBody(body).Patch("/api/v3/winupdates/"); err != nil {
			a.Logger.Debugln("InstallUpdates() patch:", err)
		}
	}
	queries, ok := wuaIDQueries(guid)
	if !ok {
		a.Logger.Errorf("InstallUpdates(): %q is not an update id, skipped", guid)
		return
	}
	var coll *IUpdateCollection
	var n int32
	for _, query := range queries {
		c, err := s.GetWUAUpdateCollection(query)
		if err != nil {
			a.Logger.Errorln("InstallUpdates() search:", err)
			report(false)
			return
		}
		cnt, err := c.Count()
		if err != nil {
			c.Release()
			a.Logger.Errorln("InstallUpdates() count:", err)
			report(false)
			return
		}
		if cnt > 0 {
			coll, n = c, cnt
			break
		}
		c.Release()
	}
	if coll == nil {
		// superseded or withdrawn since the last scan
		body := rmm.UpdateSuperseded{AgentID: a.AgentID, GUID: guid}
		if _, err := a.rClient.R().SetBody(body).Post("/api/v3/superseded/"); err != nil {
			a.Logger.Debugln("InstallUpdates() superseded:", err)
		}
		return
	}
	defer coll.Release()
	for i := 0; i < int(n); i++ {
		u, err := coll.Item(i)
		if err != nil {
			a.Logger.Errorln("InstallUpdates() item:", err)
			report(false)
			continue
		}
		err = installWUA(s, u)
		u.Release()
		if err != nil {
			a.Logger.Errorln("InstallUpdates():", guid, err)
		}
		report(err == nil)
	}
}

// installWUA downloads and installs one update and checks the result code
// of both steps; a call that returns without error can still have failed.
func installWUA(s *IUpdateSession, u *IUpdate) error {
	coll, err := NewUpdateCollection()
	if err != nil {
		return err
	}
	defer coll.Release()
	eula, err := u.GetProperty("EulaAccepted")
	if err != nil {
		return fmt.Errorf("EulaAccepted: %w", err)
	}
	if accepted, ok := eula.Value().(bool); ok && !accepted {
		if _, err := u.CallMethod("AcceptEula"); err != nil {
			return fmt.Errorf("AcceptEula: %w", err)
		}
	}
	if err := coll.Add(u); err != nil {
		return err
	}
	for _, step := range []struct{ create, run string }{
		{"CreateUpdateDownloader", "Download"},
		{"CreateUpdateInstaller", "Install"},
	} {
		code, err := wuaOperation(s, step.create, step.run, coll)
		if err != nil {
			return fmt.Errorf("%s: %w", step.run, err)
		}
		if !wuaSucceeded(code) {
			return fmt.Errorf("%s ended with result code %d", step.run, code)
		}
	}
	return nil
}

// OperationResultCode of Download or Install on coll.
func wuaOperation(s *IUpdateSession, create, run string, coll *IUpdateCollection) (int64, error) {
	raw, err := s.CallMethod(create)
	if err != nil {
		return 0, err
	}
	op := raw.ToIDispatch()
	defer op.Release()
	if _, err := op.PutProperty("Updates", coll.IDispatch); err != nil {
		return 0, err
	}
	resRaw, err := op.CallMethod(run)
	if err != nil {
		return 0, err
	}
	res := resRaw.ToIDispatch()
	defer res.Release()
	code, err := res.GetProperty("ResultCode")
	if err != nil {
		return 0, err
	}
	return code.Val, nil
}
