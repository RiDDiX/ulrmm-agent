// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"time"
	"unsafe"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Every service handle is opened with only the rights the call needs, so
// services with a restrictive DACL still show up and can be queried.

func scmConnect(access uint32) (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

func openServiceOn(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, p, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func withService(name string, access uint32, fn func(s *mgr.Service) error) error {
	m, err := scmConnect(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openServiceOn(m, name, access)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}

func svcRecord(name string, state, pid uint32, c mgr.Config) rmm.WinService {
	return rmm.WinService{
		SvcName:   CleanString(name),
		State:     svcStateText(state),
		Display:   CleanString(c.DisplayName),
		ExePath:   CleanString(c.BinaryPathName),
		Desc:      CleanString(c.Description),
		Account:   CleanString(c.ServiceStartName),
		ProcID:    pid,
		Start:     svcStartTypeText(c.StartType),
		AutoDelay: c.DelayedAutoStart,
	}
}

type svcEntry struct {
	name       string
	state, pid uint32
}

// enumServices lists all Win32 services with state and process id in the
// order the service manager returns them.
func enumServices(scm windows.Handle) ([]svcEntry, error) {
	var (
		out    []svcEntry
		resume uint32
	)
	buf := make([]byte, 64<<10)
	for {
		var needed, count uint32
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL, &buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return out, err
		}
		if count == 0 && err != nil {
			if needed <= uint32(len(buf)) {
				return out, err
			}
			buf = make([]byte, needed)
			continue
		}
		if count > 0 {
			for _, e := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count) {
				out = append(out, svcEntry{
					name:  windows.UTF16PtrToString(e.ServiceName),
					state: e.ServiceStatusProcess.CurrentState,
					pid:   e.ServiceStatusProcess.ProcessId,
				})
			}
		}
		if err == nil {
			return out, nil
		}
	}
}

func (a *Agent) GetServices() []rmm.WinService {
	ret := []rmm.WinService{}
	m, err := scmConnect(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		a.Logger.Debugln("GetServices(): connect:", err)
		return ret
	}
	defer m.Disconnect()
	entries, err := enumServices(m.Handle)
	if err != nil {
		a.Logger.Debugln("GetServices(): enumerate:", err)
	}
	for _, e := range entries {
		s, err := openServiceOn(m, e.name, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			continue
		}
		c, err := s.Config()
		s.Close()
		if err != nil {
			continue
		}
		ret = append(ret, svcRecord(e.name, e.state, e.pid, c))
	}
	return ret
}

func (a *Agent) GetServiceDetail(name string) rmm.WinService {
	var ret rmm.WinService
	err := withService(name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		c, err := s.Config()
		if err != nil {
			return err
		}
		ret = svcRecord(name, uint32(st.State), st.ProcessId, c)
		return nil
	})
	if err != nil {
		a.Logger.Errorln("GetServiceDetail():", name, err)
		return rmm.WinService{}
	}
	return ret
}

// GetServiceStatus returns the state text, or "n/a" and the Windows error.
func GetServiceStatus(name string) (string, error) {
	state := "n/a"
	err := withService(name, windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		st, err := s.Query()
		if err == nil {
			state = svcStateText(uint32(st.State))
		}
		return err
	})
	if err != nil {
		return "n/a", err
	}
	return state, nil
}

// The server's restart is stop then start with 32 s each, so the stop wait
// stays below that.
const svcStopWait = 30 * time.Second

func stopAndWait(s *mgr.Service) error {
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	for deadline := time.Now().Add(svcStopWait); ; time.Sleep(500 * time.Millisecond) {
		st, err := s.Query()
		switch {
		case err != nil:
			return err
		case st.State == svc.Stopped:
			return nil
		case time.Now().After(deadline):
			return errors.New("Timed out waiting for service to stop")
		}
	}
}

func (a *Agent) ControlService(name, action string) rmm.SvcActionResult {
	var err error
	switch action {
	case "stop":
		err = withService(name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS, stopAndWait)
	case "start":
		err = withService(name, windows.SERVICE_START, func(s *mgr.Service) error { return s.Start() })
	default:
		return rmm.SvcActionResult{OK: false, Reason: "Something went wrong"}
	}
	if err != nil {
		return rmm.SvcActionResult{OK: false, Reason: err.Error()}
	}
	return rmm.SvcActionResult{OK: true, Reason: ""}
}

// EditService changes the start type and, for auto/autodelay, the delayed
// flag; the rest of the configuration is not touched.
func (a *Agent) EditService(name, startType string) rmm.SvcActionResult {
	ch, ok := svcStartRequest(startType)
	if !ok {
		return rmm.SvcActionResult{OK: false, Reason: "Unknown startup type provided"}
	}
	err := withService(name, windows.SERVICE_CHANGE_CONFIG, func(s *mgr.Service) error {
		nc := uint32(windows.SERVICE_NO_CHANGE)
		if err := windows.ChangeServiceConfig(s.Handle, nc, ch.startType, nc, nil, nil, nil, nil, nil, nil, nil); err != nil {
			return err
		}
		if !ch.setDelay {
			return nil
		}
		var info windows.SERVICE_DELAYED_AUTO_START_INFO
		if ch.delay {
			info.IsDelayedAutoStartUp = 1
		}
		return windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&info)))
	})
	if err != nil {
		return rmm.SvcActionResult{OK: false, Reason: err.Error()}
	}
	return rmm.SvcActionResult{OK: true, Reason: ""}
}

func serviceExists(name string) bool {
	return withService(name, windows.SERVICE_QUERY_STATUS, func(*mgr.Service) error { return nil }) == nil
}
