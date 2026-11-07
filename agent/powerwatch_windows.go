// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/kardianos/service"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// Shutdown and restart reach the service as PRESHUTDOWN, before any service
// gets SHUTDOWN, so DNS and the network are still up; kardianos/service does
// not accept it. Sleep and the Fast Startup shutdown (session 0 hibernates,
// the service never stops) come through the powrprof suspend callback.

const (
	pbtAPMSuspend         = 0x4
	pbtAPMResumeSuspend   = 0x7
	pbtAPMResumeAutomatic = 0x12
	deviceNotifyCallback  = 2
	preShutdownBudget     = 6 * time.Second
	suspendBudget         = 1500 * time.Millisecond
)

var (
	procPowerRegisterSuspendResume = windows.NewLazySystemDLL("powrprof.dll").NewProc("PowerRegisterSuspendResumeNotification")
	powerConn                      atomic.Pointer[nats.Conn]
	// the system keeps a pointer to it
	powerSub *deviceNotifySubscribe
	// replaced in tests
	powerAnnounce      = (*Agent).announcePower
	powerShutdownEvent = shutdownEvent
)

// DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS
type deviceNotifySubscribe struct {
	Callback uintptr
	Context  uintptr
}

// RunService is -m svc. From a console it is the kardianos run: start,
// Ctrl+C, stop.
func (a *Agent) RunService() error {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		s, err := service.New(a, a.ServiceConfig)
		if err != nil {
			return err
		}
		return s.Run()
	}
	return svc.Run(winSvcName, &winService{
		start: func() { _ = a.Start(nil) },
		stop:  func() { _ = a.Stop(nil) },
		shutdown: func() {
			expectStop(a.dataDir())
			a.announceShutdown(preShutdownBudget)
		},
	})
}

// winService is the kardianos handler plus PRESHUTDOWN.
type winService struct {
	start, stop, shutdown func()
}

func (w *winService) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	w.start()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptPreShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.PreShutdown:
			s <- svc.Status{State: svc.StopPending, WaitHint: 8000}
			w.shutdown()
			w.stop()
			return false, 0
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			w.stop()
			return false, 0
		}
	}
	return false, 0
}

// announceShutdown tells restart from shutdown by the newest User32 1074.
func (a *Agent) announceShutdown(budget time.Duration) {
	nc := powerConn.Load()
	if nc == nil {
		return
	}
	kind, by := classify1074(powerShutdownEvent(10 * time.Minute))
	powerAnnounce(a, nc, kind, "os", by, budget)
}

// watchPower registers the suspend callback. Suspend waits for it, so the
// notice goes out before the network adapters power down.
func (a *Agent) watchPower(nc *nats.Conn) {
	powerConn.Store(nc)
	if err := procPowerRegisterSuspendResume.Find(); err != nil {
		a.Logger.Debugln("watchPower():", err)
		return
	}
	powerSub = &deviceNotifySubscribe{Callback: windows.NewCallback(func(_, typ, _ uintptr) uintptr {
		a.onPowerEvent(nc, typ)
		return 0
	})}
	var h uintptr
	if r, _, _ := procPowerRegisterSuspendResume.Call(deviceNotifyCallback, uintptr(unsafe.Pointer(powerSub)), uintptr(unsafe.Pointer(&h))); r != 0 {
		a.Logger.Errorln("watchPower(): PowerRegisterSuspendResumeNotification:", windows.Errno(r))
	}
}

func (a *Agent) onPowerEvent(nc *nats.Conn, typ uintptr) {
	switch typ {
	case pbtAPMSuspend:
		// a Fast Startup shutdown suspends too; its 1074 says power off
		kind, by := "sleep", ""
		if k, i := classify1074(powerShutdownEvent(2 * time.Minute)); k == "shutdown" {
			kind, by = k, i
		}
		powerAnnounce(a, nc, kind, "os", by, suspendBudget)
	case pbtAPMResumeSuspend, pbtAPMResumeAutomatic:
		// the next sleep needs its own notice; a Fast Startup boot is a
		// resume, the service never stopped
		// the cancel also drops the expected-stop marker
		go a.powerBack(nc)
	}
}

// shutdownEvent returns the inserts of the newest User32 1074 (shutdown or
// restart started) within window, nil without one or when a 1075 (aborted)
// came after it.
func shutdownEvent(window time.Duration) []string {
	h, err := openEventLog("System")
	if err != nil {
		return nil
	}
	defer evtCloseEventLog.Call(h)
	var ins []string
	readEventRecords(h, time.Now().Add(-window).Unix(), func(rec evtRecord) bool {
		if !strings.EqualFold(rec.Source, "User32") {
			return true
		}
		switch rec.EventID & 0xffff {
		case 1074:
			ins = rec.Inserts
			return false
		case 1075:
			return false
		}
		return true
	})
	return ins
}
