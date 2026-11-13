// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
)

func runExecute(t *testing.T, cmd svc.Cmd) (calls []string, states []svc.Status, exitSvc bool, code uint32) {
	t.Helper()
	w := &winService{
		start:    func() { calls = append(calls, "start") },
		stop:     func() { calls = append(calls, "stop") },
		shutdown: func() { calls = append(calls, "shutdown") },
	}
	r := make(chan svc.ChangeRequest, 2)
	s := make(chan svc.Status, 8)
	r <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
	r <- svc.ChangeRequest{Cmd: cmd}
	exitSvc, code = w.Execute(nil, r, s)
	close(s)
	for st := range s {
		states = append(states, st)
	}
	return
}

func TestWinServiceExecute(t *testing.T) {
	calls, states, exitSvc, code := runExecute(t, svc.PreShutdown)
	if exitSvc || code != 0 {
		t.Fatalf("preshutdown: exit %v %d, want false 0", exitSvc, code)
	}
	if want := "start shutdown stop"; strings.Join(calls, " ") != want {
		t.Fatalf("preshutdown: calls %q, want %q", strings.Join(calls, " "), want)
	}
	if len(states) != 4 || states[1].Accepts != svc.AcceptStop|svc.AcceptPreShutdown || states[2].State != svc.Running {
		t.Fatalf("preshutdown: states %+v", states)
	}
	if last := states[3]; last.State != svc.StopPending || last.WaitHint == 0 {
		t.Fatalf("preshutdown: last state %+v, want StopPending with a wait hint", last)
	}

	calls, states, exitSvc, code = runExecute(t, svc.Stop)
	if exitSvc || code != 0 || strings.Join(calls, " ") != "start stop" {
		t.Fatalf("stop: exit %v %d calls %q, want false 0 \"start stop\"", exitSvc, code, strings.Join(calls, " "))
	}
	if last := states[len(states)-1]; last.State != svc.StopPending {
		t.Fatalf("stop: last state %+v", last)
	}
}

func TestOnPowerEvent(t *testing.T) {
	type sent struct {
		kind, source, by string
		budget           time.Duration
	}
	var got []sent
	var window time.Duration
	event := []string(nil)
	resumes := 0
	oldAnnounce, oldEvent, oldResume, oldConn := powerAnnounce, powerShutdownEvent, powerResume, powerConn.Load()
	defer func() {
		powerAnnounce, powerShutdownEvent, powerResume = oldAnnounce, oldEvent, oldResume
		powerConn.Store(oldConn)
	}()
	powerResume = func(*Agent, *nats.Conn) { resumes++ }
	powerAnnounce = func(_ *Agent, _ *nats.Conn, kind, source, initiator string, budget time.Duration) error {
		got = append(got, sent{kind, source, initiator, budget})
		return nil
	}
	powerShutdownEvent = func(w time.Duration) []string { window = w; return event }
	a := &Agent{Logger: logrus.New()}
	by := `NT AUTHORITY\SYSTEM, shutdown.exe, Other (Planned), patch day`
	for _, c := range []struct {
		name   string
		typ    uintptr
		event  []string
		want   sent
		window time.Duration
	}{
		{"sleep", pbtAPMSuspend, nil, sent{"sleep", "os", "", suspendBudget}, 2 * time.Minute},
		{"suspend after a restart 1074", pbtAPMSuspend, ins1074("restart"), sent{"sleep", "os", "", suspendBudget}, 2 * time.Minute},
		{"fast startup shutdown", pbtAPMSuspend, ins1074("power off"), sent{"shutdown", "os", by, suspendBudget}, 2 * time.Minute},
	} {
		got, event = nil, c.event
		a.onPowerEvent(nil, c.typ)
		if len(got) != 1 || got[0] != c.want || window != c.window {
			t.Errorf("%s: sent %+v (window %v), want %+v (window %v)", c.name, got, window, c.want, c.window)
		}
	}

	got = nil
	a.onPowerEvent(nil, 0xA) // PBT_POWERSETTINGCHANGE
	if len(got) != 0 || resumes != 0 {
		t.Errorf("other type: sent %+v, %d resumes", got, resumes)
	}

	// a user-triggered wake sends PBT_APMRESUMEAUTOMATIC and then
	// PBT_APMRESUMESUSPEND (0x7): one resume
	a.onPowerEvent(nil, pbtAPMResumeAutomatic)
	a.onPowerEvent(nil, 0x7)
	if len(got) != 0 || resumes != 1 {
		t.Errorf("resume: sent %+v, %d resumes, want 1", got, resumes)
	}

	// preshutdown: nothing without a connection, then the 1074 decides
	powerConn.Store(nil)
	a.announceShutdown(preShutdownBudget)
	if len(got) != 0 {
		t.Errorf("no connection: sent %+v", got)
	}
	powerConn.Store(&nats.Conn{})
	event = ins1074("Neu starten")
	a.announceShutdown(preShutdownBudget)
	if want := (sent{"restart", "os", by, preShutdownBudget}); len(got) != 1 || got[0] != want || window != 10*time.Minute {
		t.Errorf("preshutdown: sent %+v (window %v), want %+v", got, window, want)
	}
}
