// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build freebsd

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/sirupsen/logrus"
)

func rmmCheck(name string) rmm.CheckDef { return rmm.CheckDef{Svc: name} }

// Against the running system, as root: ULRMM_LIVE=1 ./agent.test -test.run Live -test.v

func liveOnly(t *testing.T) {
	if os.Getenv("ULRMM_LIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set ULRMM_LIVE=1 and run as root")
	}
}

func logJSON(t *testing.T, what string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	t.Logf("%s: %s", what, b)
}

func TestLiveCollectors(t *testing.T) {
	liveOnly(t)
	a := &Agent{Logger: logrus.New(), Version: "live"}
	t.Logf("os: %s", a.osString())
	t.Logf("boot time: %s, total RAM: %v GB", time.Unix(a.BootTime(), 0).UTC(), a.TotalRAM())
	reboot, err := a.SystemRebootRequired()
	t.Logf("reboot required: %v %v", reboot, err)
	t.Logf("logged on user: %s", a.LoggedOnUser())
	idle, err := UserIdle()
	t.Logf("idle: %d %v", idle, err)
	t.Logf("keep awake: %v", KeepAwake(time.Now().Add(time.Hour).Unix()))

	procs := a.GetProcsRPC()
	if len(procs) < 10 {
		t.Fatalf("%d processes", len(procs))
	}
	logJSON(t, "first processes", procs[:5])

	svcs, err := PosixServices()
	if err != nil {
		t.Fatal(err)
	}
	running := 0
	for _, s := range svcs {
		if s.State == "running" {
			running++
		}
	}
	t.Logf("services: %d, running: %d", len(svcs), running)
	for _, s := range svcs {
		if s.Unit == "sshd" || s.Unit == "ntpd" || s.Unit == "zfs" {
			logJSON(t, "service", s)
		}
	}
	for name, want := range map[string]string{"sshd": "passing active/running", "sshd.service": "passing active/running", "nosuchd": "failing service nosuchd not found"} {
		st, info := systemdUnitCheck(rmmCheck(name))
		t.Logf("service check %s: %s %s", name, st, info)
		if st+" "+info != want {
			t.Fatalf("want %q", want)
		}
	}

	logJSON(t, "disks", a.GetDisks())
	start := time.Now()
	logJSON(t, "state", collectState(true))
	t.Logf("state took %s", time.Since(start))
	start = time.Now()
	logJSON(t, "wmi", a.GetWMIInfo())
	t.Logf("wmi took %s", time.Since(start))

	self, _ := os.Executable()
	t.Logf("checkExecFormat(self, freebsd): %v", checkExecFormat(self, "freebsd", "amd64"))
	t.Logf("checkExecFormat(self, linux): %v", checkExecFormat(self, "linux", "amd64"))
}

// rc.d service, cron job and the agent's uninstall steps for a stand-in under
// another name; the mesh steps are left out, they would hit a real install
func TestLiveRcdService(t *testing.T) {
	liveOnly(t)
	oldSvc, oldLog := IdentNixSvc, NixLogFile
	dir := t.TempDir()
	defer func() {
		IdentNixSvc, NixLogFile = oldSvc, oldLog
		setNixLayout(false)
	}()
	IdentNixSvc = "rmm-live.service"
	nixAgentDir, etcConfig, nixMeshDir = filepath.Join(dir, "data"), filepath.Join(dir, "conf"), filepath.Join(dir, "mesh")
	nixMainBin, NixLogFile = filepath.Join(dir, "rmm-live"), filepath.Join(dir, "log")
	os.MkdirAll(nixAgentDir, 0o755)
	os.WriteFile(etcConfig, []byte("{}"), 0o600)
	os.WriteFile(nixMainBin, []byte("#!/bin/sh\necho \"$$ $*\" >> "+dir+"/runs\nwhile :; do sleep 1; done\n"), 0o755)

	p := freebsdHeal{}
	if inst, run := p.serviceState(); inst || run {
		t.Fatalf("before: %v %v", inst, run)
	}
	if err := p.ensureService(nixMainBin); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if inst, run := p.serviceState(); !inst || !run {
		t.Fatalf("after ensureService: %v %v", inst, run)
	}
	if err := p.registerSchedule(filepath.Join(nixAgentDir, "selfheal", "rmm-live")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(healCronPath())
	t.Logf("%s:\n%s", healCronPath(), b)
	if err := p.restartService(); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Logger: logrus.New()}
	if err := a.restartAgentService(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	runs, _ := os.ReadFile(filepath.Join(dir, "runs"))
	t.Logf("runs:\n%s", runs)
	if n := strings.Count(string(runs), "-m svc"); n != 3 {
		t.Fatalf("%d starts", n)
	}

	if err := p.removeSchedule(); err != nil {
		t.Fatal(err)
	}
	for _, s := range uninstallPlan("freebsd", nil) {
		if strings.Contains(strings.Join(s.argv, " ")+s.remove, "meshagent") {
			continue
		}
		if s.remove != "" {
			os.RemoveAll(s.remove)
		} else if out, err := healCmd(s.timeout, s.argv[0], s.argv[1:]...); err != nil {
			t.Logf("%s: %v %s", strings.Join(s.argv, " "), err, out)
		}
	}
	if inst, run := p.serviceState(); inst || run {
		t.Fatalf("after uninstall: %v %v", inst, run)
	}
	for _, f := range []string{rcScriptPath(), healCronPath(), nixMainBin, nixAgentDir, etcConfig} {
		if healFileExists(f) {
			t.Fatalf("%s left", f)
		}
	}
	if out, _ := healCmd(time.Minute, "sysrc", "-n", rcName()+"_enable"); strings.TrimSpace(out) == "YES" {
		t.Fatal("rc.conf still enables it")
	}
}

// The update restart from inside the supervised process: the rc script must
// finish the start after the stop has ended its caller.
func TestLiveSelfRestart(t *testing.T) {
	liveOnly(t)
	dir := t.TempDir()
	self, _ := os.Executable()
	oldSvc := IdentNixSvc
	defer func() { IdentNixSvc = oldSvc }()
	IdentNixSvc = "rmm-restart.service"
	wrapper := filepath.Join(dir, "agent")
	os.WriteFile(wrapper, []byte("#!/bin/sh\nexec env ULRMM_RESTART_CHILD="+dir+" IDENT="+rcName()+" "+self+" -test.run TestLiveRestartChild\n"), 0o755)
	p := freebsdHeal{}
	if err := p.ensureService(wrapper); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = healCmd(time.Minute, "service", rcName(), "onestop")
		_, _ = healCmd(time.Minute, "sysrc", "-x", rcName()+"_enable")
		os.Remove(rcScriptPath())
	}()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(filepath.Join(dir, "log")); strings.Contains(string(b), "second start") {
			t.Logf("child log:\n%s", b)
			return
		}
		time.Sleep(time.Second)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "log"))
	t.Fatalf("no second start:\n%s", b)
}

func TestLiveRestartChild(t *testing.T) {
	dir := os.Getenv("ULRMM_RESTART_CHILD")
	if dir == "" {
		t.Skip("runs under the rc service of TestLiveSelfRestart")
	}
	IdentNixSvc = strings.ReplaceAll(os.Getenv("IDENT"), "_", "-") + ".service"
	logf := func(s string) {
		f, _ := os.OpenFile(filepath.Join(dir, "log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		f.WriteString(s + "\n")
		f.Close()
	}
	marker := filepath.Join(dir, "restarted")
	if healFileExists(marker) {
		logf("second start, pid " + strconv.Itoa(os.Getpid()))
		select {}
	}
	os.WriteFile(marker, nil, 0o600)
	logf("first start, pid " + strconv.Itoa(os.Getpid()) + ", restarting")
	a := &Agent{Logger: logrus.New()}
	err := a.restartAgentService()
	logf(fmt.Sprintf("restartAgentService returned %v (the stop should have ended this process)", err))
	select {}
}
