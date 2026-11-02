// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package agent

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// Against a TrueNAS SCALE host, as root: ULRMM_LIVE=1 ./agent.test -test.run LiveTrueNAS -test.v

func liveTrueNAS(t *testing.T) {
	if os.Getenv("ULRMM_LIVE") != "1" || os.Geteuid() != 0 || !isTrueNAS() {
		t.Skip("set ULRMM_LIVE=1 and run as root on TrueNAS SCALE")
	}
	setNixLayout(true)
	t.Cleanup(func() { setNixLayout(false) })
}

func TestLiveTrueNASCollectors(t *testing.T) {
	liveTrueNAS(t)
	t.Logf("paths: conf %s, dir %s, main %s, mesh %s, mesh unit %s, rollback %s, tmp %s, log %s",
		etcConfig, nixAgentDir, nixMainBin, nixMeshAgentBin, nixMeshUnit, rollbackCopy, nixTmpDir, NixLogFile)
	t.Logf("init command: %s", trueNASInitCommand())
	a := &Agent{Logger: logrus.New(), Version: "live"}
	t.Logf("os: %s", a.osString())
	t.Logf("boot time: %s, total RAM: %v GB", time.Unix(a.BootTime(), 0).UTC(), a.TotalRAM())
	svcs, err := PosixServices()
	t.Logf("services: %d %v", len(svcs), err)
	t.Logf("processes: %d", len(a.GetProcsRPC()))
	w := a.GetWMIInfo()
	b, _ := json.Marshal(map[string]interface{}{"appliance": w["appliance"], "make_model": w["make_model"], "disks": w["disks"], "local_ips": w["local_ips"]})
	t.Logf("wmi: %s", b)
	if ap, ok := w["appliance"].(map[string]string); !ok || ap["name"] != "TrueNAS" || ap["version"] == "" {
		t.Fatalf("appliance %v", w["appliance"])
	}
	h, _ := json.Marshal(w["health"])
	t.Logf("health: %s", h)
	s, _ := json.Marshal(collectState(true))
	t.Logf("state: %s", s)
}

func TestLiveTrueNASInitTask(t *testing.T) {
	liveTrueNAS(t)
	count := func() int {
		tasks, err := trueNASInitTasks()
		if err != nil {
			t.Fatal(err)
		}
		return len(tasks)
	}
	if n := count(); n != 0 {
		t.Fatalf("%d rows before the test", n)
	}
	for i := 0; i < 2; i++ {
		if err := ensureTrueNASInitTask(); err != nil {
			t.Fatal(err)
		}
		if n := count(); n != 1 {
			t.Fatalf("run %d: %d rows", i+1, n)
		}
	}
	tasks, _ := trueNASInitTasks()
	t.Logf("row: %+v", tasks[0])
	if err := removeTrueNASInitTask(); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Fatalf("%d rows after remove", n)
	}
}

// TestCmdV2RunAsUser's script part in the real TrueNAS script dir
func TestLiveTrueNASRunAsUser(t *testing.T) {
	liveTrueNAS(t)
	u, err := lookupRunAs("nobody")
	if err != nil {
		t.Skip("no user nobody:", err)
	}
	a := testUpdateAgent()
	f, err := createNixTmpFile(a.UnixTmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("#!/bin/sh\nid -u\n")
	f.Close()
	os.Chmod(f.Name(), 0o770)
	os.Chown(f.Name(), int(u.uid), int(u.gid))
	st, _ := os.Stat(nixTmpDir)
	t.Logf("script %s, dir mode %v", f.Name(), st.Mode())
	opts := a.NewCMDOpts()
	opts.IsScript, opts.Shell = true, f.Name()
	opts.RunAsUser, opts.user = true, u
	if out := a.CmdV2(opts); out.Stdout != strconv.Itoa(int(u.uid))+"\n" {
		t.Fatalf("script as nobody: %+v", out)
	}
}
