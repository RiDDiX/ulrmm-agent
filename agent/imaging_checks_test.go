// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	nats "github.com/nats-io/nats.go"
)

func TestChecksVSSFixArgvSafe(t *testing.T) {
	want := []string{`C:\Windows\System32\sc.exe`, "config", "VSS", "start=", "demand"}
	for _, level := range []string{"safe", "all"} {
		var ran [][]string
		run := func(argv []string) error { ran = append(ran, argv); return nil }
		c := imagingServiceCheck("win.vss_service", "VSS", true, nil, level, run, 42)
		if len(ran) != 1 || !slices.Equal(ran[0], want) || !slices.Equal(c.FixArgv, want) {
			t.Fatalf("%s: ran %q, fix_argv %q", level, ran, c.FixArgv)
		}
		if c.State != "fixed" || c.FixedAt == nil || *c.FixedAt != 42 || c.Fix != strings.Join(want, " ") {
			t.Fatalf("%s: %+v", level, c)
		}
		if c := imagingServiceCheck("win.vss_service", "VSS", false, nil, level, run, 42); c.State != "ok" || len(ran) != 1 {
			t.Fatalf("%s: an enabled service was touched: %+v", level, c)
		}
	}
	failing := func([]string) error { return errors.New("access denied") }
	if c := imagingServiceCheck("win.swprv_service", "swprv", true, nil, "safe", failing, 1); c.State != "failed" || !c.Blocking || c.FixedAt != nil {
		t.Fatalf("a failed fix: %+v", c)
	}
}

func TestChecksOffNoFix(t *testing.T) {
	ran := false
	run := func([]string) error { ran = true; return nil }
	var none imagingConfig
	for _, level := range []string{"off", none.autoSetup()} {
		c := imagingServiceCheck("win.swprv_service", "swprv", true, nil, level, run, 1)
		if ran || c.State != "missing" || !c.Blocking || c.Fix != "Set the swprv service start type to Manual." || c.FixedAt != nil {
			t.Fatalf("%q: ran %v, %+v", level, ran, c)
		}
	}
	if c := imagingServiceCheck("win.vss_service", "VSS", false, errors.New("gone"), "safe", run, 1); ran || c.State != "failed" || c.Blocking {
		t.Fatalf("an unreadable service: %+v", c)
	}
}

func TestLinuxToolsManualCommand(t *testing.T) {
	has := func(names ...string) func(string) bool {
		return func(n string) bool { return slices.Contains(names, n) }
	}
	if c := imagingToolsCheck(has("lsblk", "blkid", "dumpe2fs"), true); c.State != "ok" {
		t.Fatalf("all tools: %+v", c)
	}
	if c := imagingToolsCheck(has("lsblk", "blkid"), false); c.State != "ok" {
		t.Fatalf("dumpe2fs asked for without ext4: %+v", c)
	}
	if c := imagingToolsCheck(has("lsblk"), false); c.State != "manual" || c.Detail != "Missing tools: blkid." {
		t.Fatalf("without ext4: %+v", c)
	}
	for manager, fix := range map[string]string{
		"apt-get": "apt-get install -y util-linux e2fsprogs",
		"dnf":     "dnf install -y util-linux e2fsprogs",
		"zypper":  "zypper --non-interactive install util-linux e2fsprogs",
		"pacman":  "pacman -S --noconfirm util-linux e2fsprogs",
		"":        "Install util-linux and e2fsprogs.",
	} {
		c := imagingToolsCheck(has("lsblk", manager), true)
		if c.State != "manual" || !c.Blocking || c.Fix != fix || c.Detail != "Missing tools: blkid, dumpe2fs." || c.FixArgv != nil {
			t.Fatalf("%q: %+v", manager, c)
		}
	}
}

func TestSmartCheckPolicy(t *testing.T) {
	bad := []HDisk{{Name: "sda", Health: "ok", Smart: "passed"}, {Name: "sdb", Health: "warning", Smart: "passed"}, {Name: "nvme0", Health: "unknown", Smart: "failed"}}
	detail := "sdb: health warning, SMART passed; nvme0: health unknown, SMART failed"
	for smart, want := range map[string]imagingCheck{
		"warn":  {State: "failed", Blocking: false, Detail: detail},
		"abort": {State: "failed", Blocking: true, Detail: detail},
		"off":   {State: "ok"},
	} {
		c := imagingSmartCheck(bad, smart)
		if c.ID != "smart.source" || c.State != want.State || c.Blocking != want.Blocking || c.Detail != want.Detail {
			t.Fatalf("%s: %+v", smart, c)
		}
	}
	if c := imagingSmartCheck(bad[:1], "abort"); c.State != "ok" {
		t.Fatalf("healthy disks: %+v", c)
	}
}

func TestNativeArchCheck(t *testing.T) {
	for _, c := range []struct {
		goarch, os, state string
	}{{"386", "x64", "missing"}, {"386", "arm64", "missing"}, {"386", "x86", "ok"}, {"amd64", "x64", "ok"}, {"amd64", "arm64", "ok"}} {
		if got := imagingArchCheck(c.goarch, c.os); got.State != c.state || !got.Blocking {
			t.Errorf("%s on %s: %+v", c.goarch, c.os, got)
		}
	}
}

func TestCheckListShape(t *testing.T) {
	reason := strings.Repeat("x", 600)
	list := imagingCheckList(ImagingCapability{Method: "linux-files-v1", Reason: reason}, nil, "warn", []imagingCheck{{ID: "linux.tools.base", State: "ok"}}, 7)
	if len(list) != 3 || list[0].ID != "method.linux-files-v1" || list[0].State != "missing" || !list[0].Blocking || len(list[0].Detail) != imagingTextMax {
		t.Fatalf("%+v", list)
	}
	for _, c := range list {
		if c.ObservedAt != 7 || c.FixArgv == nil {
			t.Fatalf("%+v", c)
		}
	}
	if list := imagingCheckList(ImagingCapability{Method: "m", Ready: true}, nil, "warn", nil, 7); list[0].State != "ok" || list[1].ID != "smart.source" {
		t.Fatalf("%+v", list)
	}
}

func TestLinuxToolsThroughPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux.tools.base is a Linux check")
	}
	dir := t.TempDir()
	for _, tool := range []string{"lsblk", "blkid"} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	probe := func(fs string) func() ImagingCapability {
		return func() ImagingCapability { return ImagingCapability{Volumes: []ImagingVolume{{Mount: "/", FS: fs}}} }
	}
	if _, checks := imagingOSChecks("safe", 1, probe("xfs")); len(checks) != 1 || checks[0].State != "ok" {
		t.Fatalf("tools on PATH, no ext4: %+v", checks)
	}
	if _, checks := imagingOSChecks("safe", 1, probe("ext4")); checks[0].State != "manual" || checks[0].Detail != "Missing tools: dumpe2fs." {
		t.Fatalf("ext4 without dumpe2fs: %+v", checks)
	}
}

func TestImagingCheckRPC(t *testing.T) {
	probes := stubImagingProbe(t)
	drainImagingWake()
	r := &rpcReq{a: testUpdateAgent(), msg: &nats.Msg{}, p: &NatsMsg{Func: "imagingcheck"}}
	r.run()
	if !r.replied || probes.calls != 1 {
		t.Fatalf("replied %v, probes %d", r.replied, probes.calls)
	}
	select {
	case <-imagingWake:
	default:
		t.Fatal("the poll was not woken")
	}
}

// probeStub stands in for the probe: it counts calls, records the level it
// was given and returns the capability and checks set on it.
type probeStub struct {
	calls    int
	level    string
	notReady bool
	checks   []imagingCheck
	during   func(*Agent)
}

func stubImagingProbe(t *testing.T) *probeStub {
	st := &probeStub{}
	old := imagingRunProbe
	imagingRunProbe = func(_ context.Context, a *Agent, autoSetup, _ string) (ImagingCapability, []imagingCheck) {
		st.calls++
		st.level = autoSetup
		if st.during != nil {
			st.during(a)
		}
		return ImagingCapability{Method: "m", Ready: !st.notReady}, slices.Clone(st.checks)
	}
	t.Cleanup(func() { imagingRunProbe = old })
	return st
}

func drainImagingWake() {
	select {
	case <-imagingWake:
	default:
	}
}
