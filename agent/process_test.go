// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestParseCPUTime(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"0:00.25":    250 * time.Millisecond,
		"27:41.19":   27*time.Minute + 41190*time.Millisecond,
		"123:00.00":  123 * time.Minute,
		"01:02:03":   time.Hour + 2*time.Minute + 3*time.Second,
		"2-01:00:00": 49 * time.Hour,
		"1:02,50":    62500 * time.Millisecond,
		"garbage":    0,
	} {
		if got := parseCPUTime(in); got.Round(time.Millisecond) != want {
			t.Errorf("parseCPUTime(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParsePs(t *testing.T) {
	out := `    0     0      0 105:12.00 kernel_task
    1     0  12345   3:01.50 /sbin/launchd
  620    88 200000   1:00.00 /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer
85801   501 512000   0:10.00 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  777   270     64   0:00.01 7zip helper
broken line
`
	got := parsePs(out, func(uid string) string { return "u" + uid })
	if _, ok := got[0]; ok {
		t.Error("pid 0 must be left out")
	}
	want := map[int]procSample{
		1:     {name: "launchd", user: "u0", mem: 12345 * 1024, cpu: 3*time.Minute + 1500*time.Millisecond},
		620:   {name: "WindowServer", user: "u88", mem: 200000 * 1024, cpu: time.Minute},
		85801: {name: "Google Chrome", user: "u501", mem: 512000 * 1024, cpu: 10 * time.Second},
		777:   {name: "7zip helper", user: "u270", mem: 64 * 1024, cpu: 10 * time.Millisecond},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d processes, want %d: %+v", len(got), len(want), got)
	}
	for pid, w := range want {
		g := got[pid]
		g.cpu = g.cpu.Round(time.Millisecond)
		if g != w {
			t.Errorf("pid %d = %+v, want %+v", pid, g, w)
		}
	}
}

func TestProcMsgs(t *testing.T) {
	prev := map[int]procSample{
		10: {name: "busy", cpu: 10 * time.Second},
		11: {name: "old", cpu: 50 * time.Second},
		15: {name: "kworker/1:0-events", cpu: 30 * time.Second},
		16: {name: "svchost.exe", cpu: time.Second, start: 1},
		12: {name: "idle", cpu: time.Second},
	}
	cur := map[int]procSample{
		10: {name: "busy", user: "root", mem: 2048, cpu: 12 * time.Second}, // 2 s of 4 cores over 1 s
		11: {name: "reused", cpu: 500 * time.Millisecond},                  // pid reused by a new process
		12: {name: "idle", cpu: time.Second},
		13: {name: "new", cpu: 100 * time.Millisecond},
		14: {name: "hog", cpu: 9 * time.Second},
		15: {name: "kworker/1:0-mm_percpu_wq", cpu: 30*time.Second + 40*time.Millisecond},
		16: {name: "svchost.exe", cpu: 2 * time.Second, start: 2}, // reused, more CPU than the old one
	}
	msgs := procMsgs(prev, cur, time.Second, 4)
	want := map[int]string{10: "50.0", 11: "12.5", 12: "0.0", 13: "2.5", 14: "100.0", 15: "1.0", 16: "50.0"}
	if len(msgs) != len(want) {
		t.Fatalf("got %d rows, want %d", len(msgs), len(want))
	}
	for i, m := range msgs {
		if m.RowID != i || (i > 0 && msgs[i-1].PID > m.PID) {
			t.Errorf("row %d: id %d pid %d not in pid order", i, m.RowID, m.PID)
		}
		if m.CPUPct != want[m.PID] {
			t.Errorf("pid %d cpu %s, want %s", m.PID, m.CPUPct, want[m.PID])
		}
	}
	if msgs[0].ProcName != "busy" || msgs[0].Owner != "root" || msgs[0].RSSBytes != 2048 {
		t.Errorf("row 0 = %+v", msgs[0])
	}
}

func TestGetProcsRPCReusesRecentAnswer(t *testing.T) {
	a := &Agent{Logger: logrus.New()}
	first := a.GetProcsRPC()
	if len(first) == 0 {
		t.Fatal("no processes")
	}
	start := time.Now()
	second := a.GetProcsRPC()
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Errorf("second request took %v, want the cached answer", took)
	}
	if len(second) != len(first) || &second[0] != &first[0] {
		t.Error("second request inside the window did not return the previous answer")
	}
}
