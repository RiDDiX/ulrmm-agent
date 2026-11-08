// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"
	"unicode/utf16"
)

func TestSvcTexts(t *testing.T) {
	states := map[uint32]string{1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
		5: "continue_pending", 6: "pause_pending", 7: "paused", 0: "unknown", 8: "unknown"}
	for in, want := range states {
		if got := svcStateText(in); got != want {
			t.Errorf("state %d: %q, want %q", in, got, want)
		}
	}
	types := map[uint32]string{0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled", 5: "Unknown"}
	for in, want := range types {
		if got := svcStartTypeText(in); got != want {
			t.Errorf("start type %d: %q, want %q", in, got, want)
		}
	}
}

func TestSvcStartRequest(t *testing.T) {
	cases := map[string]svcStartChange{
		"auto":      {startType: 2, setDelay: true},
		"autodelay": {startType: 2, setDelay: true, delay: true},
		"manual":    {startType: 3},
		"disabled":  {startType: 4},
	}
	for in, want := range cases {
		got, ok := svcStartRequest(in)
		if !ok || got != want {
			t.Errorf("%s: %+v %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "bogus", "Auto", "boot"} {
		if _, ok := svcStartRequest(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidTaskName(t *testing.T) {
	for _, ok := range []string{"ULRMM_abc", "ULRMM_SchedReboot_xYz", "name with space"} {
		if !validTaskName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "  ", `a\b`, "a/b", `\`, "x\x00", "a\nb", strings.Repeat("a", 201)} {
		if validTaskName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func dailyPlan() taskPlan {
	return taskPlan{Type: "rmm", Name: "ULRMM_t", Trigger: "daily", PK: 7, DayInterval: 1,
		Start: [5]int{2026, 10, 11, 13, 0}}
}

func TestTaskPlanCheck(t *testing.T) {
	ok := []func(p *taskPlan){
		func(p *taskPlan) {},
		func(p *taskPlan) { p.Trigger = "manual"; p.Start = [5]int{} },
		func(p *taskPlan) { p.Trigger = "onboarding"; p.Start = [5]int{} },
		func(p *taskPlan) { p.Trigger = "runonce" },
		func(p *taskPlan) { p.Trigger = "weekly"; p.WeekInterval = 2; p.DaysOfWeek = 2 | 32 },
		func(p *taskPlan) { p.Trigger = "monthly"; p.LastDayOfMonth = true; p.MonthsOfYear = 0xfff },
		func(p *taskPlan) {
			p.Trigger = "monthlydow"
			p.DaysOfWeek, p.MonthsOfYear, p.WeeksOfMonth = 1, 1, 16
		},
		// expiry at minute 0 is a real expiry
		func(p *taskPlan) { p.HasExpire = true; p.Expire = [5]int{2026, 12, 1, 13, 0} },
		func(p *taskPlan) { p.Type = "schedreboot" },
		func(p *taskPlan) { p.Type = "custom"; p.Path = `C:\x.exe` },
		func(p *taskPlan) { p.Policy = 3 },
	}
	for i, f := range ok {
		p := dailyPlan()
		f(&p)
		if err := p.check(); err != nil {
			t.Errorf("ok case %d: %v", i, err)
		}
	}
	bad := map[string]func(p *taskPlan){
		"unknown trigger":  func(p *taskPlan) { p.Trigger = "hourly" },
		"empty trigger":    func(p *taskPlan) { p.Trigger = "" },
		"unknown type":     func(p *taskPlan) { p.Type = "other" },
		"custom no path":   func(p *taskPlan) { p.Type = "custom" },
		"bad name":         func(p *taskPlan) { p.Name = `x\y` },
		"policy":           func(p *taskPlan) { p.Policy = 4 },
		"daily interval":   func(p *taskPlan) { p.DayInterval = 0 },
		"weekly no days":   func(p *taskPlan) { p.Trigger = "weekly"; p.WeekInterval = 1 },
		"weekly mask":      func(p *taskPlan) { p.Trigger = "weekly"; p.WeekInterval = 1; p.DaysOfWeek = 0x80 },
		"monthly no days":  func(p *taskPlan) { p.Trigger = "monthly"; p.MonthsOfYear = 1 },
		"monthly no month": func(p *taskPlan) { p.Trigger = "monthly"; p.DaysOfMonth = 1 },
		"dow no weeks":     func(p *taskPlan) { p.Trigger = "monthlydow"; p.DaysOfWeek, p.MonthsOfYear = 1, 1 },
		"feb 30":           func(p *taskPlan) { p.Start = [5]int{2026, 2, 30, 10, 0} },
		"no start":         func(p *taskPlan) { p.Start = [5]int{} },
		"minute 60":        func(p *taskPlan) { p.Start[4] = 60 },
		"bad expiry":       func(p *taskPlan) { p.HasExpire = true; p.Expire = [5]int{2026, 13, 1, 0, 0} },
	}
	for name, f := range bad {
		p := dailyPlan()
		f(&p)
		if err := p.check(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTaskPlanAction(t *testing.T) {
	p := dailyPlan()
	exe, dir, args := p.action(`C:\Program Files\ULRMM Agent`, `C:\Windows\`)
	if exe != IdentWinExe || dir != `C:\Program Files\ULRMM Agent` || args != "-m taskrunner -p 7" {
		t.Errorf("rmm: %q %q %q", exe, dir, args)
	}
	p.Type = "schedreboot"
	if exe, dir, args = p.action("", `C:\Windows\`); exe != "shutdown.exe" || dir != `C:\Windows\System32` || args != "/r /t 5 /f" {
		t.Errorf("reboot: %q %q %q", exe, dir, args)
	}
	p.Type, p.Path, p.WorkDir, p.Args = "custom", `C:\t\x.exe`, `C:\t`, "-a b"
	if exe, dir, args = p.action("", ""); exe != `C:\t\x.exe` || dir != `C:\t` || args != "-a b" {
		t.Errorf("custom: %q %q %q", exe, dir, args)
	}
}

func TestLocalTime(t *testing.T) {
	got, err := localTime([5]int{2026, 10, 11, 13, 5})
	if err != nil || !got.Equal(time.Date(2026, 10, 11, 13, 5, 0, 0, time.Local)) || got.Location() != time.Local {
		t.Fatalf("%v %v", got, err)
	}

	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Local
	time.Local = berlin
	defer func() { time.Local = old }()
	// 2027-03-28 02:30 does not exist there, 2027-10-31 02:30 exists twice
	if got, err := localTime([5]int{2027, 3, 28, 2, 30}); err != nil || got.Hour() != 3 {
		t.Fatalf("gap: %v %v", got, err)
	}
	if got, err := localTime([5]int{2027, 10, 31, 2, 30}); err != nil || got.Hour() != 2 || got.Minute() != 30 {
		t.Fatalf("overlap: %v %v", got, err)
	}
	for _, bad := range [][5]int{{2027, 2, 31, 10, 0}, {2027, 13, 1, 10, 0}, {2027, 0, 1, 10, 0}, {2027, 1, 1, 24, 0}, {2027, 1, 1, 10, 60}, {2027, 1, 1, -1, 0}, {0, 1, 1, 0, 0}} {
		if _, err := localTime(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func u16z(s string) []byte {
	var b []byte
	for _, c := range append(utf16.Encode([]rune(s)), 0) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// mkRecord lays out an EVENTLOGRECORD the way ReadEventLog returns it.
func mkRecord(num, written, id uint32, typ uint16, source string, inserts ...string) []byte {
	body := append(u16z(source), u16z("HOST")...)
	strOff := evtHeaderLen + len(body)
	for _, s := range inserts {
		body = append(body, u16z(s)...)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	length := evtHeaderLen + len(body) + 4
	h := make([]byte, evtHeaderLen)
	le := binary.LittleEndian
	le.PutUint32(h[0:], uint32(length))
	le.PutUint32(h[4:], evtSignature)
	le.PutUint32(h[8:], num)
	le.PutUint32(h[12:], written)
	le.PutUint32(h[16:], written)
	le.PutUint32(h[20:], id)
	le.PutUint16(h[24:], typ)
	le.PutUint16(h[26:], uint16(len(inserts)))
	le.PutUint32(h[36:], uint32(strOff))
	rec := append(h, body...)
	return le.AppendUint32(rec, uint32(length))
}

func TestParseEventRecords(t *testing.T) {
	a := mkRecord(9, 1700000000, 0x40001001, 4, "Service Control Manager", "Print Spooler", "running")
	b := mkRecord(8, 1699999000, 7036, 1, "Disk")
	recs, ok := parseEventRecords(append(append([]byte{}, a...), b...))
	if !ok || len(recs) != 2 {
		t.Fatalf("ok=%v recs=%+v", ok, recs)
	}
	r := recs[0]
	if r.Number != 9 || r.Written != 1700000000 || r.EventID != 0x40001001 || r.EventType != 4 ||
		r.Source != "Service Control Manager" || len(r.Inserts) != 2 || r.Inserts[1] != "running" {
		t.Errorf("first record %+v", r)
	}
	if recs[1].Source != "Disk" || len(recs[1].Inserts) != 0 {
		t.Errorf("second record %+v", recs[1])
	}

	// truncated second record: the first one is kept
	recs, ok = parseEventRecords(append(append([]byte{}, a...), b[:40]...))
	if ok || len(recs) != 1 {
		t.Errorf("truncated: ok=%v n=%d", ok, len(recs))
	}
	// length beyond the buffer, bad signature, zero length
	for name, mut := range map[string]func([]byte){
		"length": func(x []byte) { binary.LittleEndian.PutUint32(x, 1<<20) },
		"sig":    func(x []byte) { x[4] = 'X' },
		"zero":   func(x []byte) { binary.LittleEndian.PutUint32(x, 0) },
	} {
		x := append([]byte{}, a...)
		mut(x)
		if recs, ok := parseEventRecords(x); ok || len(recs) != 0 {
			t.Errorf("%s: ok=%v n=%d", name, ok, len(recs))
		}
	}
	// string offset outside the record and more strings than present
	x := append([]byte{}, a...)
	binary.LittleEndian.PutUint32(x[36:], 1<<30)
	if recs, ok := parseEventRecords(x); !ok || len(recs) != 1 || len(recs[0].Inserts) != 0 {
		t.Errorf("bad offset: %v %+v", ok, recs)
	}
	x = append([]byte{}, a...)
	binary.LittleEndian.PutUint16(x[26:], 500)
	if recs, ok := parseEventRecords(x); !ok || len(recs[0].Inserts) < 2 || recs[0].Inserts[1] != "running" ||
		strings.Join(recs[0].Inserts[2:], "") != "" {
		t.Errorf("string count: %v %+v", ok, recs)
	}
	if recs, ok := parseEventRecords(nil); !ok || len(recs) != 0 {
		t.Errorf("empty: %v %v", ok, recs)
	}
}

func FuzzParseEventRecords(f *testing.F) {
	f.Add(mkRecord(1, 2, 3, 4, "src", "a", "b"))
	f.Fuzz(func(t *testing.T, b []byte) { parseEventRecords(b) })
}

func TestEventHelpers(t *testing.T) {
	types := map[uint16]string{0: "SUCCESS", 1: "ERROR", 2: "WARNING", 4: "INFO", 8: "AUDIT_SUCCESS", 16: "AUDIT_FAILURE", 3: "Unknown"}
	for in, want := range types {
		if got := evtTypeText(in); got != want {
			t.Errorf("type %d: %q", in, got)
		}
	}
	if got := cleanEventMessage("line one\r\nline two\r\n\r\n"); got != "line one\nline two\n" {
		t.Errorf("clean: %q", got)
	}
	if got := splitModules(` C:\a.dll; ;C:\b.dll;`); len(got) != 2 || got[0] != `C:\a.dll` || got[1] != `C:\b.dll` {
		t.Errorf("split: %q", got)
	}
	lookup := func(id uint32) (string, bool) {
		if id == 1936 {
			return "Type 1", true
		}
		return "", false
	}
	cases := map[string]string{
		"no refs":                  "no refs",
		"Token: %%1936.":           "Token: Type 1.",
		"%%1936%%1936":             "Type 1Type 1",
		"unknown %%42 kept":        "unknown %%42 kept",
		"percent %% alone %%":      "percent %% alone %%",
		"big %%99999999999999 end": "big %%99999999999999 end",
	}
	for in, want := range cases {
		if got := expandParamRefs(in, lookup); got != want {
			t.Errorf("expand %q: %q", in, got)
		}
	}
	for _, ok := range []string{"Application", "System", "Security", "Windows PowerShell"} {
		if !validLogName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", " ", `System\x`, "a/b", "a\x00"} {
		if validLogName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if eventLogBudget(30) != 29*time.Second || eventLogBudget(180) != 179*time.Second || eventLogBudget(0) != 0 {
		t.Error("budget")
	}
}

func TestWuaBounded(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	began := time.Now()
	err := wuaBounded(20*time.Millisecond, func() error { <-release; return nil })
	if err == nil || !strings.Contains(err.Error(), "did not finish") || time.Since(began) > time.Second {
		t.Fatal("hung worker:", err, time.Since(began))
	}
	want := errors.New("windows update is busy")
	if err := wuaBounded(time.Second, func() error { return want }); err != want {
		t.Fatal("worker error:", err)
	}
	err = wuaBounded(time.Second, func() error { var m map[string]bool; m["x"] = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatal("worker panic:", err)
	}
}
