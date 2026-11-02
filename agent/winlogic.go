// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Services, scheduled tasks and the event log with no Windows API,
// so the Linux test run covers them.

// svcStateText maps SERVICE_STATUS.dwCurrentState to the text the server
// and the service check compare against.
var (
	svcStateNames     = [...]string{1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running", 5: "continue_pending", 6: "pause_pending", 7: "paused"}
	svcStartTypeNames = [...]string{"Boot", "System", "Automatic", "Manual", "Disabled"}
)

func svcStateText(state uint32) string {
	if state < uint32(len(svcStateNames)) && svcStateNames[state] != "" {
		return svcStateNames[state]
	}
	return "unknown"
}

func svcStartTypeText(startType uint32) string {
	if startType < uint32(len(svcStartTypeNames)) {
		return svcStartTypeNames[startType]
	}
	return "Unknown"
}

// svcStartChange is what editwinsvc changes: the start type always, the
// delayed-auto-start flag only when setDelay is true.
type svcStartChange struct {
	startType uint32
	setDelay  bool
	delay     bool
}

func svcStartRequest(s string) (svcStartChange, bool) {
	switch s {
	case "auto":
		return svcStartChange{startType: 2, setDelay: true}, true
	case "autodelay":
		return svcStartChange{startType: 2, setDelay: true, delay: true}, true
	case "manual":
		return svcStartChange{startType: 3}, true
	case "disabled":
		return svcStartChange{startType: 4}, true
	}
	return svcStartChange{}, false
}

// taskPlan carries the fields of a SchedTask request that decide whether
// the task can be built at all.
type taskPlan struct {
	Type, Name, Trigger string
	PK                  int
	Path, WorkDir, Args string
	DayInterval         uint8
	WeekInterval        uint8
	DaysOfWeek          uint16
	DaysOfMonth         uint32
	LastDayOfMonth      bool
	MonthsOfYear        uint16
	WeeksOfMonth        uint8
	Policy              uint
	Start, Expire       [5]int // year, month, day, hour, minute
	HasExpire           bool
}

const (
	maskDaysOfWeek  = 0x7f
	maskDaysOfMonth = 0x7fffffff
	maskMonths      = 0xfff
	maskWeeks       = 0x1f
)

// validTaskName accepts a plain task name in the root folder.
func validTaskName(name string) bool {
	if strings.TrimSpace(name) == "" || len(name) > 200 {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`\/:*?"<>|`, r) {
			return false
		}
	}
	return true
}

// localTime builds the y/m/d/h/min fields at second 0 in local time and
// refuses values time.Date would silently roll over.
func localTime(f [5]int) (time.Time, error) {
	t := time.Date(f[0], time.Month(f[1]), f[2], f[3], f[4], 0, 0, time.Local)
	if f[0] < 1 || t.Year() != f[0] || int(t.Month()) != f[1] || t.Day() != f[2] || t.Hour() != f[3] || t.Minute() != f[4] {
		return time.Time{}, fmt.Errorf("invalid date %04d-%02d-%02d %02d:%02d", f[0], f[1], f[2], f[3], f[4])
	}
	return t, nil
}

func (p taskPlan) check() error {
	if !validTaskName(p.Name) {
		return errors.New("invalid task name")
	}
	switch p.Type {
	case "rmm", "schedreboot":
	case "custom":
		if strings.TrimSpace(p.Path) == "" {
			return errors.New("custom task without a path")
		}
	default:
		return errors.New("unknown task type")
	}
	if p.Policy > 3 {
		return errors.New("unknown multiple instances policy")
	}
	switch p.Trigger {
	case "manual", "onboarding":
		return nil
	case "runonce":
	case "daily":
		if p.DayInterval == 0 {
			return errors.New("daily task without a day interval")
		}
	case "weekly":
		if p.WeekInterval == 0 || p.DaysOfWeek == 0 || p.DaysOfWeek > maskDaysOfWeek {
			return errors.New("weekly task needs days of week and a week interval")
		}
	case "monthly":
		if (p.DaysOfMonth == 0 && !p.LastDayOfMonth) || p.DaysOfMonth > maskDaysOfMonth ||
			p.MonthsOfYear == 0 || p.MonthsOfYear > maskMonths {
			return errors.New("monthly task needs days and months")
		}
	case "monthlydow":
		if p.DaysOfWeek == 0 || p.DaysOfWeek > maskDaysOfWeek || p.MonthsOfYear == 0 ||
			p.MonthsOfYear > maskMonths || p.WeeksOfMonth == 0 || p.WeeksOfMonth > maskWeeks {
			return errors.New("monthly task needs days of week, weeks and months")
		}
	default:
		return errors.New("unknown trigger")
	}
	if _, err := localTime(p.Start); err != nil {
		return err
	}
	if p.HasExpire {
		if _, err := localTime(p.Expire); err != nil {
			return err
		}
	}
	return nil
}

func (p taskPlan) action(programDir, systemRoot string) (exe, dir, args string) {
	switch p.Type {
	case "rmm":
		return IdentWinExe, programDir, "-m taskrunner -p " + strconv.Itoa(p.PK)
	case "schedreboot":
		return "shutdown.exe", strings.TrimRight(systemRoot, `\`) + `\System32`, "/r /t 5 /f"
	}
	return p.Path, p.WorkDir, p.Args
}

const (
	evtHeaderLen = 56         // fixed part of EVENTLOGRECORD
	evtSignature = 0x654c664c // "LfLe"
)

type evtRecord struct {
	Number    uint32
	Written   uint32 // seconds since 1970, UTC
	EventID   uint32
	EventType uint16
	Source    string
	Inserts   []string
}

// utf16z reads a NUL-terminated UTF-16LE string from b; ok is false when
// b holds no terminator.
func utf16z(b []byte) (s string, n int, ok bool) {
	u := make([]uint16, 0, 32)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			return string(utf16.Decode(u)), i + 2, true
		}
		u = append(u, c)
	}
	return "", 0, false
}

// parseEventRecords walks the records ReadEventLog put into buf. ok is
// false when a record header did not fit; the records before it are kept.
func parseEventRecords(buf []byte) (recs []evtRecord, ok bool) {
	le := binary.LittleEndian
	for off := 0; off < len(buf); {
		rest := buf[off:]
		if len(rest) < evtHeaderLen {
			return recs, false
		}
		length := int(le.Uint32(rest[0:]))
		if length < evtHeaderLen || length > len(rest) || le.Uint32(rest[4:]) != evtSignature {
			return recs, false
		}
		rec := rest[:length]
		r := evtRecord{
			Number:    le.Uint32(rec[8:]),
			Written:   le.Uint32(rec[16:]),
			EventID:   le.Uint32(rec[20:]),
			EventType: le.Uint16(rec[24:]),
		}
		r.Source, _, _ = utf16z(rec[evtHeaderLen:])
		// strings end where the event data starts, else before the
		// trailing length copy
		end := length - 4
		if d := int(le.Uint32(rec[52:])); le.Uint32(rec[48:]) > 0 && d >= evtHeaderLen && d < end {
			end = d
		}
		num := int(le.Uint16(rec[26:]))
		pos := int(le.Uint32(rec[36:]))
		for i := 0; i < num && pos >= evtHeaderLen && pos < end; i++ {
			s, n, found := utf16z(rec[pos:end])
			if !found {
				break
			}
			r.Inserts = append(r.Inserts, s)
			pos += n
		}
		recs = append(recs, r)
		off += length
	}
	return recs, true
}

var evtTypeNames = map[uint16]string{0: "SUCCESS", 1: "ERROR", 2: "WARNING", 4: "INFO", 8: "AUDIT_SUCCESS", 16: "AUDIT_FAILURE"}

func evtTypeText(t uint16) string {
	if name, ok := evtTypeNames[t]; ok {
		return name
	}
	return "Unknown"
}

// cleanEventMessage drops CR characters and one trailing LF.
func cleanEventMessage(s string) string {
	return strings.TrimSuffix(strings.ReplaceAll(s, "\r", ""), "\n")
}

// splitModules splits a message file value (a semicolon list) into paths.
func splitModules(v string) []string {
	var ret []string
	for _, p := range strings.Split(v, ";") {
		if p = strings.TrimSpace(p); p != "" {
			ret = append(ret, p)
		}
	}
	return ret
}

// expandParamRefs replaces %%nnnn references with the text lookup returns
// for nnnn; unknown references stay as they are.
func expandParamRefs(s string, lookup func(id uint32) (string, bool)) string {
	if !strings.Contains(s, "%%") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "%%")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := i + 2
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		b.WriteString(s[:i])
		txt, ok := "", false
		if id, err := strconv.ParseUint(s[i+2:j], 10, 32); err == nil {
			txt, ok = lookup(uint32(id))
		}
		if !ok {
			txt = s[i:j]
		}
		b.WriteString(txt)
		s = s[j:]
	}
}

// validLogName accepts a log name that maps to one EventLog registry key.
func validLogName(name string) bool {
	return strings.TrimSpace(name) != "" && len(name) <= 256 && !strings.ContainsAny(name, "\\/\x00")
}

// eventLogBudget turns the request timeout (seconds) into the time the
// reader may spend, leaving a second for the reply. The server waits
// timeout+2 s.
func eventLogBudget(timeout int) time.Duration {
	if timeout <= 1 {
		return 0
	}
	return time.Duration(timeout-1) * time.Second
}
