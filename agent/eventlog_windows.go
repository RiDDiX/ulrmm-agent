// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Classic event log API (advapi32), read newest first.
var (
	evtAdvapi32      = windows.NewLazySystemDLL("advapi32.dll")
	evtOpenEventLog  = evtAdvapi32.NewProc("OpenEventLogW")
	evtCloseEventLog = evtAdvapi32.NewProc("CloseEventLog")
	evtReadEventLog  = evtAdvapi32.NewProc("ReadEventLogW")
)

const (
	evtReadFlags     = 0x1 | 0x8 // EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ
	evtMaxRecords    = 20000
	evtMaxReadBuf    = 4 << 20
	evtDefaultBudget = 120 * time.Second
	evtLogsKey       = `SYSTEM\CurrentControlSet\Services\EventLog\`
	// FormatMessage reads one pointer per insert; the padding covers every
	// %1..%99 a message may name and 64-bit inserts on 386.
	evtArgSlots = 200
	evtMsgChars = 32 << 10 // FormatMessage output limit is 64 KiB
)

// GetEventLog returns the records of logName written in the last
// searchLastDays days (0 = all), newest first, at most evtMaxRecords and
// only what fits into budget (0 = evtDefaultBudget). Never nil.
func (a *Agent) GetEventLog(logName string, searchLastDays int, budget time.Duration) []rmm.EventEntry {
	ret := []rmm.EventEntry{}
	if !validLogName(logName) {
		return ret
	}
	// OpenEventLog falls back to Application for unknown names
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, evtLogsKey+logName, registry.QUERY_VALUE)
	if err != nil {
		a.Logger.Debugln("GetEventLog(): no such log", logName)
		return ret
	}
	k.Close()

	if budget <= 0 {
		budget = evtDefaultBudget
	}
	deadline := time.Now().Add(budget)
	var cutoff int64
	if searchLastDays > 0 {
		cutoff = time.Now().Add(-time.Duration(searchLastDays) * 24 * time.Hour).Unix()
	}

	h, err := openEventLog(logName)
	if err != nil {
		a.Logger.Errorln("GetEventLog(): open", logName, err)
		return ret
	}
	defer evtCloseEventLog.Call(h)

	msgs := newEvtMessages(logName)
	defer msgs.close()

	err = readEventRecords(h, cutoff, func(rec evtRecord) bool {
		ret = append(ret, rmm.EventEntry{
			Src:   CleanString(rec.Source),
			Kind:  evtTypeText(rec.EventType),
			Code:  rec.EventID & 0xffff,
			Text:  CleanString(msgs.format(rec.Source, rec.EventID, rec.Inserts)),
			When:  time.Unix(int64(rec.Written), 0).String(),
			RowID: len(ret) + 1,
		})
		if len(ret) >= evtMaxRecords {
			a.Logger.Debugln("GetEventLog(): record cap reached for", logName)
			return false
		}
		if time.Now().After(deadline) {
			a.Logger.Debugln("GetEventLog(): time budget used up for", logName)
			return false
		}
		return true
	})
	if err == errEvtMalformed {
		a.Logger.Debugln("GetEventLog(): malformed record in", logName)
	} else if err != nil {
		a.Logger.Debugln("GetEventLog(): read", logName, err)
	}
	return ret
}

var errEvtMalformed = errors.New("malformed event record")

func openEventLog(logName string) (uintptr, error) {
	name, err := windows.UTF16PtrFromString(logName)
	if err != nil {
		return 0, err
	}
	h, _, e := evtOpenEventLog.Call(0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return 0, e
	}
	return h, nil
}

// readEventRecords hands the records of h to fn, newest first, until fn
// returns false, a record is older than cutoff (0 = none) or the log ends.
func readEventRecords(h uintptr, cutoff int64, fn func(evtRecord) bool) error {
	buf := make([]byte, 64<<10)
	for {
		var read, needed uint32
		r, _, e := evtReadEventLog.Call(h, evtReadFlags, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&needed)))
		if r == 0 {
			if e == windows.ERROR_INSUFFICIENT_BUFFER && needed > uint32(len(buf)) && needed <= evtMaxReadBuf {
				buf = make([]byte, needed)
				continue
			}
			if e == windows.ERROR_HANDLE_EOF {
				return nil
			}
			return e
		}
		recs, ok := parseEventRecords(buf[:read])
		for _, rec := range recs {
			if cutoff != 0 && int64(rec.Written) < cutoff {
				return nil
			}
			if !fn(rec) {
				return nil
			}
		}
		if !ok {
			return errEvtMalformed
		}
	}
}

// evtMessages resolves message texts for one call, loading every message
// module once.
type evtMessages struct {
	logName string
	mods    map[string]windows.Handle
	sources map[string]evtSource
	buf     []uint16
	empty   []uint16
}

type evtSource struct {
	msg, param []windows.Handle
}

func newEvtMessages(logName string) *evtMessages {
	return &evtMessages{
		logName: logName,
		mods:    map[string]windows.Handle{},
		sources: map[string]evtSource{},
		buf:     make([]uint16, evtMsgChars),
		empty:   []uint16{0},
	}
}

func (m *evtMessages) close() {
	for _, h := range m.mods {
		if h != 0 {
			windows.FreeLibrary(h)
		}
	}
}

// modules loads the paths of a message file value as data files.
func (m *evtMessages) modules(value string) []windows.Handle {
	var ret []windows.Handle
	for _, p := range splitModules(value) {
		key := strings.ToLower(p)
		h, seen := m.mods[key]
		if !seen {
			h, _ = windows.LoadLibraryEx(p, 0, windows.LOAD_LIBRARY_AS_DATAFILE)
			m.mods[key] = h
		}
		if h != 0 {
			ret = append(ret, h)
		}
	}
	return ret
}

func (m *evtMessages) source(name string) evtSource {
	if s, ok := m.sources[name]; ok {
		return s
	}
	var s evtSource
	if validLogName(name) {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, evtLogsKey+m.logName+`\`+name, registry.QUERY_VALUE); err == nil {
			s.msg = m.modules(expandedValue(k, "EventMessageFile"))
			s.param = m.modules(expandedValue(k, "ParameterMessageFile"))
			k.Close()
		}
	}
	m.sources[name] = s
	return s
}

func expandedValue(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	if x, err := registry.ExpandString(v); err == nil {
		return x
	}
	return v
}

func (m *evtMessages) format(source string, eventID uint32, inserts []string) string {
	s := m.source(source)
	if len(s.msg) == 0 {
		return ""
	}
	strs := make([][]uint16, len(inserts))
	args := make([]uintptr, evtArgSlots)
	for i := range args {
		args[i] = uintptr(unsafe.Pointer(&m.empty[0]))
	}
	for i, in := range inserts {
		if i >= len(args) {
			break
		}
		strs[i] = append(utf16.Encode([]rune(in)), 0)
		args[i] = uintptr(unsafe.Pointer(&strs[i][0]))
	}
	const flags = windows.FORMAT_MESSAGE_FROM_SYSTEM | windows.FORMAT_MESSAGE_FROM_HMODULE | windows.FORMAT_MESSAGE_ARGUMENT_ARRAY
	text := ""
	for _, mod := range s.msg {
		n, err := windows.FormatMessage(flags, uintptr(mod), eventID, 0, m.buf, (*byte)(unsafe.Pointer(&args[0])))
		if err == nil && n > 0 {
			text = windows.UTF16ToString(m.buf[:n])
			break
		}
	}
	runtime.KeepAlive(strs)
	runtime.KeepAlive(args)
	if text == "" {
		return ""
	}
	text = expandParamRefs(text, func(id uint32) (string, bool) { return m.param(s.param, id) })
	return cleanEventMessage(text)
}

// param resolves a %%nnnn reference from the source's parameter modules.
// The system message table is not a fallback: its ids overlap with the
// parameter ids and would turn an unresolved reference into a wrong sentence.
func (m *evtMessages) param(mods []windows.Handle, id uint32) (string, bool) {
	const base = windows.FORMAT_MESSAGE_IGNORE_INSERTS
	try := func(flags uint32, mod windows.Handle) (string, bool) {
		n, err := windows.FormatMessage(base|flags, uintptr(mod), id, 0, m.buf, nil)
		if err != nil || n == 0 {
			return "", false
		}
		return strings.TrimRight(windows.UTF16ToString(m.buf[:n]), "\r\n "), true
	}
	for _, mod := range mods {
		if s, ok := try(windows.FORMAT_MESSAGE_FROM_HMODULE, mod); ok {
			return s, true
		}
	}
	return "", false
}
