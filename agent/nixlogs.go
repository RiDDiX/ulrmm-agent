// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"golang.org/x/sys/unix"
)

const (
	nixMaxMsg   = 4 << 10
	nixMaxReply = 4 << 20
	nixLogRoot  = "/var/log"
	nixTSLayout = "2006-01-02T15:04:05.000000Z07:00"
)

type logQuery struct {
	source, unit, path     string
	priority, lines, since int
}

func PosixLogs(p map[string]string) (*rmm.PosixLogs, error) {
	q, err := parseLogQuery(p)
	if err != nil {
		return nil, err
	}
	switch {
	case q.source == "file":
		return fileLogs(q)
	case q.source == "journal" && runtime.GOOS != "linux":
		return nil, errors.New("the journal is Linux only")
	case q.source == "unified" && runtime.GOOS != "darwin":
		return nil, errors.New("the unified log is macOS only")
	}

	ctx, cancel := context.WithTimeout(context.Background(), nixRPCMax)
	defer cancel()
	var lines []rmm.PosixLogLine
	name, args := "journalctl", journalArgs(q)
	read := func(r io.Reader) (err error) {
		lines, err = parseJournal(r)
		return err
	}
	if q.source == "unified" {
		name, args = "log", unifiedArgs(q)
		read = func(r io.Reader) (err error) {
			lines, err = parseUnified(r, q.lines+1, q.priority)
			return err
		}
	}
	// timeout is an error: a partial read is the oldest lines, not the newest
	if err := nixStream(ctx, read, name, args...); err != nil {
		return nil, err
	}
	return capLogs(lines, q.lines, false), nil
}

func parseLogQuery(p map[string]string) (logQuery, error) {
	q := logQuery{source: p["source"], unit: p["unit"], path: p["path"], priority: -1, lines: 200}
	for _, n := range []struct {
		key    string
		lo, hi int
		dst    *int
	}{
		{"priority", 0, 7, &q.priority},
		{"lines", 50, 2000, &q.lines},
		{"since", 1, 525600, &q.since},
	} {
		v := p[n.key]
		if v == "" {
			continue
		}
		i, err := strconv.Atoi(v)
		if err != nil || i < n.lo || i > n.hi {
			return q, fmt.Errorf("%s must be %d-%d", n.key, n.lo, n.hi)
		}
		*n.dst = i
	}
	switch q.source {
	case "journal", "unified":
		// a backslash escapes the closing quote in the log show predicate
		if q.unit != "" && (!nixNameRe.MatchString(q.unit) || q.source == "unified" && strings.Contains(q.unit, `\`)) {
			return q, errors.New("invalid unit")
		}
	case "file":
		if !utf8.ValidString(q.path) {
			return q, errors.New("invalid path")
		}
	default:
		return q, errors.New("source must be journal, unified or file")
	}
	return q, nil
}

// one extra line, so capLogs can see if the output was cut
func journalArgs(q logQuery) []string {
	args := []string{"-o", "json", "--no-pager", "-q", "-n", strconv.Itoa(q.lines + 1)}
	if q.unit != "" {
		args = append(args, "-u", q.unit)
	}
	if q.priority >= 0 {
		args = append(args, "-p", strconv.Itoa(q.priority))
	}
	if q.since > 0 {
		args = append(args, fmt.Sprintf("--since=-%dmin", q.since))
	}
	return args
}

// log show has no tail option, so the window defaults to 10 minutes
func unifiedArgs(q logQuery) []string {
	since := q.since
	if since == 0 {
		since = 10
	}
	args := []string{"show", "--style", "json", "--last", fmt.Sprintf("%dm", since)}
	if q.priority >= 6 {
		args = append(args, "--info")
	}
	if q.priority == 7 {
		args = append(args, "--debug")
	}
	if q.unit != "" {
		args = append(args, "--predicate", fmt.Sprintf(`subsystem == "%s" OR process == "%s"`, q.unit, q.unit))
	}
	return args
}

type journalEntry struct {
	TS    string          `json:"__REALTIME_TIMESTAMP"`
	Unit  json.RawMessage `json:"_SYSTEMD_UNIT"`
	Ident json.RawMessage `json:"SYSLOG_IDENTIFIER"`
	Prio  json.RawMessage `json:"PRIORITY"`
	Msg   json.RawMessage `json:"MESSAGE"`
}

func parseJournal(r io.Reader) ([]rmm.PosixLogLine, error) {
	var lines []rmm.PosixLogLine
	dec := json.NewDecoder(r)
	for {
		var e journalEntry
		if err := dec.Decode(&e); err == io.EOF {
			return lines, nil
		} else if err != nil {
			return lines, err
		}
		ts := ""
		if us, err := strconv.ParseInt(e.TS, 10, 64); err == nil {
			ts = time.UnixMicro(us).UTC().Format(nixTSLayout)
		}
		unit := journalField(e.Unit)
		if unit == "" {
			unit = journalField(e.Ident)
		}
		var prio *int
		if n, err := strconv.Atoi(journalField(e.Prio)); err == nil {
			prio = ptr(n)
		}
		msg := journalField(e.Msg)
		if string(e.Msg) == "null" {
			msg = "[message over 4096 bytes]"
		}
		lines = append(lines, logLine(ts, unit, prio, msg))
	}
}

// journal json values: string, byte array for binary data, a list when the
// field repeats, null when larger than 4096 bytes
func journalField(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var nums []int
	if json.Unmarshal(raw, &nums) == nil {
		b := make([]byte, len(nums))
		for i, n := range nums {
			b[i] = byte(n)
		}
		return string(b)
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
		return journalField(list[0])
	}
	return ""
}

type unifiedEntry struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"eventType"`
	MessageType string `json:"messageType"`
	Subsystem   string `json:"subsystem"`
	Process     string `json:"processImagePath"`
	Message     string `json:"eventMessage"`
}

// unified log levels as syslog priorities
var unifiedPrio = map[string]int{"Fault": 2, "Error": 3, "Default": 5, "Info": 6, "Debug": 7}

// log show --style json is one array, oldest first; past keep, drop the older lines
func parseUnified(r io.Reader, keep, maxPrio int) ([]rmm.PosixLogLine, error) {
	br := bufio.NewReader(r)
	if _, err := br.ReadString('['); err == io.EOF {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(io.MultiReader(strings.NewReader("["), br))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var lines []rmm.PosixLogLine
	for dec.More() {
		var e unifiedEntry
		if err := dec.Decode(&e); err != nil {
			return lines, err
		}
		if e.EventType != "logEvent" {
			continue
		}
		prio, known := unifiedPrio[e.MessageType]
		if maxPrio >= 0 && (!known || prio > maxPrio) {
			continue
		}
		ts := e.Timestamp
		if t, err := time.Parse("2006-01-02 15:04:05.000000-0700", e.Timestamp); err == nil {
			ts = t.UTC().Format(nixTSLayout)
		}
		unit := e.Subsystem
		if unit == "" && e.Process != "" {
			unit = filepath.Base(e.Process)
		}
		var p *int
		if known {
			p = ptr(prio)
		}
		lines = append(lines, logLine(ts, unit, p, e.Message))
		if len(lines) > keep {
			lines = lines[1:]
		}
	}
	return lines, nil
}

func fileLogs(q logQuery) (*rmm.PosixLogs, error) {
	p, err := resolveLogPath(nixLogRoot, q.path)
	if err != nil {
		return nil, err
	}
	f, err := openBeneath(nixLogRoot, p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("path must be a file under %s/", nixLogRoot)
	}
	off := fi.Size() - nixMaxReply
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, err
	}
	var lines []rmm.PosixLogLine
	for _, l := range tailLines(buf[:n], off > 0, q.lines+1) {
		lines = append(lines, logLine("", "", nil, l))
	}
	return capLogs(lines, q.lines, off > 0), nil
}

// p must stay under root after resolving symlinks and be a regular file
func resolveLogPath(root, p string) (string, error) {
	bad := fmt.Errorf("path must be a file under %s/", root)
	if filepath.Clean(p) != p || !strings.HasPrefix(p, root+"/") {
		return "", bad
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(real, realRoot+"/") {
		return "", bad
	}
	if fi, err := os.Stat(real); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", bad
	}
	return real, nil
}

// openBeneath opens p from resolveLogPath one component at a time from
// root, none of them a symlink: a link swapped in after the check fails
// instead of leading out of root. O_NONBLOCK: a fifo must not hang the read.
// O_NOCTTY: a tty node must not become the controlling terminal.
func openBeneath(root, p string) (*os.File, error) {
	bad := fmt.Errorf("path must be a file under %s/", root)
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	rel, ok := strings.CutPrefix(p, realRoot+"/")
	if !ok {
		return nil, bad
	}
	fd, err := unix.Open(realRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: realRoot, Err: err}
	}
	parts := strings.Split(rel, "/")
	for i, name := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
		if i < len(parts)-1 {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, name, flags, 0)
		unix.Close(fd)
		if err != nil {
			// a symlink: ELOOP, EMLINK on FreeBSD, ENOTDIR for a directory
			if err == unix.ELOOP || err == unix.EMLINK || err == unix.ENOTDIR {
				return nil, bad
			}
			return nil, &os.PathError{Op: "open", Path: p, Err: err}
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), p), nil
}

// last n lines; partial means buf starts mid-file and its first line is cut
func tailLines(buf []byte, partial bool, n int) []string {
	s := string(buf)
	if partial {
		_, s, _ = strings.Cut(s, "\n")
	}
	s = strings.TrimRight(s, "\r\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

func logLine(ts, unit string, prio *int, msg string) rmm.PosixLogLine {
	return rmm.PosixLogLine{
		TS:       clipUTF8(ts, 64),
		Unit:     clipUTF8(unit, 256),
		Priority: prio,
		Text:     clipUTF8(strings.TrimRight(msg, "\r\n"), nixMaxMsg),
	}
}

// newest lines, at most max, and no more than nixMaxReply bytes
func capLogs(lines []rmm.PosixLogLine, max int, cut bool) *rmm.PosixLogs {
	if len(lines) > max {
		lines, cut = lines[len(lines)-max:], true
	}
	size := 0
	for i := len(lines) - 1; i >= 0; i-- {
		size += len(lines[i].TS) + len(lines[i].Unit) + len(lines[i].Text) + 48
		if size > nixMaxReply {
			lines, cut = lines[i+1:], true
			break
		}
	}
	if lines == nil {
		lines = []rmm.PosixLogLine{}
	}
	return &rmm.PosixLogs{Lines: lines, Truncated: cut}
}

// valid UTF-8 (msgpack strings) cut to n bytes on a rune boundary
func clipUTF8(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
