// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// fixed argv, no shell, one timeout for the RPC, not per command
const (
	nixRPCMax        = 60 * time.Second
	launchDaemonsDir = "/Library/LaunchDaemons"
)

var (
	// unit names, launchd labels, OpenRC and rc.d services; no leading dash, quotes or spaces
	nixNameRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:+\\-]{0,254}$`)
	ansiRe          = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	plistLabelRe    = regexp.MustCompile(`<key>\s*Label\s*</key>\s*<string>([^<]+)</string>`)
	plistDisabledRe = regexp.MustCompile(`<key>\s*Disabled\s*</key>\s*<true\s*/>`)
	printDisabledRe = regexp.MustCompile(`^\s*"([^"]+)"\s*=>\s*(\w+)`)
)

type nixSvc struct {
	rmm.UnixService
	plist   string   // launchd: plist in /Library/LaunchDaemons
	loaded  bool     // launchd: known to launchctl list
	levels  []string // openrc: runlevels from rc-update show
	active  string   // systemd: raw ACTIVE and SUB
	sub     string
	oneshot bool // rc.d: nothing to stop, stopped by design
}

// no shell. stdout goes to read; on failure, the trimmed stderr
func nixStream(ctx context.Context, read func(io.Reader) error, name string, args ...string) error {
	var stderr capBuf
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	rerr := read(out)
	if rerr != nil {
		cmd.Process.Kill()
	}
	werr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("%s: timed out", name)
	case rerr != nil:
		return rerr
	case werr != nil:
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return errors.New(clipUTF8(msg, nixMaxMsg))
		}
		return fmt.Errorf("%s: %v", name, werr)
	}
	return nil
}

func nixRun(ctx context.Context, name string, args ...string) (string, error) {
	var out capBuf
	err := nixStream(ctx, func(r io.Reader) error {
		_, err := io.Copy(&out, r)
		return err
	}, name, args...)
	return out.String(), err
}

// stderr goes to a file, not a pipe: a daemon started by an init script
// inherits it and would hold a pipe open until the deadline
func nixAction(ctx context.Context, name string, args ...string) error {
	f, err := os.CreateTemp("", "ulrmm")
	if err != nil {
		return err
	}
	os.Remove(f.Name())
	defer f.Close()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = f
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s: timed out", name)
		}
		b := make([]byte, nixMaxMsg)
		n, _ := f.ReadAt(b, 0)
		if msg := strings.TrimSpace(string(b[:n])); msg != "" {
			return errors.New(clipUTF8(msg, nixMaxMsg))
		}
		return fmt.Errorf("%s: %v", name, err)
	}
	return nil
}

func nixManager() string {
	switch runtime.GOOS {
	case "darwin":
		return "launchd"
	case "freebsd":
		return "rc.d"
	}
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "systemd"
	}
	if _, err := exec.LookPath("rc-status"); err == nil {
		return "openrc"
	}
	return ""
}

func PosixServices() ([]rmm.UnixService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nixRPCMax)
	defer cancel()
	svcs, err := nixServices(ctx)
	if err != nil {
		return nil, err
	}
	ret := make([]rmm.UnixService, 0, len(svcs))
	for _, s := range svcs {
		ret = append(ret, s.UnixService)
	}
	return ret, nil
}

// only a name from the current listing
func PosixSvcAction(name, action string) error {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return errors.New("unknown action")
	}
	if !nixNameRe.MatchString(name) {
		return errors.New("invalid service name")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nixRPCMax)
	defer cancel()
	svcs, err := nixServices(ctx)
	cancel()
	if err != nil {
		return err
	}
	// the listing may have used most of the budget
	ctx, cancel = context.WithTimeout(context.Background(), nixRPCMax)
	defer cancel()
	for _, s := range svcs {
		if s.Unit != name {
			continue
		}
		for _, argv := range svcActionArgv(s, action) {
			if err := nixAction(ctx, argv[0], argv[1:]...); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("service %s not found", name)
}

func nixServices(ctx context.Context) ([]nixSvc, error) {
	var svcs []nixSvc
	var err error
	switch nixManager() {
	case "systemd":
		svcs, err = systemdServices(ctx)
	case "launchd":
		svcs, err = launchdServices(ctx)
	case "openrc":
		svcs, err = openrcServices(ctx)
	case "rc.d":
		svcs, err = rcdServices(ctx)
	default:
		return nil, errors.New("no supported service manager (systemd, launchd, OpenRC, rc.d)")
	}
	if err != nil {
		return nil, err
	}
	ret := svcs[:0]
	for _, s := range svcs {
		if nixNameRe.MatchString(s.Unit) {
			ret = append(ret, s)
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].Unit < ret[j].Unit })
	return ret, nil
}

func svcActionArgv(s nixSvc, action string) [][]string {
	switch s.Init {
	case "launchd":
		target := "system/" + s.Unit
		switch {
		case (action == "start" || action == "restart") && !s.loaded && s.plist != "":
			// bootstrap only loads the job; kickstart runs it unless RunAtLoad already did
			return [][]string{{"launchctl", "bootstrap", "system", s.plist}, {"launchctl", "kickstart", target}}
		case action == "start":
			return [][]string{{"launchctl", "kickstart", target}}
		case action == "restart":
			return [][]string{{"launchctl", "kickstart", "-k", target}}
		case action == "stop":
			return [][]string{{"launchctl", "bootout", target}}
		}
		return [][]string{{"launchctl", action, target}}
	case "openrc":
		switch action {
		case "enable":
			return [][]string{{"rc-update", "add", s.Unit, "default"}}
		case "disable":
			var argv [][]string
			for _, lv := range s.levels {
				argv = append(argv, []string{"rc-update", "del", s.Unit, lv})
			}
			return argv
		}
		return [][]string{{"rc-service", s.Unit, action}}
	case "rc.d":
		if action == "enable" || action == "disable" {
			return [][]string{{"service", s.Unit, action}}
		}
		// one*: also for a service that is not enabled, as systemctl does
		return [][]string{{"service", s.Unit, "one" + action}}
	}
	return [][]string{{"systemctl", action, s.Unit}}
}

func systemdUnits(ctx context.Context) ([]nixSvc, error) {
	units, err := nixRun(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, err
	}
	files, err := nixRun(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, err
	}
	return mergeSystemd(parseSystemctlUnits(units), parseUnitFiles(files)), nil
}

func systemdServices(ctx context.Context) ([]nixSvc, error) {
	svcs, err := systemdUnits(ctx)
	if err != nil {
		return nil, err
	}

	args := []string{"show", "-p", "Id", "-p", "MainPID", "--no-pager"}
	for _, s := range svcs {
		if s.State == "running" {
			args = append(args, s.Unit)
		}
	}
	// pids are optional; on failure they stay null
	if len(args) > 6 {
		if out, err := nixRun(ctx, "systemctl", args...); err == nil {
			pids := parseSystemctlShow(out)
			for i := range svcs {
				if pid, ok := pids[svcs[i].Unit]; ok {
					svcs[i].MainPID = ptr(pid)
				}
			}
		}
	}
	return svcs, nil
}

// systemctl list-units --plain: UNIT LOAD ACTIVE SUB DESCRIPTION
func parseSystemctlUnits(out string) []nixSvc {
	var svcs []nixSvc
	for _, line := range strings.Split(ansiRe.ReplaceAllString(out, ""), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || f[1] == "not-found" {
			continue
		}
		status := "unknown"
		switch f[2] {
		case "active", "reloading":
			status = "running"
		case "inactive":
			status = "stopped"
		case "failed":
			status = "failed"
		}
		svcs = append(svcs, nixSvc{active: f[2], sub: f[3], UnixService: rmm.UnixService{
			Unit:  f[0],
			Desc:  clipUTF8(strings.Join(f[4:], " "), 512),
			State: status,
			Init:  "systemd",
		}})
	}
	return svcs
}

func parseUnitFiles(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && strings.HasSuffix(f[0], ".service") {
			m[f[0]] = f[1]
		}
	}
	return m
}

func unitFileEnabled(state string) *bool {
	switch state {
	case "enabled", "enabled-runtime":
		return ptr(true)
	case "disabled", "masked", "masked-runtime":
		return ptr(false)
	}
	return nil
}

// unloaded unit files too; skip templates and aliases
func mergeSystemd(units []nixSvc, files map[string]string) []nixSvc {
	seen := map[string]bool{}
	for i := range units {
		seen[units[i].Unit] = true
		units[i].OnBoot = unitFileEnabled(files[units[i].Unit])
	}
	for name, state := range files {
		if seen[name] || strings.HasSuffix(name, "@.service") || state == "alias" {
			continue
		}
		units = append(units, nixSvc{active: "inactive", sub: "dead", UnixService: rmm.UnixService{
			Unit: name, State: "stopped", OnBoot: unitFileEnabled(state), Init: "systemd",
		}})
	}
	return units
}

// systemd check, on FreeBSD against rc.d: unit names only through argv,
// checked against nixNameRe
func systemdUnitCheck(c rmm.CheckDef) (status, info string) {
	ctx, cancel := context.WithTimeout(context.Background(), nixRPCMax)
	defer cancel()
	mgr := nixManager()
	have := mgr == "systemd" || mgr == "rc.d"
	if mgr == "rc.d" {
		// policies may still carry the systemd unit name
		c.Svc = strings.TrimSuffix(c.Svc, ".service")
	}
	if have && !nixNameRe.MatchString(c.Svc) {
		return "failing", "invalid unit name"
	}
	show := func() (unitState, error) {
		if mgr == "rc.d" {
			return rcdUnitState(ctx, c.Svc)
		}
		out, err := nixRun(ctx, "systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", "--no-pager", c.Svc)
		return parseUnitShow(out), err
	}
	start := []string{"systemctl", "start", c.Svc}
	if mgr == "rc.d" {
		start = []string{"service", c.Svc, "onestart"}
	}
	var st unitState
	var err error
	if have {
		st, err = show()
	}
	status, info = systemdVerdict(c, have, st, err, func() (unitState, error) {
		if err := nixAction(ctx, start[0], start[1:]...); err != nil {
			return unitState{}, err
		}
		return show()
	})
	if mgr == "rc.d" && err == nil && st.load == "not-found" {
		info = "service " + c.Svc + " not found"
	}
	return status, info
}

// the systemd shape for an rc.d script
func rcdUnitState(ctx context.Context, name string) (unitState, error) {
	list, err := nixRun(ctx, "service", "-l")
	if err != nil {
		return unitState{}, err
	}
	if !stringInSlice(name, strings.Fields(list)) {
		return unitState{load: "not-found"}, nil
	}
	out, _ := runOut(ctx, "service", name, "onestatus")
	switch st, _ := parseRcdStatus(out); st {
	case "running":
		return unitState{load: "loaded", active: "active", sub: "running"}, nil
	case "stopped":
		return unitState{load: "loaded", active: "inactive", sub: "dead"}, nil
	}
	return unitState{load: "loaded", active: "unknown", sub: "no status"}, nil
}

func rcdServices(ctx context.Context) ([]nixSvc, error) { return rcdScan(ctx, false) }

// rc scripts in /etc/rc.d and /usr/local/etc/rc.d, or only the enabled ones;
// onestatus runs each script, a few at a time
func rcdScan(ctx context.Context, enabledOnly bool) ([]nixSvc, error) {
	en, err := nixRun(ctx, "service", "-e")
	if err != nil {
		return nil, err
	}
	enabled := parseServiceEnabled(en)
	names := make([]string, 0, len(enabled))
	for n := range enabled {
		names = append(names, n)
	}
	sort.Strings(names)
	if !enabledOnly {
		list, err := nixRun(ctx, "service", "-l")
		if err != nil {
			return nil, err
		}
		names = strings.Fields(list)
	}
	var svcs []nixSvc
	for _, n := range names {
		if nixNameRe.MatchString(n) {
			svcs = append(svcs, nixSvc{UnixService: rmm.UnixService{Unit: n, State: "unknown", OnBoot: ptr(enabled[n]), Init: "rc.d"}})
		}
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				s := &svcs[i]
				out, _ := runOut(ctx, "service", s.Unit, "onestatus")
				s.State, s.MainPID = parseRcdStatus(out)
				for _, dir := range []string{"/etc/rc.d/", "/usr/local/etc/rc.d/"} {
					if b, err := os.ReadFile(dir + s.Unit); err == nil {
						s.Desc, s.oneshot = rcDesc(string(b)), rcOneshot(string(b))
						break
					}
				}
			}
		}()
	}
	for i := range svcs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return svcs, nil
}

func parseSystemctlShow(out string) map[string]int {
	m := map[string]int{}
	for _, block := range strings.Split(out, "\n\n") {
		id, pid := "", 0
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(line, "Id="); ok {
				id = v
			} else if v, ok := strings.CutPrefix(line, "MainPID="); ok {
				pid, _ = strconv.Atoi(v)
			}
		}
		if id != "" && pid > 0 {
			m[id] = pid
		}
	}
	return m
}

func launchdServices(ctx context.Context) ([]nixSvc, error) {
	out, err := nixRun(ctx, "launchctl", "list")
	if err != nil {
		return nil, err
	}
	disabled, _ := nixRun(ctx, "launchctl", "print-disabled", "system")
	return mergeLaunchd(parseLaunchctlList(out), launchdPlists(launchDaemonsDir), parsePrintDisabled(disabled)), nil
}

// launchctl list: PID Status Label, pid "-" when not running
func parseLaunchctlList(out string) []nixSvc {
	var svcs []nixSvc
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] == "PID" {
			continue
		}
		s := nixSvc{loaded: true, UnixService: rmm.UnixService{Unit: f[2], State: "stopped", Init: "launchd"}}
		if pid, err := strconv.Atoi(f[0]); err == nil {
			s.MainPID, s.State = ptr(pid), "running"
		} else if code, err := strconv.Atoi(f[1]); err == nil && code > 0 {
			// negative is the signal that ended it, usually a stop
			s.State = "failed"
		}
		svcs = append(svcs, s)
	}
	return svcs
}

type plistInfo struct {
	path     string
	disabled bool
}

// label from the plist when it is XML, else from the file name
func launchdPlists(dir string) map[string]plistInfo {
	m := map[string]plistInfo{}
	files, _ := filepath.Glob(filepath.Join(dir, "*.plist"))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		label := strings.TrimSuffix(filepath.Base(p), ".plist")
		if sm := plistLabelRe.FindSubmatch(b); sm != nil {
			label = strings.TrimSpace(string(sm[1]))
		}
		m[label] = plistInfo{p, plistDisabledRe.Match(b)}
	}
	return m
}

// "label" => disabled|enabled, older releases true|false
func parsePrintDisabled(out string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if sm := printDisabledRe.FindStringSubmatch(line); sm != nil {
			m[sm[1]] = sm[2] == "disabled" || sm[2] == "true"
		}
	}
	return m
}

func mergeLaunchd(svcs []nixSvc, plists map[string]plistInfo, disabled map[string]bool) []nixSvc {
	seen := map[string]bool{}
	for _, s := range svcs {
		seen[s.Unit] = true
	}
	for label := range plists {
		if !seen[label] {
			svcs = append(svcs, nixSvc{UnixService: rmm.UnixService{Unit: label, State: "stopped", Init: "launchd"}})
		}
	}
	for i := range svcs {
		s := &svcs[i]
		p, hasPlist := plists[s.Unit]
		s.plist = p.path
		if d, ok := disabled[s.Unit]; ok {
			s.OnBoot = ptr(!d)
		} else if hasPlist {
			s.OnBoot = ptr(!p.disabled)
		}
	}
	return svcs
}

func openrcServices(ctx context.Context) ([]nixSvc, error) {
	out, err := nixRun(ctx, "rc-status", "--all")
	if err != nil {
		return nil, err
	}
	upd, err := nixRun(ctx, "rc-update", "show")
	if err != nil {
		return nil, err
	}
	// rc-status leaves out stopped services outside any runlevel
	all, err := nixRun(ctx, "rc-service", "--list")
	if err != nil {
		return nil, err
	}
	levels := parseRcUpdate(upd)
	svcs := parseRcStatus(out)
	seen := map[string]bool{}
	for _, s := range svcs {
		seen[s.Unit] = true
	}
	for _, name := range strings.Fields(all) {
		if !seen[name] {
			seen[name] = true
			svcs = append(svcs, nixSvc{UnixService: rmm.UnixService{Unit: name, State: "stopped", Init: "openrc"}})
		}
	}
	for i := range svcs {
		svcs[i].levels = levels[svcs[i].Unit]
		svcs[i].OnBoot = ptr(len(svcs[i].levels) > 0)
	}
	return svcs, nil
}

// rc-status --all: "Runlevel: x" headers, then " name   [  state  ]"
func parseRcStatus(out string) []nixSvc {
	var svcs []nixSvc
	seen := map[string]bool{}
	for _, line := range strings.Split(ansiRe.ReplaceAllString(out, ""), "\n") {
		line = strings.TrimSpace(line)
		open := strings.Index(line, "[")
		if open < 0 || !strings.HasSuffix(line, "]") {
			continue
		}
		name, state := strings.Fields(line[:open]), strings.Fields(line[open+1:len(line)-1])
		// one word before the bracket; skips " * Caching service dependencies ... [ ok ]"
		if len(name) != 1 || len(state) == 0 || seen[name[0]] {
			continue
		}
		seen[name[0]] = true
		status := "unknown"
		switch state[0] {
		case "started":
			status = "running"
		case "stopped":
			status = "stopped"
		case "crashed", "failed":
			status = "failed"
		}
		svcs = append(svcs, nixSvc{UnixService: rmm.UnixService{Unit: name[0], State: status, Init: "openrc"}})
	}
	return svcs
}

// rc-update show: "name | runlevel..."
func parseRcUpdate(out string) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(ansiRe.ReplaceAllString(out, ""), "\n") {
		if name, lv, ok := strings.Cut(line, "|"); ok && strings.TrimSpace(name) != "" {
			m[strings.TrimSpace(name)] = strings.Fields(lv)
		}
	}
	return m
}
