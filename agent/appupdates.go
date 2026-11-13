// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/width"
)

// App updates: third-party applications through winget (Windows) and
// brew/mas (macOS). Linux packages are handled by the posix update path.

type AppUpdate struct {
	Source    string `json:"source"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Available string `json:"available"`
}

type AppUpgradeResult struct {
	ID         string `json:"id"`
	OK         bool   `json:"ok"`
	OutputTail string `json:"output_tail"`
	// appNotStarted or appTimedOut when ok is false for one of these reasons
	Status string `json:"status,omitempty"`
}

const (
	// the server waits 120 s for a list and 1800 s for an upgrade; no
	// package starts after appUpgradeMax, one that runs gets wingetUpgradeMax
	// but no more than what is left until appAnswerBy
	appListMax    = 110 * time.Second
	appUpgradeMax = 570 * time.Second
	appTailMax    = 2000
	appIDsMax     = 100
	// same limit as a choco install
	wingetInstallMax  = 1200 * time.Second
	wingetInstallTail = 64 << 10

	appNotStarted = "not_started"
	appTimedOut   = "timed_out"
	// only the parent is killed at the limit, an installer it started goes on
	appTimedOutText = "timed out, the installer may still finish; rescan"
)

var (
	// one package's own limit; tests shorten it
	wingetUpgradeMax = 20 * time.Minute
	// an upgrade call answers by then, counted from its start
	appAnswerBy = 1770 * time.Second
	appNow      = time.Now
	// how long a run waits for a child that keeps its output open
	pipeDrain = 10 * time.Second
)

var (
	// @ for versioned brew formulae (openssl@3, python@3.12); & ! and
	// non-ASCII letters are in winget ids (Febooti.Hash&CRC, BRÖTJE.ProfiTool).
	// No comma, upgrade ids travel as a comma list.
	appIDRe = regexp.MustCompile(`^[\pL\pN._+&!@-]{1,128}$`)
	// install ids come one at a time, so a comma is allowed
	// (IDMComputerSolutions,Inc.UltraEdit)
	wingetIDRe   = regexp.MustCompile(`^[\pL\pN][\pL\pN_.+&!,@-]{0,127}$`)
	vtSeqRe      = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	masRe        = regexp.MustCompile(`^\s*(\d+)\s+(.+?)\s+\(([^()]+?)\s*->\s*([^()]+?)\)\s*$`)
	appUpdatesMu sync.Mutex
)

// AppUpdates is the appupdates rpc: {action: list} or
// {action: upgrade, ids: "a,b", source: winget|brew|mas}.
func AppUpdates(data map[string]string) (interface{}, error) {
	if !appUpdatesMu.TryLock() {
		return nil, errors.New("app updates are already running")
	}
	defer appUpdatesMu.Unlock()
	switch data["action"] {
	case "list":
		ctx, cancel := context.WithTimeout(context.Background(), appListMax)
		defer cancel()
		return listAppUpdates(ctx)
	case "upgrade":
		ids, err := parseAppIDs(data["ids"])
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), appUpgradeMax)
		defer cancel()
		res, err := upgradeApps(ctx, data["source"], ids)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"results": res}, nil
	}
	return nil, errors.New("unknown action")
}

// an id is passed as an argument, a leading dash would make it an option
func validAppID(id string) bool {
	return appIDRe.MatchString(id) && id[0] != '-'
}

func parseAppIDs(s string) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		if !validAppID(id) {
			return nil, errors.New("invalid app id")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("no app ids")
	}
	if len(ids) > appIDsMax {
		return nil, fmt.Errorf("at most %d app ids per call", appIDsMax)
	}
	return ids, nil
}

// upgradeEach runs one upgrade per id, each with its own wingetUpgradeMax,
// cut so the call still answers by appAnswerBy. The deadline of ctx only
// stops further ids from starting; a cancel of ctx also ends the running one.
func upgradeEach(ctx context.Context, ids []string, run func(ctx context.Context, id string) (out string, ok bool, err error)) []AppUpgradeResult {
	res := make([]AppUpgradeResult, 0, len(ids))
	answerBy := appNow().Add(appAnswerBy)
	for _, id := range ids {
		if ctx.Err() != nil {
			res = append(res, AppUpgradeResult{ID: id, OutputTail: "not started: time limit reached", Status: appNotStarted})
			continue
		}
		budget := wingetUpgradeMax
		if left := answerBy.Sub(appNow()); left < budget {
			budget = left
		}
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
		stop := context.AfterFunc(ctx, func() {
			if errors.Is(ctx.Err(), context.Canceled) {
				cancel()
			}
		})
		out, ok, err := run(pctx, id)
		timedOut := err != nil && errors.Is(pctx.Err(), context.DeadlineExceeded)
		if err != nil && errors.Is(pctx.Err(), context.Canceled) {
			err = errors.New("cancelled")
		}
		stop()
		cancel()
		if timedOut {
			res = append(res, AppUpgradeResult{ID: id, OutputTail: outputTail(out+"\n"+appTimedOutText, appTailMax), Status: appTimedOut})
			continue
		}
		if err != nil {
			out += "\n" + err.Error()
		}
		res = append(res, AppUpgradeResult{ID: id, OK: ok && err == nil, OutputTail: outputTail(out, appTailMax)})
	}
	return res
}

// runApp runs argv without a shell. A non-zero exit is not an error, it is code.
func runApp(ctx context.Context, dir string, argv ...string) (stdout, stderr string, code int, err error) {
	return runAppWith(ctx, appCmdAttr, dir, argv...)
}

// runAppWith is runApp with the process attributes set by attr.
func runAppWith(ctx context.Context, attr func(*exec.Cmd), dir string, argv ...string) (stdout, stderr string, code int, err error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	var o, e capBuf
	cmd.Stdout, cmd.Stderr = &o, &e
	cmd.WaitDelay = pipeDrain
	attr(cmd)
	err = cmd.Run()
	code = -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	// a child left holding the pipes does not void the exit code
	var ee *exec.ExitError
	if errors.As(err, &ee) || errors.Is(err, exec.ErrWaitDelay) {
		err = nil
	}
	stdout, stderr = o.String(), e.String()
	// a run that ended keeps its exit code, the cut output is only noted
	if o.over || e.over {
		if code < 0 && err == nil {
			err = errOutputTooLarge
		}
		if o.over {
			stdout += "\n[output truncated]"
		}
		if e.over {
			stderr += "\n[output truncated]"
		}
	}
	if ctx.Err() != nil {
		err = errors.New("time limit reached")
	}
	return stdout, stderr, code, err
}

// appLines splits tool output into lines as a terminal would show them:
// carriage-return redraws and colour codes removed.
func appLines(s string) []string {
	s = vtSeqRe.ReplaceAllString(strings.ToValidUTF8(s, ""), "")
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if j := strings.LastIndexByte(l, '\r'); j >= 0 {
			l = l[j+1:]
		}
		lines[i] = strings.TrimRight(l, " \t")
	}
	return lines
}

// outputTail is the last limit bytes of the output without spinner and
// progress lines.
func outputTail(s string, limit int) string {
	var keep []string
	for _, l := range appLines(s) {
		if strings.Trim(l, ` -\|/`) == "" || strings.ContainsAny(l, "█▒▏▎▍▌▋▊▉") {
			continue
		}
		keep = append(keep, l)
	}
	t := strings.Join(keep, "\n")
	for len(t) > limit {
		_, n := utf8.DecodeRuneInString(t)
		t = t[n:]
	}
	return t
}

// InstallWithWinget installs one winget package machine-wide and gives the
// text for the dashboard and winget's exit code as uint32, -1 when winget did
// not run to its end.
func InstallWithWinget(id string) (string, int64) {
	if !wingetIDRe.MatchString(id) {
		return fmt.Sprintf("invalid winget id: %q", id), -1
	}
	if !appUpdatesMu.TryLock() {
		return "winget is busy with app updates, try again in a few minutes", -1
	}
	defer appUpdatesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), wingetInstallMax)
	defer cancel()
	// one limit for the whole sequence: install, probe, second install
	stdout, stderr, code, note, err := installWinget(ctx, id)
	if err != nil && ctx.Err() != nil {
		err = errors.New(appTimedOutText)
	}
	out, c := wingetInstallResult(stdout, stderr, code, err)
	if note != "" {
		out = strings.TrimRight(note+"\n"+out, "\n")
	}
	return out, c
}

// wingetInstallArgs: scope "machine" first, SYSTEM has no profile worth
// installing into and the retry as the user runs elevated; "user" for a
// per-user installer run as the signed-in user without elevation
// (wingetUserElevated); "" lets winget choose.
func wingetInstallArgs(id, scope string) []string {
	args := []string{"install", "--id", id, "--exact", "--source", "winget"}
	if scope != "" {
		args = append(args, "--scope", scope)
	}
	return append(args, "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity")
}

// wingetUserElevated: a --scope user install needs no admin rights and its
// installer lands in the user's own %TEMP%, where an unelevated process could
// swap it after the hash check; only machine-wide runs take the elevated token.
func wingetUserElevated(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--scope" && args[i+1] == "user" {
			return false
		}
	}
	return true
}

// wingetProbeArgs asks which installer winget selects for scope. show exits
// 0 either way, only its output tells.
func wingetProbeArgs(id, scope string) []string {
	return []string{"show", "--id", id, "--exact", "--source", "winget", "--scope", scope,
		"--accept-source-agreements", "--disable-interactivity"}
}

// what follows a machine-scope install
type wingetNext int

const (
	wingetDone    wingetNext = iota // the first attempt is the result
	wingetAsUser                    // per-user installer: install as the signed-in user
	wingetNoUser                    // per-user installer and nobody signed in
	wingetNoScope                   // installer without a declared scope: again without --scope
)

const wingetNoUserText = "this package installs per user only, sign a user in on the device and try again"

// an installer's SHA256 in `winget show`; its labels are localised
var wingetInstallerHashRe = regexp.MustCompile(`\b[0-9A-Fa-f]{64}\b`)

func wingetNoInstallerFound(code int, err error) bool {
	return err == nil && uint32(code) == wingetNoInstaller
}

// wingetSecondTry decides after a machine-scope install: only "no applicable
// installer" gets a second attempt. machine and user are the outputs of
// wingetProbeArgs for both scopes; a hash in the release notes shows in both,
// only an installer selected for user scope adds one. Installing a per-user
// package as SYSTEM would put it into the SYSTEM profile, so without a
// signed-in user it is not tried.
func wingetSecondTry(code int, err error, machine, user string, probeErr error, signedIn bool) wingetNext {
	switch {
	case !wingetNoInstallerFound(code, err) || probeErr != nil:
		return wingetDone
	case len(wingetInstallerHashRe.FindAllString(user, -1)) <= len(wingetInstallerHashRe.FindAllString(machine, -1)):
		return wingetNoScope
	case signedIn:
		return wingetAsUser
	}
	return wingetNoUser
}

// wingetUserNote heads the result of an install as the signed-in user.
func wingetUserNote(user string, code int, err error) string {
	done := "tried to install"
	if err == nil && (code == 0 || uint32(code) == wingetNoUpdate || uint32(code) == wingetAlready || uint32(code) == wingetReboot) {
		done = "installed"
	}
	return done + " for the signed-in user " + user + " because the package has no installer for all users"
}

// wingetLogLine: verb, package, who ran winget, exit code and duration;
// never output.
func wingetLogLine(as string, args []string, d time.Duration, code int, err error) string {
	what := ""
	if len(args) > 0 {
		what = args[0]
	}
	for i := 1; i+1 < len(args); i++ {
		if args[i] == "--id" {
			what += " " + args[i+1]
		}
	}
	s := fmt.Sprintf("winget %s as %s: exit code 0x%08X after %v", what, as, uint32(code), d.Round(time.Millisecond))
	if err != nil {
		s += ", error: " + err.Error()
	}
	return s
}

func wingetInstallResult(stdout, stderr string, code int, err error) (string, int64) {
	out := outputTail(stdout+"\n"+stderr, wingetInstallTail)
	if err != nil {
		return strings.TrimLeft(out+"\n"+err.Error(), "\n"), -1
	}
	if code != 0 {
		out = strings.TrimLeft(out+"\n"+wingetExitText(code), "\n")
	}
	return out, int64(uint32(code))
}

var wingetHints = map[uint32]string{
	0x8A150111:        "an application is in use, close it",
	0x80072EE2:        "download failed: network or server",
	0x801901F6:        "download failed: network or server",
	wingetNoUpdate:    "already installed",
	wingetNoInstaller: "winget found no applicable installer of this package",
}

// wingetExitText is the exit code line, with a hint on its own line for
// codes people meet often.
func wingetExitText(code int) string {
	s := fmt.Sprintf("exit code 0x%08X", uint32(code))
	if h := wingetHints[uint32(code)]; h != "" {
		s += "\n" + h
	}
	return s
}

// cells lays a line out in terminal columns; a wide rune takes two, the
// second is 0. winget pads its table by columns, not by runes.
func cells(s string) []rune {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		out = append(out, r)
		if k := width.LookupRune(r).Kind(); k == width.EastAsianWide || k == width.EastAsianFullwidth {
			out = append(out, 0)
		}
	}
	return out
}

func cellText(c []rune) string {
	return strings.TrimSpace(strings.ReplaceAll(string(c), "\x00", ""))
}

// startsAt: a value starts in column j of the laid-out line c.
func startsAt(c []rune, j int) bool {
	return j < len(c) && c[j] != ' ' && c[j] != 0 && (j == 0 || c[j-1] == ' ')
}

// winget: nothing installed, nothing to upgrade, installed but the reboot
// finishes it, already installed, no installer for the scope asked for.
// STATUS_DLL_NOT_FOUND is winget.exe started from its package folder as
// SYSTEM, which cannot load its framework packages (Windows 11, winget
// 1.29); it prints nothing.
const (
	wingetNoApps      = 0x8A150014
	wingetNoUpdate    = 0x8A15002B
	wingetReboot      = 0x8A150109
	wingetAlready     = 0x8A150061
	wingetNoInstaller = 0x8A150010
	statusDLLNotFound = 0xC0000135
)

func wingetNothingToDo(code int) bool {
	return code == 0 || uint32(code) == wingetNoApps || uint32(code) == wingetNoUpdate
}

// wingetNeedsUser: winget did not start (runApp gives code -1) or could not
// load its DLLs, so it is run again as the signed-in user. An upgrade that
// ran and failed is not repeated.
func wingetNeedsUser(_ string, code int, err error) bool {
	return (err != nil && code == -1) || uint32(code) == statusDLLNotFound
}

// wingetListNeedsUser: a list also goes to the user when it is neither a
// table nor a known "nothing to upgrade" answer.
func wingetListNeedsUser(stdout string, code int, err error) bool {
	if _, table := parseWingetUpgrade(stdout); table {
		return false
	}
	return err != nil || !wingetNothingToDo(code)
}

// parseWingetUpgrade reads the tables of `winget upgrade`. Headers are
// localised, so columns come from where the header words start; the order is
// Name, Id, Version, Available[, Source]. Some headers hold a space ("K
// dispozici"), so a column also has to start a value in the first row. table
// is true when a table was seen.
func parseWingetUpgrade(out string) (apps []AppUpdate, table bool) {
	apps = []AppUpdate{}
	lines := appLines(out)
	var cols []int
	for i, l := range lines {
		if len(l) >= 10 && strings.Trim(l, "-") == "" {
			cols = nil
			if i > 0 && i+1 < len(lines) {
				h, first := cells(lines[i-1]), cells(lines[i+1])
				for j := range h {
					if startsAt(h, j) && startsAt(first, j) {
						cols = append(cols, j)
					}
				}
			}
			if len(cols) < 4 {
				cols = nil
			}
			table = table || cols != nil
			continue
		}
		if cols == nil {
			continue
		}
		f, ok := wingetRow(cells(l), cols)
		if !ok {
			// rows are contiguous, the table ended
			cols = nil
			continue
		}
		// a truncated id ends in an ellipsis and cannot be targeted
		if !validAppID(f[1]) {
			continue
		}
		apps = append(apps, AppUpdate{Source: "winget", Name: f[0], ID: f[1], Installed: f[2], Available: f[3]})
	}
	return apps, table
}

func wingetRow(c []rune, cols []int) ([4]string, bool) {
	var f [4]string
	if len(c) <= cols[3] {
		return f, false
	}
	for k := 0; k < 4; k++ {
		start, end := cols[k], len(c)
		if k+1 < len(cols) && cols[k+1] < end {
			end = cols[k+1]
		}
		if !startsAt(c, start) {
			return f, false
		}
		if f[k] = cellText(c[start:end]); f[k] == "" {
			return f, false
		}
	}
	return f, true
}

// newestAppInstaller picks the highest version from
// ...\WindowsApps\Microsoft.DesktopAppInstaller_<version>_<arch>__<publisher>\winget.exe,
// of the Windows architecture arch when there is one. x86 is taken only on
// an x86 Windows.
func newestAppInstaller(paths []string, arch string) string {
	best, bestVer, bestOwn := "", []int(nil), false
	for _, p := range paths {
		dir := filepath.Base(filepath.Dir(p))
		a := appxArch(dir)
		if a == "" || (a == "x86" && arch != "x86") {
			continue
		}
		var v []int
		for _, n := range strings.Split(strings.Split(dir, "_")[1], ".") {
			i, err := strconv.Atoi(n)
			if err != nil {
				v = nil
				break
			}
			v = append(v, i)
		}
		own := a == arch
		if v != nil && (best == "" || (own && !bestOwn) || (own == bestOwn && versionLess(bestVer, v))) {
			best, bestVer, bestOwn = p, v, own
		}
	}
	return best
}

// appxArch is the architecture of a package folder
// <name>_<version>_<arch>__<publisher>, "" when the name is not one.
func appxArch(dir string) string {
	parts := strings.Split(dir, "_")
	if len(parts) < 5 {
		return ""
	}
	return parts[2]
}

func versionLess(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// parseBrewOutdated reads `brew outdated --json=v2`. Pinned items are left out,
// brew would refuse them.
func parseBrewOutdated(out string) ([]AppUpdate, error) {
	if i := strings.Index(out, "{"); i > 0 {
		out = out[i:]
	}
	var v struct {
		Formulae []brewItem `json:"formulae"`
		Casks    []brewItem `json:"casks"`
	}
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&v); err != nil {
		return nil, fmt.Errorf("brew outdated: %v", err)
	}
	apps := []AppUpdate{}
	for _, it := range append(v.Formulae, v.Casks...) {
		// tap formulae are user/tap/name, brew upgrade takes the short name
		id := it.Name[strings.LastIndex(it.Name, "/")+1:]
		if it.Pinned || !validAppID(id) {
			continue
		}
		var installed string
		var list []string
		if json.Unmarshal(it.InstalledVersions, &list) == nil && len(list) > 0 {
			installed = list[len(list)-1]
		} else {
			_ = json.Unmarshal(it.InstalledVersions, &installed)
		}
		apps = append(apps, AppUpdate{Source: "brew", ID: id, Name: it.Name, Installed: installed, Available: it.CurrentVersion})
	}
	return apps, nil
}

type brewItem struct {
	Name              string          `json:"name"`
	InstalledVersions json.RawMessage `json:"installed_versions"`
	CurrentVersion    string          `json:"current_version"`
	Pinned            bool            `json:"pinned"`
}

// parseMasOutdated reads `mas outdated`: "<id> <name> (<installed> -> <available>)".
func parseMasOutdated(out string) []AppUpdate {
	apps := []AppUpdate{}
	for _, l := range appLines(out) {
		if m := masRe.FindStringSubmatch(l); m != nil {
			apps = append(apps, AppUpdate{Source: "mas", ID: m[1], Name: m[2], Installed: m[3], Available: m[4]})
		}
	}
	return apps
}
