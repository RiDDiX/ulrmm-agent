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
}

const (
	// the server waits 120 s for a list and 600 s for an upgrade
	appListMax    = 110 * time.Second
	appUpgradeMax = 570 * time.Second
	appTailMax    = 2000
	appIDsMax     = 100
	// same limit as a choco install
	wingetInstallMax  = 1200 * time.Second
	wingetInstallTail = 64 << 10
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

// upgradeEach runs one upgrade per id until the time is up.
func upgradeEach(ctx context.Context, ids []string, run func(ctx context.Context, id string) (out string, ok bool, err error)) []AppUpgradeResult {
	res := make([]AppUpgradeResult, 0, len(ids))
	for _, id := range ids {
		if ctx.Err() != nil {
			res = append(res, AppUpgradeResult{ID: id, OutputTail: "not started: time limit reached"})
			continue
		}
		out, ok, err := run(ctx, id)
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
	cmd.WaitDelay = 10 * time.Second
	attr(cmd)
	err = cmd.Run()
	if err == nil && (o.over || e.over) {
		err = errOutputTooLarge
	}
	code = -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		err = nil
	}
	if ctx.Err() != nil {
		err = errors.New("time limit reached")
	}
	return o.String(), e.String(), code, err
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
	return wingetInstallResult(installWinget(ctx, id))
}

// wingetInstallArgs: machine scope, SYSTEM has no profile worth installing
// into and the retry as the user runs elevated.
func wingetInstallArgs(id string) []string {
	return []string{"install", "--id", id, "--exact", "--source", "winget", "--scope", "machine", "--silent",
		"--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}
}

func wingetInstallResult(stdout, stderr string, code int, err error) (string, int64) {
	out := outputTail(stdout+"\n"+stderr, wingetInstallTail)
	if err != nil {
		return strings.TrimLeft(out+"\n"+err.Error(), "\n"), -1
	}
	if code != 0 {
		out = strings.TrimLeft(out+fmt.Sprintf("\nexit code 0x%08X", uint32(code)), "\n")
	}
	return out, int64(uint32(code))
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
// finishes it. STATUS_DLL_NOT_FOUND is winget.exe started from its package
// folder as SYSTEM, which cannot load its framework packages (Windows 11,
// winget 1.29); it prints nothing.
const (
	wingetNoApps      = 0x8A150014
	wingetNoUpdate    = 0x8A15002B
	wingetReboot      = 0x8A150109
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
// ...\WindowsApps\Microsoft.DesktopAppInstaller_<version>_<arch>__<publisher>\winget.exe
func newestAppInstaller(paths []string) string {
	best, bestVer := "", []int(nil)
	for _, p := range paths {
		parts := strings.Split(filepath.Base(filepath.Dir(p)), "_")
		if len(parts) < 2 {
			continue
		}
		var v []int
		for _, n := range strings.Split(parts[1], ".") {
			i, err := strconv.Atoi(n)
			if err != nil {
				v = nil
				break
			}
			v = append(v, i)
		}
		if v != nil && (best == "" || versionLess(bestVer, v)) {
			best, bestVer = p, v
		}
	}
	return best
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
