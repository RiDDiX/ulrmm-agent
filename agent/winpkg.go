// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// Software inventory, Windows Update and Chocolatey, no Windows API,
// so the Linux test run covers them.

// Values of one Uninstall subkey.
type uninstallEntry struct {
	name, version, publisher, installDate string
	source, location, uninstall           string
	sizeKiB                               uint64
}

func (e uninstallEntry) record() rmm.InstalledApp {
	return rmm.InstalledApp{
		Title:        CleanString(e.name),
		Ver:          CleanString(e.version),
		Vendor:       CleanString(e.publisher),
		Installed:    softwareInstallDate(e.installDate),
		SizeText:     ByteCountSI(e.sizeKiB * 1024),
		Origin:       CleanString(e.source),
		Path:         CleanString(e.location),
		UninstallCmd: CleanString(e.uninstall),
	}
}

// softwareInstallDate turns the registry's YYYYMMDD into the text the web
// UI has always shown: month without padding, 5 March 2024 is "2024-3-05".
// A missing or broken date is "01-1-01".
func softwareInstallDate(raw string) string {
	t, err := time.Parse("20060102", strings.TrimSpace(raw))
	if err != nil {
		t = time.Time{}
	}
	return fmt.Sprintf("%02d-%d-%02d", t.Year(), int(t.Month()), t.Day())
}

// wuaScanQuery: every installed update plus the software updates that are
// still missing and not hidden. Missing drivers only when the server asks
// for them; older servers drop rows without a KB.
func wuaScanQuery(drivers bool) string {
	q := "IsInstalled=1 or IsInstalled=0 and Type='Software' and IsHidden=0"
	if drivers {
		q += " or IsInstalled=0 and Type='Driver' and IsHidden=0"
	}
	return q
}

// wuaUpdateType maps IUpdate.Type: 2 is utDriver, anything else software.
func wuaUpdateType(t int64) string {
	if t == 2 {
		return "driver"
	}
	return "software"
}

var updateIDRe = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// wuaIDQuery is the search for one update id; anything but a GUID never
// reaches the search string.
func wuaIDQuery(guid string) (string, bool) {
	if !updateIDRe.MatchString(guid) {
		return "", false
	}
	return "UpdateID='" + guid + "'", true
}

// wuaIDQueries: the plain id search, then the same id as a driver, so a
// driver update is not taken for superseded.
func wuaIDQueries(guid string) ([]string, bool) {
	q, ok := wuaIDQuery(guid)
	if !ok {
		return nil, false
	}
	return []string{q, q + " and Type='Driver'"}, true
}

// wuaSucceeded reads an OperationResultCode: 2 succeeded, 3 succeeded with
// errors; 0 not started, 1 in progress, 4 failed, 5 aborted.
func wuaSucceeded(code int64) bool {
	return code == 2 || code == 3
}

const (
	chocoScriptURL = "https://chocolatey.org/install.ps1"
	chocoTimeout   = 1200
)

var (
	chocoNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	sha256Re    = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
)

// chocoScriptSource prefers the install script the server pins with a
// sha256; without both, the public script is fetched as before.
func chocoScriptSource(url, sha string) (string, string) {
	if url != "" && sha256Re.MatchString(sha) {
		return url, sha
	}
	return chocoScriptURL, ""
}

// chocoArgs refuses names choco could read as an option or that are no
// package id at all.
func chocoArgs(name string) ([]string, error) {
	if !chocoNameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid package name: %q", name)
	}
	return []string{"install", name, "--yes", "--force", "--force-dependencies", "--no-progress"}, nil
}

// chocoExitOK: 1605/1614 (not installed), 1641/3010 (restart needed) are
// successes for choco.
func chocoExitOK(code int) bool {
	switch code {
	case 0, 1605, 1614, 1641, 3010:
		return true
	}
	return false
}

// chocoResult is the text for the chocoresult PATCH. On success it is
// stderr when there is any, else stdout, as the server's success test
// expects. A failure keeps the output and names the reason.
func chocoResult(stdout, stderr string, code int, timedOut bool, runErr error) (string, error) {
	var err error
	switch {
	case timedOut:
		err = fmt.Errorf("choco timed out after %d seconds", chocoTimeout)
	case runErr != nil:
		err = runErr
	case !chocoExitOK(code):
		err = fmt.Errorf("choco exited with code %d", code)
	}
	if err == nil {
		if stderr != "" {
			return stderr, nil
		}
		return stdout, nil
	}
	parts := []string{}
	for _, s := range []string{stdout, stderr, err.Error()} {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n"), err
}
