// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
)

// System information, install, update and maintenance with no Windows API,
// so the Linux test run covers them.

// winOSArch is the word the server reads the architecture from: it looks
// for "64 bit" and "32 bit" in operating_system.
func winOSArch(arch string) string {
	switch strings.ToLower(arch) {
	case "x86_64", "amd64":
		return "64 bit"
	case "x86", "386", "i386", "i686":
		return "32 bit"
	case "arm64", "aarch64":
		return "ARM 64 bit"
	}
	return ""
}

// formatWinOS is operating_system, for example
// "Windows 11 Pro, 64 bit v24H2 (build 26100)". Without a display version
// the " v..." part is left out.
func formatWinOS(name, arch, platVer, build string) string {
	if platVer == "" {
		return fmt.Sprintf("%s, %s (build %s)", name, arch, build)
	}
	return fmt.Sprintf("%s, %s v%s (build %s)", name, arch, platVer, build)
}

// noUser is logged_in_username when nobody is signed in; the server keeps
// the last known user for it.
const noUser = "None"

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func firstName(names []string) string {
	for _, n := range names {
		if n != "" {
			return n
		}
	}
	return ""
}

// pickLoggedOnUser chooses logged_in_username. sessions are the user names
// of the terminal sessions (sessionsOK false when they could not be listed);
// logons are the names from the logon sessions, asked only when needed. A
// name with non-ASCII characters is taken from the logon sessions, which
// give it in lower case.
func pickLoggedOnUser(sessions []string, sessionsOK bool, logons func() []string) string {
	if sessionsOK {
		name := firstName(sessions)
		if name == "" {
			return noUser
		}
		if isASCII(name) {
			return name
		}
	}
	if name := firstName(logons()); name != "" {
		return name
	}
	return noUser
}

// meshNodeIDUsable: the mesh agent prints "not defined" until it has
// registered with its server.
func meshNodeIDUsable(id string) bool {
	return id != "" && !strings.Contains(strings.ToLower(id), "not defined")
}

func meshInstallArgs(proxy string) []string {
	args := []string{"-fullinstall"}
	if proxy != "" {
		args = append(args, "--WebProxy="+proxy)
	}
	return args
}

// checkInOverrides maps the registry values an administrator can set to the
// check-in intervals they replace.
func checkInOverrides(c *AgentCheckInConfig) map[string]*int {
	return map[string]*int{
		"CheckInHello":     &c.Hello,
		"CheckInAgentInfo": &c.AgentInfo,
		"CheckInWinSvc":    &c.WinSvc,
		"CheckInPubIP":     &c.PubIP,
		"CheckInDisks":     &c.Disks,
		"CheckInSW":        &c.SW,
		"CheckInWMI":       &c.WMI,
		"CheckInSyncMesh":  &c.SyncMesh,
	}
}

// applyCheckInOverrides takes "min,max" ranges and CheckInLimitData from
// get; a value that is not a usable range leaves the server's interval.
func applyCheckInOverrides(c AgentCheckInConfig, get func(name string) string) AgentCheckInConfig {
	for name, v := range checkInOverrides(&c) {
		if n := regRangeToInt(get(name)); n > 0 {
			*v = n
		}
	}
	if get("CheckInLimitData") == "true" {
		c.LimitData = true
	}
	return c
}

var (
	updaterNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+\.[Ee][Xx][Ee]$`)
	versionTextRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// checkUpdateRequest validates what agentupdate takes from the server
// before it becomes a path: the installer must be a bare .exe name and the
// version ends up in the name of the update log. Without a hash the
// download has to come over https.
func checkUpdateRequest(url, inno, version, sha string) error {
	if !plainFileName(inno) || !updaterNameRe.MatchString(inno) {
		return fmt.Errorf("refusing installer name %q", inno)
	}
	if !versionTextRe.MatchString(version) || strings.Contains(version, "..") {
		return fmt.Errorf("refusing version %q", version)
	}
	if sha == "" && !strings.HasPrefix(strings.ToLower(url), "https://") {
		return errors.New("refusing an unverified download over plain http")
	}
	return nil
}

func updateLogName(version string) string {
	return fmt.Sprintf("%s_update_v%s.txt", IdentArtifact, version)
}

// isChecksRun tells a check run of this agent (-m runchecks or
// -m checkrunner) from anything else; paths compare without case.
func isChecksRun(exe string, args []string, self string) bool {
	if self == "" || !strings.EqualFold(exe, self) {
		return false
	}
	for _, a := range args {
		if a == "runchecks" || a == "checkrunner" {
			return true
		}
	}
	return false
}

// Windows release assets of the script runtimes; "" when there is none for
// the architecture.
func winNushellRelease(goarch, ver string) string {
	triple := map[string]string{
		"amd64": "x86_64-pc-windows-msvc",
		"arm64": "aarch64-pc-windows-msvc",
	}[goarch]
	if triple == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/nu-%s-%s.zip", nuReleaseURL, ver, ver, triple)
}

func winDenoRelease(goarch, ver string) string {
	if goarch != "amd64" {
		return ""
	}
	return fmt.Sprintf("%s/%s/deno-x86_64-pc-windows-msvc.zip", denoReleaseURL, ver)
}

// pythonZipURL: the brand's own Python host, else the RMM's agentdist.
func pythonZipURL(brandURL, baseURL, zipName string) string {
	base := brandURL
	if base == "" {
		base = strings.TrimSuffix(baseURL, "/") + "/agentdist/python"
	}
	return strings.TrimSuffix(base, "/") + "/" + zipName
}

// findFile looks for a file called name below dir, the top level first.
func findFile(dir, name string) (string, error) {
	top := filepath.Join(dir, name)
	if st, err := os.Stat(top); err == nil && st.Mode().IsRegular() {
		return top, nil
	}
	found := ""
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(d.Name(), name) {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("%s not found in the archive", name)
	}
	return found, nil
}

// powercfgSteps turn off sleep, hibernation, disk and monitor timeouts and
// the lid action for one power source ("ac" or "dc").
func powercfgSteps(src string) [][]string {
	steps := [][]string{{"/set" + src + "valueindex", "scheme_current", "sub_buttons", "lidaction", "0"}}
	for _, t := range []string{"standby", "hibernate", "disk", "monitor"} {
		steps = append(steps, []string{"/x", "-" + t + "-timeout-" + src, "0"})
	}
	return steps
}

// psEncoded is a script for powershell -EncodedCommand (UTF-16LE, base64),
// which needs no quoting on the command line.
func psEncoded(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// existingInstallText is printed when -m install finds a configured agent.
// The uninstaller may return before it has finished (the NSIS one always
// does), so the text does not rely on its exit.
func existingInstallText(uninstaller string) string {
	return "Existing installation found and must be removed before attempting to reinstall.\n" +
		fmt.Sprintf("Remove it from the dashboard, or run \"%s\" /VERYSILENT /UNINSTALLCODE=<uninstall code>. ", uninstaller) +
		"Start this installer again once the uninstaller's folder is gone."
}

// The setup and its uninstaller take Inno's switches. NSIS reads its own /S
// before the script runs; without it the NSIS runtime may show an error box
// that nobody sees when the service starts the setup. Inno Setup has no /S
// switch of its own.
// /S comes before /LOG= and /UNINSTALLCODE=, whose values run to the next
// switch.
func updateSetupArgs(logFile string) []string {
	return []string{"/VERYSILENT", "/S", "/LOG=" + logFile}
}

func healSetupArgs(logFile string) []string {
	return []string{"/VERYSILENT", "/S", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG=" + logFile}
}

func uninstallerArgs(code string) []string {
	args := []string{"/VERYSILENT", "/S"}
	if code != "" {
		args = append(args, "/UNINSTALLCODE="+code)
	}
	return args
}
