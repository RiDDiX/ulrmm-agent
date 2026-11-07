// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type darwinHeal struct{}

func newHealPlatform(_ *Agent) healPlatform { return darwinHeal{} }

func (darwinHeal) dataDir() string     { return nixAgentDir }
func (darwinHeal) configPresent() bool { return healFileExists(etcConfig) }
func healLabel() string                { return IdentMacPlistLabel + ".selfheal" }
func healPlistPath() string            { return "/Library/LaunchDaemons/" + healLabel() + ".plist" }

// print fails for a job launchd does not know.
func launchdLoaded(label string) (loaded, running bool) {
	out, err := healCmd(30*time.Second, "launchctl", "print", "system/"+label)
	if err != nil {
		return false, false
	}
	return true, strings.Contains(out, "state = running")
}

// Reports launchctl's output on failure.
func launchctl(args ...string) error {
	out, err := healCmd(time.Minute, "launchctl", args...)
	if err != nil {
		return fmt.Errorf("%s: %v: %s", args[0], err, out)
	}
	return nil
}

func (darwinHeal) serviceState() (installed, running bool) {
	loaded, running := launchdLoaded(IdentMacPlistLabel)
	return loaded && healFileExists(macPlistPath), running
}

// Rewrites the LaunchDaemon and loads it fresh.
func (darwinHeal) ensureService(mainPath string) error {
	if err := os.WriteFile(macPlistPath, []byte(macServicePlist(mainPath)), 0o644); err != nil {
		return err
	}
	_ = launchctl("bootout", "system/"+IdentMacPlistLabel)
	return launchctl("bootstrap", "system", macPlistPath)
}

// restartService loads a job launchd lost, or restarts the running one.
func (darwinHeal) restartService() error {
	if loaded, _ := launchdLoaded(IdentMacPlistLabel); loaded {
		return launchctl("kickstart", "-k", "system/"+IdentMacPlistLabel)
	}
	return launchctl("bootstrap", "system", macPlistPath)
}

func (darwinHeal) registerSchedule(healBin string) error {
	plist := launchdPlist(healLabel(), []string{healBin, "-m", "selfheal"},
		"<key>StartInterval</key><integer>900</integer>",
		"<key>RunAtLoad</key><false/>")
	changed, err := writeIfChanged(healPlistPath(), plist, 0o644)
	if err != nil {
		return err
	}
	loaded, _ := launchdLoaded(healLabel())
	if changed && loaded {
		_, _ = healCmd(time.Minute, "launchctl", "bootout", "system/"+healLabel())
		loaded = false
	}
	if !loaded {
		if out, err := healCmd(time.Minute, "launchctl", "bootstrap", "system", healPlistPath()); err != nil {
			return fmt.Errorf("bootstrap self-healing job: %v: %s", err, out)
		}
	}
	return nil
}

func (darwinHeal) removeSchedule() error {
	_, _ = healCmd(time.Minute, "launchctl", "bootout", "system/"+healLabel())
	return os.Remove(healPlistPath())
}

func (d darwinHeal) installDownload(path, mainPath string) error {
	return swapBinary(d, path, mainPath)
}

func (d darwinHeal) restoreBinary(src, mainPath string) error { return swapBinary(d, src, mainPath) }
