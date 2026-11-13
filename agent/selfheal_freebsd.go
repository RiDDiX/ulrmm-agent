// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type freebsdHeal struct{}

func newHealPlatform(_ *Agent) healPlatform { return freebsdHeal{} }

func (freebsdHeal) dataDir() string     { return nixAgentDir }
func (freebsdHeal) configPresent() bool { return healFileExists(etcConfig) }

func rcService(args ...string) error {
	out, err := healCmd(time.Minute, "service", append([]string{rcName()}, args...)...)
	if err != nil {
		return fmt.Errorf("service %s %s: %v: %s", rcName(), strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

// registered: the script exists and rc.conf enables it
func (freebsdHeal) serviceState() (installed, running bool) {
	if !healFileExists(rcScriptPath()) {
		return false, false
	}
	_, en := healCmd(time.Minute, "service", rcName(), "enabled")
	_, st := healCmd(time.Minute, "service", rcName(), "onestatus")
	return rcServiceState(en, st)
}

func (f freebsdHeal) ensureService(mainPath string) error {
	// a system without packages has no /usr/local/etc/rc.d yet
	if err := os.MkdirAll(filepath.Dir(rcScriptPath()), 0o755); err != nil {
		return err
	}
	if _, err := writeIfChanged(rcScriptPath(), rcScript(mainPath), 0o755); err != nil {
		return err
	}
	if out, err := healCmd(time.Minute, "sysrc", rcName()+"_enable=YES"); err != nil {
		return fmt.Errorf("sysrc: %v: %s", err, out)
	}
	return f.restartService()
}

// restart also starts a stopped service; one*: plain restart does nothing,
// with exit 0, when rc.conf does not enable it
func (freebsdHeal) restartService() error { return rcService("onerestart") }

func (freebsdHeal) registerSchedule(healBin string) error {
	_, err := writeIfChanged(healCronPath(), healCron(healBin), 0o644)
	return err
}

func (freebsdHeal) removeSchedule() error {
	if err := os.Remove(healCronPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f freebsdHeal) installDownload(path, mainPath string) error {
	return swapBinary(f, path, mainPath)
}

func (f freebsdHeal) restoreBinary(src, mainPath string) error { return swapBinary(f, src, mainPath) }
