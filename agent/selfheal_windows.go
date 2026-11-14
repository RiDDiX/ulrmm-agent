// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows/registry"
)

type windowsHeal struct{ a *Agent }

func newHealPlatform(a *Agent) healPlatform { return windowsHeal{a} }

// Not IdentTaskPrefix: the server removes unknown tasks with that
// prefix as orphans.
func healTaskName() string { return IdentWinSvcName + "-selfheal" }

func (w windowsHeal) dataDir() string { return w.a.ProgramDir }

func (windowsHeal) configPresent() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\`+IdentWinRegKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (w windowsHeal) svc() (service.Service, error) {
	return service.New(w.a, w.a.ServiceConfig)
}

func (w windowsHeal) serviceState() (bool, bool) {
	s, err := w.svc()
	if err != nil {
		return false, false
	}
	st, err := s.Status()
	if err == service.ErrNotInstalled {
		return false, false
	}
	if err != nil {
		// unknown: do not report a missing service
		return true, true
	}
	return true, st == service.StatusRunning
}

func (w windowsHeal) ensureService(_ string) error {
	s, err := w.svc()
	if err != nil {
		return err
	}
	if err := s.Install(); err != nil {
		return err
	}
	return s.Start()
}

func (w windowsHeal) restartService() error {
	s, err := w.svc()
	if err != nil {
		return err
	}
	_ = s.Stop()
	time.Sleep(3 * time.Second)
	return s.Start()
}

// /F replaces the task an earlier build made with schtasks /SC.
func (w windowsHeal) registerSchedule(healBin string) error {
	// the definition goes where only admins can write: it says what SYSTEM runs
	if err := createWinTempDir(); err != nil {
		return err
	}
	def := filepath.Join(w.a.WinTmpDir, "selfheal-task.xml")
	if err := os.WriteFile(def, healTaskXML(healBin), 0o600); err != nil {
		return err
	}
	defer os.Remove(def)
	out, err := healCmd(time.Minute, "schtasks.exe", "/Create", "/F", "/TN", healTaskName(), "/XML", def)
	if err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	return nil
}

func (windowsHeal) removeSchedule() error {
	_, err := healCmd(time.Minute, "schtasks.exe", "/Delete", "/TN", healTaskName(), "/F")
	return err
}

// The Windows build is the installer: it stops the service, replaces the files
// and starts it again, so it has to outlive this process.
func (w windowsHeal) installDownload(path, _ string) error {
	dir := w.a.WinTmpDir
	// the installer runs as SYSTEM: never from a directory others can write
	if err := createWinTempDir(); err != nil {
		return err
	}
	installer := filepath.Join(dir, fmt.Sprintf("selfheal-%d.exe", time.Now().Unix()))
	if err := copyFileAtomic(path, installer, 0o755); err != nil {
		return err
	}
	return startDetached(installer, healSetupArgs(filepath.Join(dir, "selfheal-install.log"))...)
}

// a running exe cannot be replaced on Windows
func (w windowsHeal) restoreBinary(src, mainPath string) error {
	s, err := w.svc()
	if err != nil {
		return err
	}
	_ = s.Stop()
	var cerr error
	for i := 0; i < 10; i++ {
		time.Sleep(2 * time.Second)
		if cerr = copyFileAtomic(src, mainPath, 0o755); cerr == nil {
			break
		}
	}
	if cerr != nil {
		_ = s.Start()
		return cerr
	}
	return s.Start()
}
