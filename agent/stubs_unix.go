// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/kardianos/service"
	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

// Windows-only parts, from Linux and macOS. Replies are what the server and
// the web UI get from posix agents.

func ShowStatus(version string) { fmt.Println(version) }

func (a *Agent) Start(_ service.Service) error { return nil }
func (a *Agent) Stop(_ service.Service) error  { return nil }
func (a *Agent) InstallService() error         { return nil }

func (a *Agent) GetAgentCheckInConfig(c AgentCheckInConfig) AgentCheckInConfig { return c }

func EnableRDP()                      {}
func protectConfigKey() error         { return nil }
func protectService() error           { return nil }
func createWinTempDir() error         { return nil }
func RestrictToAdmins(_ string) error { return nil }
func DisableSleepHibernate()          {}
func EnablePing()                     {}

func (a *Agent) SendSoftware()                            {}
func (a *Agent) UninstallCleanup()                        {}
func (a *Agent) GetPython(_ bool)                         {}
func (a *Agent) PatchMgmnt(_ bool) error                  { return nil }
func (a *Agent) rearmPatchMgmt()                          {}
func (a *Agent) GetInstalledSoftware() []rmm.InstalledApp { return []rmm.InstalledApp{} }
func (a *Agent) ChecksRunning() bool                      { return checksBusy.Load() }
func (a *Agent) InstallChoco()                            {}
func (a *Agent) InstallWithChoco(_ string) (string, error) {
	return "", nil
}
func installWinget(_ context.Context, _ string) (string, string, int, string, error) {
	return "", "", -1, "", errors.New("winget is only available on Windows")
}

func (a *Agent) GetWinUpdates(_ bool)      {}
func (a *Agent) InstallUpdates(_ []string) {}

func (a *Agent) installMesh(_, _, _ string) (string, error) {
	return "", errors.New("not implemented")
}

func (a *Agent) CreateSchedTask(_ SchedTask) (bool, error) { return false, nil }
func DeleteSchedTask(_ string) error                       { return nil }
func ListSchedTasks() []string                             { return []string{} }

func (a *Agent) GetEventLog(_ string, _ int, _ time.Duration) []rmm.EventEntry {
	return []rmm.EventEntry{}
}

func (a *Agent) GetServices() []rmm.WinService                  { return []rmm.WinService{} }
func (a *Agent) GetServiceDetail(_ string) rmm.WinService       { return rmm.WinService{} }
func GetServiceStatus(_ string) (string, error)                 { return "", nil }
func (a *Agent) ControlService(_, _ string) rmm.SvcActionResult { return noWinSvc }
func (a *Agent) EditService(_, _ string) rmm.SvcActionResult    { return noWinSvc }

var noWinSvc = rmm.SvcActionResult{OK: false, Reason: "/na"}

// CMD and CMDShell run Windows programs; posix commands go through CmdV2.
func CMD(_ string, _ []string, _ int, _ bool) ([2]string, error) { return [2]string{}, nil }

func CMDShell(_ string, _ []string, _ string, _ int, _, _, _ bool, _, _ *string, _ *nats.Conn) ([2]string, error) {
	return [2]string{}, nil
}

func BrowseRegistry(_ string, _, _ int) ([]string, []string, bool, error) {
	return nil, nil, false, errors.New("registry access is only supported on Windows")
}

func CreateRegistryKey(_ string) error {
	return errors.New("registry key creation is only supported on Windows")
}

func DeleteRegistryKey(_ string) error {
	return errors.New("deleting registry keys is only supported on Windows")
}

func RenameRegistryKey(_, _ string) error {
	return errors.New("renaming registry keys is only supported on Windows")
}

func CreateRegistryValue(_, _, _ string, _ interface{}) (map[string]interface{}, error) {
	return nil, errors.New("creating registry values is only supported on Windows")
}

func DeleteRegistryValue(_, _ string) error {
	return errors.New("deleting registry values is only supported on Windows")
}

func RenameRegistryValue(_, _, _ string) (string, error) {
	return "", errors.New("renaming registry values is only supported on Windows")
}

func ModifyRegistryValue(_, _, _ string, _ interface{}) (map[string]interface{}, error) {
	return nil, errors.New("modifying registry values is only supported on Windows")
}

var errWinTerminal = errors.New("this terminal type is only available on Windows")

func StartTerminalSessionWindows(_, _, _, _ string, _ bool, _ *nats.Conn, _ *logrus.Logger) error {
	return errWinTerminal
}
func FeedTerminalInputWindows(_, _ string) error            { return errWinTerminal }
func ResizeTerminalSessionWindows(_ string, _, _ int) error { return errWinTerminal }
func KillTerminalSessionWindows(_ string) error             { return errWinTerminal }
