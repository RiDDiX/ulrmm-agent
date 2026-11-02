// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package agent

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// the shell a package script runs with
const pkgShell = "powershell"

// free bytes on the volume of dir; tests replace it
var pkgFree = sdioFreeSpace

// work dirs go in the protected work directory, like scripts
func (a *Agent) pkgRoot() (string, error) {
	if err := createWinTempDir(); err != nil {
		return "", err
	}
	work, _ := winWorkDirs()
	return work, nil
}

// msiexec, Windows PowerShell and PowerShell 7 come from fixed places: a
// SYSTEM service must not take them from a PATH entry users can write.
func pkgSystemExe(name string) (string, bool) {
	switch strings.ToLower(name) {
	case "msiexec.exe":
		return filepath.Join(os.Getenv("WINDIR"), "System32", "msiexec.exe"), true
	case "powershell.exe":
		return getPowershellExe(), true
	case "pwsh.exe":
		pf := os.Getenv("ProgramW6432")
		if pf == "" {
			pf = os.Getenv("ProgramFiles")
		}
		return filepath.Join(pf, "PowerShell", "7", "pwsh.exe"), true
	}
	return "", false
}

// pkgCommand runs exe with the plan's argument string, unchanged, in dir as
// SYSTEM. At the deadline the job object and so everything it started is
// terminated.
func (a *Agent) pkgCommand(ctx context.Context, exe string, r *pkgRun, dir string, env []string, out io.Writer) (code int, timedOut bool, err error) {
	cmd := exec.CommandContext(ctx, exe)
	line := `"` + exe + `"`
	if r.Args != "" {
		line += " " + r.Args
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return winExec(ctx, cmd, out, out)
}

// as uint32, like the winget results: 386 builds would give large codes negative
func pkgExit(code int) int64 { return int64(uint32(code)) }
