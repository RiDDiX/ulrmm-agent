// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func appCmdAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// wingetPath: the agent runs as SYSTEM, which has no working winget alias; the
// binary lives in the App Installer package folder. PATH is for servers with a
// winget installed by hand.
func wingetPath() (string, error) {
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	m, _ := filepath.Glob(filepath.Join(pf, "WindowsApps", "Microsoft.DesktopAppInstaller_*", "winget.exe"))
	if p := newestAppInstaller(m); p != "" {
		return p, nil
	}
	// no PATH fallback: a user-writable PATH entry would run as SYSTEM
	return "", errors.New("winget is not installed")
}

// runWinget runs winget as SYSTEM and, when retry finds no usable answer in
// that, once more as the signed-in user.
func runWinget(ctx context.Context, wg string, retry func(stdout string, code int, err error) bool, args ...string) (stdout, stderr string, code int, err error) {
	stdout, stderr, code, err = runAppWith(ctx, wingetSystemAttr(wg), filepath.Dir(wg), append([]string{wg}, args...)...)
	if ctx.Err() == nil && retry(stdout, code, err) {
		return runWingetAsUser(ctx, wg, args...)
	}
	if err != nil {
		err = fmt.Errorf("winget: %v", err)
	}
	return stdout, stderr, code, err
}

// runWingetAsUser: on Windows 11 the package-folder winget.exe fails as SYSTEM
// with 0xC0000135, so it runs with the signed-in user's token; getUserToken
// takes an administrator's elevated linked token, so machine-wide upgrades
// work. The alias in the user's %LOCALAPPDATA%\Microsoft\WindowsApps starts
// winget inside its package; without it the package-folder exe is tried.
func runWingetAsUser(ctx context.Context, pkgExe string, args ...string) (stdout, stderr string, code int, err error) {
	tok, err := getUserToken()
	if err != nil {
		return "", "", -1, errors.New("winget needs a signed-in user on this Windows")
	}
	defer tok.Close()
	exe, dir := pkgExe, filepath.Dir(pkgExe)
	var aliasH windows.Handle
	if home, err := tok.Token().GetUserProfileDirectory(); err == nil {
		dir = home
		alias := filepath.Join(home, "AppData", "Local", "Microsoft", "WindowsApps", "winget.exe")
		if h, ok := wingetAlias(alias, filepath.Dir(filepath.Dir(pkgExe))); ok {
			exe, aliasH = alias, h
		}
	}
	// Env stays nil: os/exec builds the user's environment from the token
	asUser := func(cmd *exec.Cmd) {
		appCmdAttr(cmd)
		cmd.SysProcAttr.Token = syscall.Token(tok.Token())
	}
	stdout, stderr, code, err = runAppWith(ctx, asUser, dir, append([]string{exe}, args...)...)
	if aliasH != 0 {
		windows.CloseHandle(aliasH)
		// the alias did not start (no exit code): once more with the package exe
		if err != nil && code == -1 && ctx.Err() == nil {
			stdout, stderr, code, err = runAppWith(ctx, asUser, dir, append([]string{pkgExe}, args...)...)
		}
	}
	if err != nil {
		err = fmt.Errorf("winget as user: %v", err)
	}
	return stdout, stderr, code, err
}

// wingetAlias: path is an App Execution Alias that starts an exe of the App
// Installer package. The folder is the user's own, so anything else there
// could be planted and would run with the elevated token. The returned
// handle shares neither write nor delete: while it is open the alias cannot
// be replaced or renamed. The caller closes it.
func wingetAlias(path, windowsApps string) (windows.Handle, bool) {
	// Lstat: the alias is a reparse point Stat cannot follow
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
		return 0, false
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, false
	}
	buf := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var n uint32
	if windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &n, nil) == nil {
		if target, ok := appExecLinkTarget(buf[:n]); ok && inAppInstaller(target, windowsApps) {
			return h, true
		}
	}
	windows.CloseHandle(h)
	return 0, false
}

func listAppUpdates(ctx context.Context) ([]AppUpdate, error) {
	wg, err := wingetPath()
	if err != nil {
		return nil, err
	}
	stdout, stderr, code, err := runWinget(ctx, wg, wingetListNeedsUser, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity")
	if err != nil {
		return nil, err
	}
	apps, table := parseWingetUpgrade(stdout)
	if table || wingetNothingToDo(code) {
		return apps, nil
	}
	return nil, fmt.Errorf("winget failed (0x%08X): %s", uint32(code), outputTail(stdout+"\n"+stderr, appTailMax))
}

func upgradeApps(ctx context.Context, source string, ids []string) ([]AppUpgradeResult, error) {
	if source != "" && source != "winget" {
		return nil, errors.New("unknown source")
	}
	wg, err := wingetPath()
	if err != nil {
		return nil, err
	}
	return upgradeEach(ctx, ids, func(ctx context.Context, id string) (string, bool, error) {
		stdout, stderr, code, err := runWinget(ctx, wg, wingetNeedsUser, "upgrade", "--id", id, "--exact", "--silent",
			"--include-unknown", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity")
		out := stdout + "\n" + stderr
		if err == nil && code != 0 {
			out += fmt.Sprintf("\nexit code 0x%08X", uint32(code))
		}
		// already current, or installed and waiting for a reboot
		return out, code == 0 || uint32(code) == wingetNoUpdate || uint32(code) == wingetReboot, err
	}), nil
}

func installWinget(ctx context.Context, id string) (stdout, stderr string, code int, err error) {
	wg, err := wingetPath()
	if err != nil {
		return "", "", -1, err
	}
	return runWinget(ctx, wg, wingetNeedsUser, wingetInstallArgs(id)...)
}

// wingetSystemAttr puts the VC++ runtime package winget links against on
// PATH. As SYSTEM nothing resolves it, which is the 0xC0000135 above; with
// it winget runs without a signed-in user. WindowsApps is writable only by
// TrustedInstaller, so the extra PATH entries cannot be planted.
func wingetSystemAttr(wg string) func(*exec.Cmd) {
	arch := map[string]string{"amd64": "x64", "386": "x86", "arm64": "arm64"}[runtime.GOARCH]
	m, _ := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(wg)), "Microsoft.VCLibs.140.00.UWPDesktop_*_"+arch+"__8wekyb3d8bbwe", "*.dll"))
	vc := newestAppInstaller(m)
	return func(cmd *exec.Cmd) {
		appCmdAttr(cmd)
		if vc == "" {
			return
		}
		env := os.Environ()
		for i, kv := range env {
			if strings.HasPrefix(strings.ToUpper(kv), "PATH=") {
				env[i] = "PATH=" + filepath.Dir(vc) + ";" + filepath.Dir(wg) + ";" + kv[5:]
			}
		}
		cmd.Env = env
	}
}
