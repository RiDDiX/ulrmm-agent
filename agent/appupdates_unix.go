// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

func appCmdAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// sudo passes SIGTERM on to brew/mas
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
}

func macBin(name string) string {
	for _, d := range []string{"/opt/homebrew/bin/", "/usr/local/bin/"} {
		if st, err := os.Stat(d + name); err == nil && st.Mode().IsRegular() {
			return d + name
		}
	}
	return ""
}

// consoleUID is the user at the Mac's screen; root means the login window.
func consoleUID() (uint32, error) {
	if st, err := os.Stat("/dev/console"); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Uid != 0 {
			return s.Uid, nil
		}
	}
	return 0, errors.New("no user is logged in at the console")
}

// brewUID: brew refuses root and writes to its prefix, so it runs as the
// owner of the installation, else as the console user.
func brewUID(brew string) (uint32, error) {
	if st, err := os.Stat(brew); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Uid != 0 {
			return s.Uid, nil
		}
	}
	return consoleUID()
}

func asUser(uid uint32, argv ...string) []string {
	u := strconv.FormatUint(uint64(uid), 10)
	return append([]string{"/usr/bin/sudo", "-n", "-H", "-u", "#" + u, "--"}, argv...)
}

// mas talks to the App Store in the user's login session
func inUserSession(uid uint32, argv ...string) []string {
	return append([]string{"/bin/launchctl", "asuser", strconv.FormatUint(uint64(uid), 10)}, asUser(uid, argv...)...)
}

func listAppUpdates(ctx context.Context) ([]AppUpdate, error) {
	if runtime.GOOS != "darwin" {
		return []AppUpdate{}, nil
	}
	return listMacUpdates(ctx, macBin("brew"), macBin("mas"), consoleUID)
}

// listMacUpdates: mas needs a user at the screen. At the login window only
// brew is asked, so an unattended Mac still reports its brew updates.
func listMacUpdates(ctx context.Context, brew, mas string, console func() (uint32, error)) ([]AppUpdate, error) {
	apps := []AppUpdate{}
	if brew != "" {
		uid, err := brewUID(brew)
		if err != nil {
			return nil, err
		}
		stdout, stderr, code, err := runApp(ctx, "/", asUser(uid, brew, "outdated", "--json=v2")...)
		if err == nil && code != 0 {
			err = fmt.Errorf("exit code %d: %s", code, outputTail(stderr, appTailMax))
		}
		if err != nil {
			return nil, fmt.Errorf("brew outdated: %v", err)
		}
		b, err := parseBrewOutdated(stdout)
		if err != nil {
			return nil, err
		}
		apps = append(apps, b...)
	}
	if mas != "" {
		uid, err := console()
		if err != nil {
			return apps, nil
		}
		stdout, stderr, code, err := runApp(ctx, "/", inUserSession(uid, mas, "outdated")...)
		if err == nil && code != 0 {
			err = fmt.Errorf("exit code %d: %s", code, outputTail(stderr, appTailMax))
		}
		if err != nil {
			return nil, fmt.Errorf("mas outdated: %v", err)
		}
		apps = append(apps, parseMasOutdated(stdout)...)
	}
	return apps, nil
}

func upgradeApps(ctx context.Context, source string, ids []string) ([]AppUpgradeResult, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("app updates are not available on " + runtime.GOOS)
	}
	var argv func(uid uint32, id string) []string
	var uid uint32
	var err error
	switch source {
	case "brew":
		brew := macBin("brew")
		if brew == "" {
			return nil, errors.New("brew is not installed")
		}
		uid, err = brewUID(brew)
		argv = func(uid uint32, id string) []string { return asUser(uid, brew, "upgrade", id) }
	case "mas":
		mas := macBin("mas")
		if mas == "" {
			return nil, errors.New("mas is not installed")
		}
		uid, err = consoleUID()
		argv = func(uid uint32, id string) []string { return inUserSession(uid, mas, "upgrade", id) }
	default:
		return nil, errors.New("unknown source")
	}
	if err != nil {
		return nil, err
	}
	return upgradeEach(ctx, ids, func(ctx context.Context, id string) (string, bool, error) {
		stdout, stderr, code, err := runApp(ctx, "/", argv(uid, id)...)
		out := stdout + "\n" + stderr
		if err == nil && code != 0 {
			out += fmt.Sprintf("\nexit code %d", code)
		}
		return out, code == 0, err
	}), nil
}
