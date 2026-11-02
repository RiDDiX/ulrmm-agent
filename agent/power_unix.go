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
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var awakeStateDir = func() string { return nixAgentDir }

func holdAwake(d time.Duration) (func(), error) {
	if runtime.GOOS == "freebsd" {
		return nil, errors.New("keep awake is not available on FreeBSD")
	}
	argv := keepAwakeArgv(runtime.GOOS, d, os.Getpid())
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var errb capBuf
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// a missing logind or a refused assertion exits right away
	select {
	case err := <-done:
		return nil, fmt.Errorf("keep-awake exited: %v %s", err, clip(errb.String(), 128))
	case <-time.After(500 * time.Millisecond):
	}
	pgid := cmd.Process.Pid
	return func() {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}, nil
}

func userIdleSeconds() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Now()
	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		// HIDIdleTime misses ssh; a tty's atime is its last input read
		out, err := runOut(ctx, "/usr/bin/who")
		if err != nil {
			return 0, err
		}
		ttys, err := parseWhoTTYs(out)
		if err != nil {
			return 0, err
		}
		best := int64(-1)
		for _, tty := range ttys {
			var st unix.Stat_t
			if err := unix.Stat("/dev/"+tty, &st); err != nil {
				return 0, err
			}
			sec, _ := st.Atim.Unix()
			if idle := secondsSince(now, sec); best < 0 || idle < best {
				best = idle
			}
		}
		// login window: no GUI user. FreeBSD has no idle source for X.
		if runtime.GOOS == "freebsd" {
			return best, nil
		}
		if fi, err := os.Stat("/dev/console"); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid == 0 {
				return best, nil
			}
		}
		out, err = runOut(ctx, "/usr/sbin/ioreg", "-c", "IOHIDSystem", "-r", "-d", "1", "-k", "HIDIdleTime")
		if err != nil {
			return 0, err
		}
		idle, err := parseHIDIdle(out)
		if err != nil {
			return 0, err
		}
		if best < 0 || idle < best {
			best = idle
		}
		return best, nil
	}

	out, err := runOut(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return 0, err
	}
	best := int64(-1)
	for _, id := range parseLoginctlSessions(out) {
		props, err := runOut(ctx, "loginctl", "show-session", id, "-p", "Type", "-p", "Class", "-p", "State", "-p", "IdleHint", "-p", "IdleSinceHint", "-p", "TTY")
		if err != nil {
			return 0, err
		}
		idle, user, err := parseLoginctlIdle(props, now)
		if err != nil {
			return 0, err
		}
		if user && (best < 0 || idle < best) {
			best = idle
		}
	}
	return best, nil
}

func lastInputMillis() (int64, error) {
	return 0, errors.New("windows only")
}

// closed lid ignores caffeinate. pmset disablesleep is undocumented
// and the only switch that blocks it. Linux: handle-lid-switch on the inhibitor.
func holdLid(*awakeState) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return pmsetDisableSleep("1")
}

func undoLid(awakeState) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return pmsetDisableSleep("0")
}

func pmsetDisableSleep(v string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := runOut(ctx, "/usr/bin/pmset", "-a", "disablesleep", v)
	if err != nil {
		return fmt.Errorf("pmset disablesleep %s: %v %s", v, err, clip(out, 128))
	}
	return nil
}
