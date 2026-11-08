// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

// the shell a package script runs with
const pkgShell = "shell"

// free bytes on the volume of dir; tests replace it
var pkgFree = func(dir string) (uint64, error) {
	u, err := statBounded(dir, statfsWait)
	if err != nil {
		return 0, err
	}
	return u.Free, nil
}

// work dirs go in the configured tmpdir, else the agent's data dir
func (a *Agent) pkgRoot() (string, error) {
	root := orDefault(a.UnixTmpDir, nixAgentDir)
	return root, os.MkdirAll(root, 0o755)
}

// sh and bash are the programs a command may name without a path.
func pkgSystemExe(name string) (string, bool) {
	if name != "sh" && name != "bash" {
		return "", false
	}
	p, _ := exec.LookPath(name)
	return p, true
}

// pkgCommand runs exe with argv in dir as root. At the deadline the process
// group and everything it started is killed.
func (a *Agent) pkgCommand(ctx context.Context, exe string, r *pkgRun, dir string, env []string, out io.Writer) (code int, timedOut bool, err error) {
	cmd := a.buildCmd(ctx, &CmdOptions{IsScript: true, Shell: exe, Args: r.Argv, EnvVars: env})
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, out, out
	if err := cmd.Start(); err != nil {
		return -1, false, err
	}
	werr := cmd.Wait()
	var ee *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return cmdTimeoutExit, true, nil
	case werr == nil || errors.Is(werr, exec.ErrWaitDelay):
		return cmd.ProcessState.ExitCode(), false, nil
	case errors.As(werr, &ee):
		return ee.ExitCode(), false, nil
	}
	return -1, false, werr
}

func pkgExit(code int) int64 { return int64(code) }
