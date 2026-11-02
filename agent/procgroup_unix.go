// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// setProcGroup starts the child in its own process group so a timeout can
// kill everything it spawned. Detached children are in one as well.
func setProcGroup(cmd *exec.Cmd, _ bool) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcGroup(pid int) {
	if pid > 1 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

// Drops the child to u, with u's home and identity in its environment.
// Call after setProcGroup.
func applyRunAs(cmd *exec.Cmd, u *runAs) {
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: u.uid, Gid: u.gid, Groups: u.groups}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = runAsEnv(env, u)
	if st, err := os.Stat(u.home); err == nil && st.IsDir() {
		cmd.Dir = u.home
	}
}

// runAsEnv replaces root's identity variables with u's.
func runAsEnv(env []string, u *runAs) []string {
	set := map[string]string{"HOME": u.home, "USER": u.name, "LOGNAME": u.name}
	ret := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; !ok && k != "XDG_RUNTIME_DIR" && k != "MAIL" {
			ret = append(ret, kv)
		}
	}
	for _, k := range []string{"HOME", "USER", "LOGNAME"} {
		ret = append(ret, k+"="+set[k])
	}
	return ret
}
