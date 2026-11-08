// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"testing"

	"github.com/shirou/gopsutil/v3/host"
)

// Run as user never picks or accepts root.
func TestRunAsUserIsNotRoot(t *testing.T) {
	users := []host.UserStat{{User: "root"}, {User: ""}, {User: "alice"}}
	if got := pickLoginUser(users, true); got != "alice" {
		t.Fatalf("run-as fallback picked %q", got)
	}
	if got := pickLoginUser(users, false); got != "root" {
		t.Fatalf("logged on user %q", got)
	}
	if got := pickLoginUser(users[:2], true); got != "" {
		t.Fatalf("only root logged in, picked %q", got)
	}
	if u, err := lookupRunAs("root"); err != errRunAsRoot {
		t.Fatalf("root accepted: %+v %v", u, err)
	}
}
