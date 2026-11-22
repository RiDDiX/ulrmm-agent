// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// imagingPartialPrivate tells whether only this user can write a partial
// download left by an earlier run. Its inode becomes the published artifact.
func imagingPartialPrivate(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && info.Mode().Perm()&0o022 == 0
}
