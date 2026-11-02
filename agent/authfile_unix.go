// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"fmt"
	"os"
	"syscall"
)

func authFileOwnerOK(path string, fi os.FileInfo) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return fmt.Errorf("%s must belong to root", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be readable by root only (mode 0600)", path)
	}
	return nil
}
