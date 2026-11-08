// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// The Windows self-heal leaves its installer copies in the work directory.
func TestCleanupAgentUpdatesRemovesHealInstallers(t *testing.T) {
	t.Setenv("TMP", t.TempDir())
	a := testUpdateAgent()
	a.WinTmpDir = t.TempDir()
	exe, log := filepath.Join(a.WinTmpDir, "selfheal-1700000000.exe"), filepath.Join(a.WinTmpDir, "selfheal-install.log")
	for _, p := range []string{exe, log} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a.CleanupAgentUpdates()
	if _, err := os.Stat(exe); !os.IsNotExist(err) {
		t.Fatal("the heal installer was left behind")
	}
	if _, err := os.Stat(log); err != nil {
		t.Fatal("the install log is gone:", err)
	}
}
