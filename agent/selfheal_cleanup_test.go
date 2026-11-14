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

// A setup killed before its replace step leaves its side files in the
// program directory; the installed files stay.
func TestCleanupAgentUpdatesRemovesSetupSideFiles(t *testing.T) {
	t.Setenv("TMP", t.TempDir())
	a := testUpdateAgent()
	a.WinTmpDir = t.TempDir()
	a.ProgramDir = t.TempDir()
	var gone, kept []string
	for _, n := range []string{IdentWinExe + ".new", "unins000.exe.new"} {
		gone = append(gone, filepath.Join(a.ProgramDir, n))
	}
	for _, n := range []string{IdentWinExe, "unins000.exe", "LICENSE.md.new"} {
		kept = append(kept, filepath.Join(a.ProgramDir, n))
	}
	// the names count only in the program directory
	kept = append(kept, filepath.Join(a.WinTmpDir, IdentWinExe+".new"))
	for _, p := range append(gone, kept...) {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a.CleanupAgentUpdates()
	for _, p := range gone {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Error("left behind:", p)
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Error("removed:", p, err)
		}
	}
}
