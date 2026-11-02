// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// This build's winpty.dll and winpty-agent.exe, next to the agent (fallback
// where Windows has no ConPTY). Present files stay unless force is set: a
// running terminal session keeps them loaded.
func EnsureWinPTY(programDir string, force bool) (string, error) {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "386" {
		return "", fmt.Errorf("unsupported arch %s", arch)
	}
	if st, err := os.Stat(programDir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("expected install directory not found: %s", programDir)
	}
	files := []struct {
		name          string
		mode          os.FileMode
		readMsg, wMsg string
	}{
		{"winpty.dll", 0o644, "failed to read embedded DLL", "failed to write DLL"},
		{"winpty-agent.exe", 0o755, "failed to read embedded EXE", "failed to write agent"},
	}
	if !force {
		present := true
		for _, f := range files {
			if st, err := os.Stat(filepath.Join(programDir, f.name)); err != nil || !st.Mode().IsRegular() {
				present = false
			}
		}
		if present {
			return programDir, nil
		}
	}
	for _, f := range files {
		data, err := winptyFS.ReadFile("winpty_bins/" + arch + "/" + f.name)
		if err != nil {
			return "", fmt.Errorf("%s: %w", f.readMsg, err)
		}
		target := filepath.Join(programDir, f.name)
		if !force && sameSHA256(target, data) {
			continue
		}
		tmp := target + ".tmp"
		if err := os.WriteFile(tmp, data, f.mode); err != nil {
			return "", fmt.Errorf("%s: %w", f.wMsg, err)
		}
		if err := os.Rename(tmp, target); err != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("%s: %w", f.wMsg, err)
		}
	}
	return programDir, nil
}

func sameSHA256(path string, data []byte) bool {
	got, err := fileSHA256(path)
	if err != nil {
		return false
	}
	want := sha256.Sum256(data)
	return got == hex.EncodeToString(want[:])
}
