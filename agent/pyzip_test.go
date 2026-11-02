// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPyZip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "py.zip")
	if err := os.WriteFile(p, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	pyZipSHA256["test.zip"] = sum
	defer delete(pyZipSHA256, "test.zip")

	if err := checkPyZip(p, "test.zip"); err != nil {
		t.Fatalf("matching zip refused: %v", err)
	}
	if err := checkPyZip(p, "py3.14.5_amd64.zip"); err == nil {
		t.Fatal("zip with the wrong hash accepted")
	}
	if err := checkPyZip(p, "py0.0.0_amd64.zip"); err == nil {
		t.Fatal("unlisted zip accepted")
	}
	for _, v := range []string{"3.14.5", "3.11.9", "3.8.7"} {
		for _, a := range []string{"amd64", "386"} {
			if len(pyZipSHA256["py"+v+"_"+a+".zip"]) != 64 {
				t.Errorf("no sha256 for py%s_%s.zip", v, a)
			}
		}
	}
}
