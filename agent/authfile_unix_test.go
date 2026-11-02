// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAuthFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the token file must belong to root")
	}
	p := filepath.Join(t.TempDir(), "token")
	write := func(body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
		uid        int
		err        string
	}{
		{"group readable", "tok", 0o640, 0, "readable by root only"},
		{"other owner", "tok", 0o600, 1000, "belong to root"},
		{"empty", " \n", 0o600, 0, "holds no token"},
		{"too large", strings.Repeat("a", maxAuthFile+1), 0o600, 0, "too large"},
	} {
		write(tc.body, tc.mode)
		if err := os.Chown(p, tc.uid, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadAuthFile(p); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	write(" tok-123\n", 0o400)
	if tok, err := ReadAuthFile(p); err != nil || tok != "tok-123" {
		t.Fatalf("valid file: %q %v", tok, err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("the token file is still there")
	}
}

func TestScriptEnvDropsDenied(t *testing.T) {
	a := testUpdateAgent()
	got := a.scriptEnv([]string{"A=1", "PERL5OPT=-Mevil", "1BAD=x", "gconv_path=/tmp", "B=2"})
	if strings.Join(got, " ") != "A=1 B=2" {
		t.Fatalf("env %v", got)
	}
}
