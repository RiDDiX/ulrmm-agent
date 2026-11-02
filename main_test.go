// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTimeoutFlag(t *testing.T) {
	for in, want := range map[string]time.Duration{"600": 600 * time.Second, "10m": 10 * time.Minute, "90s": 90 * time.Second} {
		var s secondsFlag
		if err := s.Set(in); err != nil || time.Duration(s) != want {
			t.Fatalf("%q: %v %v", in, time.Duration(s), err)
		}
	}
	for _, bad := range []string{"", "0", "-5", "soon"} {
		var s secondsFlag
		if s.Set(bad) == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// the server build takes the version from main.go with this pattern
func TestVersionLine(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*version\s*=\s*"([0-9.]+)"`).FindAllSubmatch(b, -1)
	if len(m) != 1 || string(m[0][1]) != version {
		t.Fatalf("matches %q, version %q", m, version)
	}
	if !regexp.MustCompile(`^[1-9]\d*\.\d{2}\.\d{2}\.\d{4}$`).MatchString(version) {
		t.Fatalf("version %q is not X.DD.MM.YYYY", version)
	}
}

func TestInsecureFlagRemoved(t *testing.T) {
	if os.Getenv("ULRMM_TEST_MAIN") != "" {
		os.Args = []string{"agent", "-m", "install", "-api", "https://rmm.example", "-insecure"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInsecureFlagRemoved$")
	cmd.Env = append(os.Environ(), "ULRMM_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(out), "insecure mode was removed; use -cert <ca.pem>") {
		t.Fatalf("%v %q", err, out)
	}
}
