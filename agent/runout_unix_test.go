// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"context"
	"strings"
	"testing"
)

func TestRunOutUntranslated(t *testing.T) {
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	t.Setenv("LC_MESSAGES", "de_DE.UTF-8")
	out, err := runOut(context.Background(), "sh", "-c", `echo "$LC_ALL|$LC_MESSAGES|$LC_NUMERIC|$LC_CTYPE"`)
	if err != nil || strings.TrimSpace(out) != "|C|C|de_DE.UTF-8" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestUntranslatedEnvKeepsCtype(t *testing.T) {
	env := untranslatedEnv([]string{"LANG=de_DE.UTF-8", "LC_CTYPE=en_US.UTF-8", "LC_ALL=de_DE.UTF-8", "PATH=/bin"})
	got := strings.Join(env, " ")
	if got != "LANG=de_DE.UTF-8 LC_CTYPE=en_US.UTF-8 PATH=/bin LC_MESSAGES=C LC_NUMERIC=C" {
		t.Fatal(got)
	}
}
