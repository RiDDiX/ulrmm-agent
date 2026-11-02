// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import "testing"

func TestFreebsdStopKind(t *testing.T) {
	if !rcShutdownRunning("/sbin/init\n/bin/sh /etc/rc.shutdown reboot\n") || rcShutdownRunning("/sbin/init\nsshd\n") {
		t.Fatal("rc.shutdown detection")
	}
	msgs := "Nov  1 20:00:00 nas shutdown[812]: power-down by root: disk swap\nNov  1 20:10:00 nas shutdown[901]: reboot by admin: freebsd-update\n"
	for _, c := range []struct{ in, kind, ini string }{
		{msgs, "restart", "admin: freebsd-update"},
		{"Nov  1 20:00:00 nas shutdown[812]: power-down by root:\n", "shutdown", "root"},
		{"Nov  1 20:00:00 nas kernel: em0: link state changed to UP\n", "shutdown_or_restart", ""},
		{"", "shutdown_or_restart", ""},
	} {
		if kind, ini := freebsdStopKind(c.in); kind != c.kind || ini != c.ini {
			t.Errorf("%q: %q %q", c.in, kind, ini)
		}
	}
}
