// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"os"
	"strings"
	"testing"
)

func TestPrintLicenses(t *testing.T) {
	var out strings.Builder
	if err := printLicenses(&out); err != nil {
		t.Fatal(err)
	}
	for _, name := range licenseOrder {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "==> "+name+" <==\n"+string(b)) {
			t.Fatalf("%s missing from the output", name)
		}
	}
}
