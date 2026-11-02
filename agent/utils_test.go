// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"strings"
	"testing"
)

func TestSafeJoinRejectsTraversal(t *testing.T) {
	dest := t.TempDir()
	for _, bad := range []string{"../evil", "a/../../evil", "/../../etc/passwd"} {
		if p, err := safeJoin(dest, bad); err == nil && !strings.HasPrefix(p, dest) {
			t.Fatalf("%q escaped to %q", bad, p)
		} else if err == nil && bad != "/../../etc/passwd" {
			t.Fatalf("%q was accepted", bad)
		}
	}
	if _, err := safeJoin(dest, "nu-0.1/nu"); err != nil {
		t.Fatal(err)
	}
}
