// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHealUnitState(t *testing.T) {
	for _, c := range []struct {
		name               string
		out                string
		err                error
		installed, running bool
	}{
		// systemd 219 (CentOS 7) prints in its own order
		{"219 running", "ActiveState=active\nLoadState=loaded\n", nil, true, true},
		{"219 missing", "LoadState=not-found\nActiveState=inactive\n", nil, false, false},
		{"219 no --value", "systemctl: unrecognized option '--value'\n", errors.New("exit status 1"), true, true},
		{"252 running", "LoadState=loaded\nActiveState=active\n", nil, true, true},
		{"252 stopped", "LoadState=loaded\nActiveState=failed\n", nil, true, false},
		{"252 starting", "LoadState=loaded\nActiveState=activating\n", nil, true, true},
		{"252 reloading", "LoadState=loaded\nActiveState=reloading\n", nil, true, true},
		{"no bus", "Failed to connect to bus: No such file or directory\n", errors.New("exit status 1"), true, true},
		{"empty", "", nil, true, true},
	} {
		if i, r := healUnitState(c.out, c.err); i != c.installed || r != c.running {
			t.Errorf("%s: installed %v running %v", c.name, i, r)
		}
	}
}

func TestWriteUnitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.service")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileSynced(path, []byte("new unit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	st, _ := os.Stat(path)
	if string(b) != "new unit\n" || st.Mode().Perm() != 0o644 {
		t.Fatalf("%q %v", b, st.Mode())
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temp file left")
	}
}
