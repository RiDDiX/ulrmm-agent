// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Two writers of one file: every write succeeds and the file is always one
// of them in full.
func TestWriteFileSyncedConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf(`{"writer":%d,"pad":"%s"}`, w, strings.Repeat("x", 4096*(w+1))))
			for i := 0; i < 200; i++ {
				if err := writeFileSynced(path, body, 0o600); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	b, err := os.ReadFile(path)
	if err != nil || !json.Valid(b) {
		t.Fatalf("not valid JSON (%v): %.80q", err, b)
	}
	if fi, err := os.Stat(path); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o600) {
		t.Fatalf("mode: %v %v", fi.Mode(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}
