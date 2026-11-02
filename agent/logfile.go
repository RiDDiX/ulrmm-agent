// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"os"
	"sync"
)

// NixLogFile is the agent log on Linux and macOS.
var NixLogFile = "/var/log/" + IdentNixBin + ".log"

// The log moves aside to <path>.1 (the one before to .2) once it would
// pass logMaxSize, so it cannot fill the disk.
var logMaxSize int64 = 10 << 20

const logKeep = 2

// Append-only, mode 0600, rotated on size.
type LogFile struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	size    int64
	created func(string)
}

// created runs on every file opened (Windows restricts the ACL there).
func OpenLogFile(path string, created func(string)) (*LogFile, error) {
	l := &LogFile{path: path, created: created}
	return l, l.open()
}

func (l *LogFile) open() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.f, l.size = f, 0
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
	if l.created != nil {
		l.created(l.path)
	}
	return nil
}

func (l *LogFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size > 0 && l.size+int64(len(p)) > logMaxSize {
		l.rotate()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *LogFile) rotate() {
	l.f.Close()
	for i := logKeep; i > 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i-1), fmt.Sprintf("%s.%d", l.path, i))
	}
	moved := os.Rename(l.path, l.path+".1") == nil
	if err := l.open(); err != nil {
		l.f, l.size = os.Stderr, 0
		return
	}
	if !moved {
		// another process holds the file (Windows): try again one size later
		l.size = 0
	}
}
