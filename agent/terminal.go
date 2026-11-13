// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/creack/pty"
	nats "github.com/nats-io/nats.go"
)

// One shell on a PTY per session. Output goes to <AgentID>.terminal.<session>.
// Windows is terminal_windows.go.

type TerminalSession struct {
	ID   string
	Cmd  *exec.Cmd
	Ptmx *os.File

	lastUse atomic.Int64
}

func (s *TerminalSession) touch() { s.lastUse.Store(time.Now().UnixNano()) }

// PendingTerminalResize is a size that arrived before its session started.
type PendingTerminalResize struct {
	Rows int
	Cols int
	at   time.Time
}

const (
	terminalChunk = 2048
	terminalDrain = 2 * time.Second
	// a session without input or output this long is ended
	termIdleLimit = 2 * time.Hour
	// a size that arrived for a session that never started is dropped
	termPendingTTL = time.Minute
)

// Terminal output: what arrives within termFlushEvery goes out as one
// message of at most termMaxMsg bytes, and beyond a short burst no more than
// termRate bytes a second, so a flood (cat of a big file) cannot swamp NATS
// or the browser. The shell blocks on its full console meanwhile.
var (
	termFlushEvery       = 10 * time.Millisecond
	termMaxMsg           = 16 << 10
	termRate       int64 = 2 << 20
	termBurst            = 250 * time.Millisecond
)

// pumpTermOutput forwards r to publish until r ends (nil) or publish fails
// (its error). A character cut by a read is held for the next message, so
// each message is valid UTF-8 when the output is. touch runs on every read.
func pumpTermOutput(r io.Reader, publish func([]byte) error, touch func()) error {
	chunks := make(chan []byte, 4)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(chunks)
		for {
			b := make([]byte, terminalChunk)
			n, err := r.Read(b)
			if n > 0 {
				touch()
				select {
				case chunks <- b[:n]:
				case <-stop:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	var pending []byte
	var next time.Time
	flush := func(all bool) error {
		for len(pending) > 0 {
			n := min(len(pending), termMaxMsg)
			cut := n
			if n == len(pending) && !all {
				if cut = completeUTF8(pending); cut == 0 {
					return nil
				}
			} else if n < len(pending) {
				if cut = completeUTF8(pending[:n]); cut == 0 {
					cut = n
				}
			}
			if err := publish(pending[:cut]); err != nil {
				return err
			}
			pending = pending[cut:]
			now := time.Now()
			if next.Before(now) {
				next = now
			}
			next = next.Add(time.Duration(int64(cut) * int64(time.Second) / termRate))
			if d := time.Until(next) - termBurst; d > 0 {
				time.Sleep(d)
			}
		}
		return nil
	}
	for {
		b, ok := <-chunks
		if !ok {
			return flush(true)
		}
		pending = append(pending, b...)
		deadline := time.After(termFlushEvery)
	gather:
		for len(pending) < termMaxMsg {
			select {
			case b, ok := <-chunks:
				if !ok {
					return flush(true)
				}
				pending = append(pending, b...)
			case <-deadline:
				break gather
			}
		}
		if err := flush(false); err != nil {
			return err
		}
	}
}

func (a *Agent) StartTerminalSession(sessionID, shell string, nc *nats.Conn) error {
	// check and insert under one lock: concurrent starts must not pass the cap
	a.TerminalSessionsMu.Lock()
	if _, exists := a.TerminalSessions[sessionID]; exists {
		a.TerminalSessionsMu.Unlock()
		return fmt.Errorf("session already exists: %s", sessionID)
	}
	if len(a.TerminalSessions) >= termMaxSessions {
		a.TerminalSessionsMu.Unlock()
		return fmt.Errorf("too many terminal sessions on this agent (limit %d)", termMaxSessions)
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		a.TerminalSessionsMu.Unlock()
		return fmt.Errorf("failed to start PTY: %w", err)
	}

	sess := &TerminalSession{ID: sessionID, Cmd: cmd, Ptmx: ptmx}
	sess.touch()
	if a.TerminalSessions == nil {
		a.TerminalSessions = make(map[string]*TerminalSession)
	}
	a.TerminalSessions[sessionID] = sess
	size, pending := a.PendingTerminalResizes[sessionID]
	delete(a.PendingTerminalResizes, sessionID)
	a.TerminalSessionsMu.Unlock()

	if pending {
		_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(size.Rows), Cols: uint16(size.Cols)})
	}
	a.Logger.Debugln("Registered terminal session", sessionID)
	termReaper.Do(func() { go a.reapIdleTerminals() })

	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		err := pumpTermOutput(ptmx, func(b []byte) error { return a.publishTerminal(nc, sessionID, b) }, sess.touch)
		if err != nil {
			a.Logger.Debugln("terminal output:", err)
			_ = a.KillTerminalSession(sessionID)
		}
	}()
	go func() {
		err := cmd.Wait()
		a.Logger.Debugf("Terminal session %s exited: %v", sessionID, err)
		code := 0
		if err != nil {
			code = 1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode() // -1 when a signal ended it
			}
		}
		// let the last output out before the PTY goes away
		select {
		case <-pumped:
		case <-time.After(terminalDrain):
		}
		a.stopTerminalSession(sessionID)
		a.publishTerminal(nc, sessionID, map[string]interface{}{"done": true, "exit_code": code})
		forgetFrames(fmt.Sprintf("%s.terminal.%s", a.AgentID, sessionID), time.Minute)
	}()
	return nil
}

var termReaper sync.Once

// reapIdleTerminals ends sessions nobody used for termIdleLimit, such as
// one whose browser went away without a kill.
func (a *Agent) reapIdleTerminals() {
	for range time.Tick(time.Minute) {
		var idle []string
		a.TerminalSessionsMu.Lock()
		for id, s := range a.TerminalSessions {
			if time.Since(time.Unix(0, s.lastUse.Load())) > termIdleLimit {
				idle = append(idle, id)
			}
		}
		a.TerminalSessionsMu.Unlock()
		for _, id := range idle {
			a.Logger.Debugln("Ending idle terminal session", id)
			_ = a.KillTerminalSession(id)
		}
	}
}

// completeUTF8 returns how much of b can be sent without splitting a
// character at the end. Bytes that can never become valid are not held.
func completeUTF8(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if !utf8.RuneStart(b[i]) {
			continue
		}
		if !utf8.FullRune(b[i:]) {
			return i
		}
		break
	}
	return len(b)
}

func (a *Agent) publishTerminal(nc *nats.Conn, sessionID string, v interface{}) error {
	return publishFrame(nc, fmt.Sprintf("%s.terminal.%s", a.AgentID, sessionID), v)
}

// sendTerminalError tells the web terminal that the session failed.
func (a *Agent) sendTerminalError(nc *nats.Conn, sessionID, message string) {
	_ = a.publishTerminal(nc, sessionID, map[string]interface{}{
		"output":     "[ERROR] " + message + "\r\n",
		"session_id": sessionID,
		"done":       true,
		"exit_code":  1,
	})
}

// terminalSession looks a session up; remove also forgets it and any
// size that waits for it.
func (a *Agent) terminalSession(sessionID string, remove bool) (*TerminalSession, bool) {
	a.TerminalSessionsMu.Lock()
	defer a.TerminalSessionsMu.Unlock()
	t, ok := a.TerminalSessions[sessionID]
	if remove {
		delete(a.TerminalSessions, sessionID)
		delete(a.PendingTerminalResizes, sessionID)
	}
	return t, ok
}

func (a *Agent) FeedTerminalInput(sessionID, data string) error {
	sess, found := a.terminalSession(sessionID, false)
	switch {
	case !found:
		return fmt.Errorf("session not found: %s", sessionID)
	case sess.Ptmx == nil:
		return fmt.Errorf("PTY not initialized for session: %s", sessionID)
	}
	sess.touch()
	_, err := sess.Ptmx.Write([]byte(data))
	return err
}

func (a *Agent) ResizeTerminalSession(sessionID string, rows, cols int) error {
	if rows <= 0 || cols <= 0 || rows > 0xffff || cols > 0xffff {
		return nil
	}
	a.TerminalSessionsMu.Lock()
	sess, ok := a.TerminalSessions[sessionID]
	if !ok {
		// the web UI sends its size right after the start
		if a.PendingTerminalResizes == nil {
			a.PendingTerminalResizes = make(map[string]PendingTerminalResize)
		}
		now := time.Now()
		for id, p := range a.PendingTerminalResizes {
			if now.Sub(p.at) > termPendingTTL {
				delete(a.PendingTerminalResizes, id)
			}
		}
		a.PendingTerminalResizes[sessionID] = PendingTerminalResize{Rows: rows, Cols: cols, at: now}
		a.TerminalSessionsMu.Unlock()
		return nil
	}
	a.TerminalSessionsMu.Unlock()
	return pty.Setsize(sess.Ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}

// KillTerminalSession kills the shell and everything started in its
// session (the shell leads its own process group); its waiter then sends
// done.
func (a *Agent) KillTerminalSession(sessionID string) error {
	sess, ok := a.terminalSession(sessionID, false)
	if !ok {
		a.Logger.Debugln("KillTerminalSession: session already cleaned up:", sessionID)
		return nil
	}
	if sess.Cmd != nil && sess.Cmd.Process != nil {
		killProcGroup(sess.Cmd.Process.Pid)
		_ = sess.Cmd.Process.Kill()
	}
	a.stopTerminalSession(sessionID)
	return nil
}

func (a *Agent) stopTerminalSession(sessionID string) {
	if sess, ok := a.terminalSession(sessionID, true); ok && sess.Ptmx != nil {
		sess.Ptmx.Close()
	}
}
