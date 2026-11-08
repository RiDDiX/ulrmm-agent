// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"testing"
)

// A stream that never ends a line stays within the head and tail caps.
func TestLineCollectorLineWithoutEnd(t *testing.T) {
	l := &lineCollector{}
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for i := 0; i < 640; i++ { // 20 MiB
		l.Write(chunk)
		if len(l.partial) >= cmdKeepTail {
			t.Fatalf("partial line grew to %d bytes", len(l.partial))
		}
	}
	if n := len(l.text()); n > cmdKeepHead+cmdKeepTail+100 {
		t.Fatalf("kept %d bytes", n)
	}
}

// A panic inside agentupdate does not block every later update.
func TestAgentUpdatePanicFreesUpdate(t *testing.T) {
	a := testUpdateAgent()
	r := &rpcReq{a: a, p: &NatsMsg{Func: "agentupdate"}} // no msg: the reply panics
	func() {
		defer func() { _ = recover() }()
		a.rpcAgentUpdate(r)
	}()
	if updateRunning.Load() {
		updateRunning.Store(false)
		t.Fatal("update still marked running")
	}
}
