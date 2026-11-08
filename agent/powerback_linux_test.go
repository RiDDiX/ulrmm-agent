// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux
// +build linux

package agent

import (
	"os"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
)

// After a sleep the heartbeat is as old as the sleep: the wake renews it, so
// a heal run right after does not take the agent for hung.
func TestPowerBackRenewsHealHeartbeat(t *testing.T) {
	oldDir := nixAgentDir
	nixAgentDir = t.TempDir()
	t.Cleanup(func() { nixAgentDir = oldDir; powerResumed() })
	pubs := make(chan string, 16)
	nc, err := nats.Connect(fakeNats(t, pubs))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	a := testUpdateAgent()
	a.AgentID = "agent-1"
	h := a.newHealer()
	if err := os.MkdirAll(h.dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return time.Now().Add(-2 * healStaleAfter) }
	h.heartbeat()
	if !a.newHealer().heartbeatStale() {
		t.Fatal("the old heartbeat is not stale")
	}

	a.powerBack(nc)
	if a.newHealer().heartbeatStale() {
		t.Fatal("the wake left the heartbeat stale")
	}
	// cancel, hello and agentinfo: the wake is done with the state dir
	for i := 0; i < 3; i++ {
		select {
		case <-pubs:
		case <-time.After(time.Minute):
			t.Fatal("the wake messages did not go out")
		}
	}
}
