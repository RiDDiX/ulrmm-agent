// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"time"

	nats "github.com/nats-io/nats.go"
)

// No watcher: FreeBSD has no sleep the agent could see, and a shutdown runs
// /etc/rc.shutdown, which stops the agent's rc.d service first.
func (a *Agent) watchPower(*nats.Conn) {}

// classifyStop: init runs rc.shutdown for halt, power-off and reboot alike;
// shutdown(8) logs which one and who asked for it.
func classifyStop() (kind, initiator string) {
	ps, _ := healCmd(2*time.Second, "ps", "-ax", "-o", "command=")
	if !rcShutdownRunning(ps) {
		return "", ""
	}
	b, _ := os.ReadFile("/var/log/messages")
	return freebsdStopKind(string(b))
}
