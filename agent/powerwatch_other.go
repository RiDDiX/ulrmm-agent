// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin && !windows && !freebsd

package agent

import nats "github.com/nats-io/nats.go"

// No power watcher here; the stop signal is all the agent sees.
func (a *Agent) watchPower(*nats.Conn) {}

func classifyStop() (kind, initiator string) { return "", "" }
