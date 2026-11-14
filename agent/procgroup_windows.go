// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"os/exec"
)

// Windows has no process groups to signal; killTree covers the children.
func setProcGroup(*exec.Cmd) {}

func killProcGroup(int) {}

func hangUpOutsideGroup(int, []int32) {}

// CmdV2 is the posix runner; Windows runs as the user through its own
// token path.
func applyRunAs(*exec.Cmd, *runAs) {}

func sessionRunAs() (*runAs, error) { return nil, errors.New("not supported on Windows") }
