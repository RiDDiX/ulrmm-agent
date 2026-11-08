// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"strings"
	"testing"
)

// /S fails after AC and DC were set to 0: the saved indexes go back
func TestHoldLidFailedPutsIndexesBack(t *testing.T) {
	old := powercfg
	defer func() { powercfg = old }()
	var calls []string
	powercfg = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if len(calls) == 3 {
			return "access denied", errors.New("exit status 1")
		}
		return "", nil
	}
	st := awakeState{LidAC: "0x00000001", LidDC: "0x00000002"}
	if err := holdLid(&st); err == nil {
		t.Fatal("failed hold reported as held")
	}
	want := []string{
		"/setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0",
		"/setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0",
		"/S SCHEME_CURRENT",
		"/setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 1",
		"/setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 2",
		"/S SCHEME_CURRENT",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%q", calls)
	}
}
