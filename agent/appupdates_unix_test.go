// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	nats "github.com/nats-io/nats.go"
)

func TestMasSkippedAtLoginWindow(t *testing.T) {
	nobody := func() (uint32, error) { return 0, errors.New("no user is logged in at the console") }
	apps, err := listMacUpdates(context.Background(), "", "/opt/homebrew/bin/mas", nobody)
	if err != nil || apps == nil || len(apps) != 0 {
		t.Fatalf("got %+v %v", apps, err)
	}
}

func TestInstallWithWingetPostsResult(t *testing.T) {
	var got map[string]interface{}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v4/agent1/12/wingetresult/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	})
	p := decodeReq(t, map[string]interface{}{"func": "installwithwinget", "winget_id": "7zip.7zip", "pending_action_pk": 12})
	(&rpcReq{a: a, msg: &nats.Msg{}, p: p}).run()
	if got["results"] != "winget is only available on Windows" || got["exit_code"] != float64(-1) {
		t.Fatalf("got %v", got)
	}
}
