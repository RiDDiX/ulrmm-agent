// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "testing"

func TestUnmarkedAnswerDecodedAsGrantOnly(t *testing.T) {
	body := []byte(`{"url":"https://rmm/imaging/transfers/1/","token":"t","claim":"c","expires_at":"x","network_mode":"internet","image_id":"i",
		"run":"r","config_version":7,"trigger":"schedule","stop_at":1764003600000,"run_config":{"smart":"abort","pause_max_minutes":5},
		"hooks":[{"phase":"pre-backup","script_id":12,"code":"echo","env_vars":["A=b"]}],"nushell_enable_config":true,"deno_default_permissions":"--allow-all"}`)
	plain, err := decodeImagingClaim(body, false)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Claim != "c" || plain.URL == "" || plain.Token != "t" || plain.Image != "i" || plain.Mode != "internet" {
		t.Fatalf("grant fields: %+v", plain.imagingGrant)
	}
	if plain.Run != "" || plain.Trigger != "" || plain.StopAt != nil || plain.RunConfig.Smart != "" ||
		plain.Hooks != nil || plain.NushellEnableConfig || plain.DenoDefaultPermissions != "" {
		t.Fatalf("protocol-2 keys read from an unsealed answer: %+v", plain)
	}
	sealed, err := decodeImagingClaim(body, true)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Claim != "c" || sealed.Run != "r" || sealed.Trigger != "schedule" || sealed.StopAt == nil || *sealed.StopAt != 1764003600000 ||
		sealed.RunConfig.Smart != "abort" || sealed.RunConfig.PauseMaxMinutes != 5 || len(sealed.Hooks) != 1 || sealed.Hooks[0].EnvVars[0] != "A=b" ||
		!sealed.NushellEnableConfig || sealed.DenoDefaultPermissions != "--allow-all" {
		t.Fatalf("sealed claim: %+v", sealed)
	}
}
