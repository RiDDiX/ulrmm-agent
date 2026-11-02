// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

func decodeReq(t *testing.T, msg map[string]interface{}) *NatsMsg {
	t.Helper()
	b, err := encodeMsgpack(msg)
	if err != nil {
		t.Fatal(err)
	}
	var p *NatsMsg
	var mh codec.MsgpackHandle
	mh.RawToString = true
	if err := codec.NewDecoderBytes(b, &mh).Decode(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNatsMsgWUADrivers(t *testing.T) {
	if p := decodeReq(t, map[string]interface{}{"func": "getwinupdates", "wua_drivers": true}); !p.WUADrivers {
		t.Fatal("wua_drivers not decoded")
	}
	if p := decodeReq(t, map[string]interface{}{"func": "getwinupdates"}); p.WUADrivers {
		t.Fatal("older servers must get the software-only scan")
	}
}

func TestPayloadTakesNonStrings(t *testing.T) {
	p := decodeReq(t, map[string]interface{}{
		"func":    "terminal_resize",
		"payload": map[string]interface{}{"session_id": "s1", "rows": 24, "cols": uint64(80), "flag": true, "gone": nil},
		"timeout": 30,
	})
	want := map[string]string{"session_id": "s1", "rows": "24", "cols": "80", "flag": "true", "gone": ""}
	for k, v := range want {
		if p.Data[k] != v {
			t.Fatalf("payload[%q] = %q, want %q", k, p.Data[k], v)
		}
	}
	if p.Func != "terminal_resize" || p.Timeout != 30 {
		t.Fatalf("envelope: %+v", p)
	}
}

func TestPayloadMissing(t *testing.T) {
	p := decodeReq(t, map[string]interface{}{"func": "ping"})
	if p.Data["anything"] != "" {
		t.Fatal("missing payload must read as empty")
	}
}

// The server's msgpack reader takes the old raw string format; str8 (0xd9)
// and bin would change what it gets.
func TestRepliesUseRawStrings(t *testing.T) {
	for _, v := range []interface{}{strings.Repeat("x", 40), []byte(strings.Repeat("y", 40))} {
		b, err := encodeMsgpack(v)
		if err != nil {
			t.Fatal(err)
		}
		if b[0] != 0xda {
			t.Fatalf("%T encoded with type byte %#x, want raw16 0xda", v, b[0])
		}
	}
	if b, _ := encodeMsgpack("pong"); b[0] != 0xa4 {
		t.Fatalf("short string type byte %#x", b[0])
	}
}

func TestDispatchSurvivesBadMessages(t *testing.T) {
	a := testUpdateAgent()
	for _, data := range [][]byte{{0xc0}, {0xff, 0x00}, nil, []byte("not msgpack")} {
		a.dispatch(nil, &nats.Msg{Data: data})
	}
}

func TestPanicReplyKeepsShape(t *testing.T) {
	if m, ok := panicReply("registry_browse").(map[string]interface{}); !ok || m["error"] == "" {
		t.Fatalf("registry: %#v", panicReply("registry_browse"))
	}
	if r := panicReply("winsvcaction"); r == nil {
		t.Fatal("winsvcaction: nil")
	}
	if _, ok := panicReply("procs").(string); !ok {
		t.Fatal("procs: want a string")
	}
}

func TestRegistryArguments(t *testing.T) {
	cases := []struct {
		fn   string
		data payloadMap
		want string
	}{
		{"registry_browse", payloadMap{}, "missing path"},
		{"registry_browse", payloadMap{"path": `HKEY_LOCAL_MACHINE\SOFTWARE`, "page": "0"}, "page must be 1 or higher"},
		{"registry_browse", payloadMap{"path": `HKEY_LOCAL_MACHINE\SOFTWARE`, "page_size": "-1"}, "page_size must be between 1 and 1000"},
		{"registry_browse", payloadMap{"path": `HKEY_LOCAL_MACHINE\SOFTWARE`, "page_size": "100000"}, "page_size must be between 1 and 1000"},
		{"registry_create_key", payloadMap{"path": "  "}, "Missing or empty path"},
		{"registry_delete_key", payloadMap{}, "Missing or empty path"},
		{"registry_rename_key", payloadMap{"old_path": "a"}, "Both old_path and new_path are required"},
		{"registry_rename_key", payloadMap{"old_path": "a", "new_path": "a"}, "Old and new path cannot be the same"},
		{"registry_create_value", payloadMap{"type": "REG_SZ"}, "Missing path"},
		{"registry_create_value", payloadMap{"path": "p"}, "Missing value type"},
		{"registry_modify_value", payloadMap{"path": "p", "name": "n"}, "Missing value type"},
		{"registry_rename_value", payloadMap{"path": "p", "new_name": "b"}, "Missing old_name"},
		{"registry_rename_value", payloadMap{"path": "p", "old_name": "a"}, "Missing new_name"},
		{"registry_browse", payloadMap{"path": `HKEY_LOCAL_MACHINE\SOFTWARE\` + IdentWinRegKey}, regKeyDenied},
		{"registry_delete_key", payloadMap{"path": `HKLM\software`}, regKeyDenied},
		{"registry_delete_key", payloadMap{"path": `HKEY_LOCAL_MACHINE\`}, "deleting root hive 'HKEY_LOCAL_MACHINE' is not allowed"},
		{"registry_delete_key", payloadMap{"path": "computer"}, "deleting root hive 'computer' is not allowed"},
		{"registry_modify_value", payloadMap{"path": `hkey_local_machine\SOFTWARE\` + IdentWinRegKey + `\`, "name": "Token", "type": "REG_SZ"}, regKeyDenied},
		{"registry_rename_key", payloadMap{"old_path": `HKEY_LOCAL_MACHINE\SOFTWARE\x`, "new_path": `HKEY_LOCAL_MACHINE\SOFTWARE\` + IdentWinRegKey + `\x`}, regKeyDenied},
		{"registry_browse", payloadMap{"path": `HKEY_LOCAL_MACHINE\SAM\SAM`}, regKeyDenied},
		{"registry_rename_value", payloadMap{"path": `HKEY_LOCAL_MACHINE\SECURITY`, "old_name": "a", "new_name": "b"}, regKeyDenied},
		{"registry_modify_value", payloadMap{"path": `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` + IdentWinSvcName, "name": "ImagePath", "type": "REG_EXPAND_SZ"}, regKeyDenied},
		{"registry_delete_value", payloadMap{"path": `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\` + IdentWinSvcName, "name": "ImagePath"}, regKeyDenied},
		{"registry_create_key", payloadMap{"path": `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` + IdentWinSvcName + `\x`}, regKeyDenied},
		{"registry_delete_key", payloadMap{"path": `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`}, regKeyDenied},
		{"registry_rename_key", payloadMap{"old_path": `HKEY_LOCAL_MACHINE\SOFTWARE\x`, "new_path": `HKEY_LOCAL_MACHINE\SAM\x`}, regKeyDenied},
	}
	for _, c := range cases {
		got := registryRPC(c.fn, c.data)
		if got["error"] != c.want {
			t.Fatalf("%s %v: got %v, want error %q", c.fn, c.data, got, c.want)
		}
	}
}

func TestRegistryDefaultValuePassesThrough(t *testing.T) {
	// a blank name reaches the registry call (the default value); off
	// Windows that call answers with its stub error
	for _, fn := range []string{"registry_modify_value", "registry_create_value", "registry_delete_value"} {
		got := registryRPC(fn, payloadMap{"path": `HKEY_LOCAL_MACHINE\SOFTWARE\x`, "name": "", "type": "REG_SZ"})
		if e, _ := got["error"].(string); e == "" || strings.Contains(e, "Missing") {
			t.Errorf("%s with a blank name: %v", fn, got)
		}
	}
	if got := registryRPC("registry_rename_value", payloadMap{"path": "p", "old_name": "", "new_name": "b"}); got["error"] != "Missing old_name" {
		t.Errorf("rename of the default value: %v", got)
	}
}

func TestPatchHistResultRetries(t *testing.T) {
	old := histRetryWait
	histRetryWait = time.Millisecond
	defer func() { histRetryWait = old }()
	var calls atomic.Int32
	status := []int{502, 200}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v3/7/agent1/histresult/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(status[min(int(n)-1, len(status)-1)])
	})
	if err := a.patchHistResult(7, map[string]string{"results": "x"}); err != nil || calls.Load() != 2 {
		t.Fatalf("5xx then ok: %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	status = []int{500, 503}
	if err := a.patchHistResult(7, nil); err == nil || calls.Load() != 2 {
		t.Fatalf("two 5xx: %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	status = []int{400}
	if err := a.patchHistResult(7, nil); err != nil || calls.Load() != 1 {
		t.Fatalf("4xx is no retry: %v after %d calls", err, calls.Load())
	}
}

func TestRegDenied(t *testing.T) {
	key := `HKEY_LOCAL_MACHINE\SOFTWARE\` + IdentWinRegKey
	svc := `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` + IdentWinSvcName
	for _, p := range []string{key, key + `\Sub`, `Computer\` + key, strings.ToLower(key), `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\` + IdentWinRegKey, `HKEY_LOCAL_MACHINE//SOFTWARE/` + IdentWinRegKey,
		`HKEY_LOCAL_MACHINE\SAM`, `HKLM\sam\SAM\Domains`, `Computer\HKEY_LOCAL_MACHINE\SECURITY\`, `HKEY_LOCAL_MACHINE\\Security\Policy\Secrets`} {
		if !regDenied(p, false, false) || !regDenied(p, true, false) {
			t.Fatalf("%q not refused", p)
		}
	}
	for _, p := range []string{`HKEY_LOCAL_MACHINE\SOFTWARE`, key + "Other", `HKEY_CURRENT_USER\SOFTWARE\` + IdentWinRegKey, "Computer", "", `HKEY_LOCAL_MACHINE\SAMx`, `HKEY_USERS\SAM`, `HKEY_LOCAL_MACHINE\SOFTWARE\SECURITY`} {
		if regDenied(p, true, false) {
			t.Fatalf("%q wrongly matched", p)
		}
	}
	// the service key is readable but not changeable, in every control set
	for _, p := range []string{svc, svc + `\Parameters`, `hklm\system\ControlSet001\services\` + IdentWinSvcName, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet012\Services\` + IdentWinSvcName} {
		if regDenied(p, false, false) || !regDenied(p, true, false) {
			t.Fatalf("%q: read must pass, write must not", p)
		}
	}
	for _, p := range []string{svc + "-selfheal", `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet\Services\` + IdentWinSvcName, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSetX1\Services\` + IdentWinSvcName, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler`} {
		if regDenied(p, true, false) {
			t.Fatalf("%q wrongly matched", p)
		}
	}
	for _, p := range []string{`HKEY_LOCAL_MACHINE\SOFTWARE`, "HKEY_LOCAL_MACHINE", `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Services`, `HKEY_LOCAL_MACHINE\SYSTEM`} {
		if !regDenied(p, true, true) {
			t.Fatalf("%q: a parent of a protected key must count when deleting", p)
		}
	}
	if regDenied(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`, true, false) {
		t.Fatal("creating below Services must stay possible")
	}
}

func TestPlainFileName(t *testing.T) {
	for _, ok := range []string{"ulrmm-agent-v2.09.10.2026-windows-amd64.exe", "setup.exe"} {
		if !plainFileName(ok) {
			t.Fatalf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "..", `..\x.exe`, "../x.exe", `C:\x.exe`, `sub\x.exe`, "a/b.exe"} {
		if plainFileName(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestNatsMsgWingetID(t *testing.T) {
	p := decodeReq(t, map[string]interface{}{"func": "installwithwinget", "winget_id": "Febooti.Hash&CRC", "pending_action_pk": 5})
	if p.WingetID != "Febooti.Hash&CRC" || p.PendingActionPK != 5 {
		t.Fatalf("%+v", p)
	}
}

func TestPostWingetResult(t *testing.T) {
	var body map[string]json.RawMessage
	status := http.StatusOK
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v4/agent1/9/wingetresult/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(status)
	})
	if err := a.postWingetResult(9, "Successfully installed", 0x8A150109); err != nil {
		t.Fatal(err)
	}
	if string(body["results"]) != `"Successfully installed"` || string(body["exit_code"]) != "2316632329" || len(body) != 2 {
		t.Fatalf("body %s %s (%d keys)", body["results"], body["exit_code"], len(body))
	}
	status = http.StatusBadRequest
	if err := a.postWingetResult(9, "", -1); err == nil {
		t.Fatal("4xx not reported")
	}
}
