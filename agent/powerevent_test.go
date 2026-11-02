// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/ugorji/go/codec"
)

func TestPowerReportEncoding(t *testing.T) {
	in := rmm.PowerReport{AgentID: "abc", Kind: "restart", Source: "rmm", Initiator: "rmm: rebootnow"}
	b, err := encodeMsgpack(in)
	if err != nil {
		t.Fatal(err)
	}
	var out rmm.PowerReport
	if err := codec.NewDecoderBytes(b, new(codec.MsgpackHandle)).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v", out)
	}
	// the server reads the json names
	var m map[string]interface{}
	mh := codec.MsgpackHandle{}
	mh.RawToString = true
	if err := codec.NewDecoderBytes(b, &mh).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m["agent_id"] != "abc" || m["kind"] != "restart" || m["source"] != "rmm" || m["initiator"] != "rmm: rebootnow" || len(m) != 4 {
		t.Fatalf("keys: %v", m)
	}
}

func TestPowerSkip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	const boot = 1_799_990_000
	st := powerState{Kind: "restart", Source: "os", Boot: boot, At: now.Add(-30 * time.Second).Unix()}
	rmmSt := st
	rmmSt.Source = "rmm"
	for _, c := range []struct {
		name         string
		st           powerState
		kind, source string
		boot         int64
		at           time.Time
		skip         bool
	}{
		{"nothing sent", powerState{}, "restart", "os", boot, now, false},
		{"same kind same boot", st, "restart", "os", boot, now, true},
		{"boot time drift", st, "restart", "os", boot + 1, now, true},
		{"new boot", st, "restart", "os", boot + 600, now, false},
		{"other kind", st, "sleep", "os", boot, now, false},
		{"cancel always", st, "cancel", "os", boot, now, false},
		{"after the window", st, "restart", "os", boot, now.Add(powerAnnounceFor), false},
		{"os after rmm", rmmSt, "shutdown_or_restart", "os", boot, now, true},
		{"rmm after os", st, "shutdown", "rmm", boot, now, false},
		{"vaguer after precise", st, "shutdown_or_restart", "os", boot, now, true},
		{"precise after vague", powerState{Kind: "shutdown_or_restart", Source: "os", Boot: boot, At: st.At}, "restart", "os", boot, now, false},
		{"os shutdown after rmm sleep", powerState{Kind: "sleep", Source: "rmm", Boot: boot, At: st.At}, "shutdown", "os", boot, now, false},
		{"os sleep after rmm sleep", powerState{Kind: "sleep", Source: "rmm", Boot: boot, At: st.At}, "sleep", "os", boot, now, true},
		{"cancel after rmm", rmmSt, "cancel", "os", boot, now, false},
		{"wake cancel, nothing newer", powerState{}, "cancel", "wake", boot, now, false},
		{"wake cancel after a newer sleep", powerState{Kind: "sleep", Source: "os", Boot: boot, At: st.At}, "cancel", "wake", boot, now, true},
	} {
		if got := powerSkip(c.st, c.kind, c.source, c.boot, c.at); got != c.skip {
			t.Errorf("%s: skip %v, want %v", c.name, got, c.skip)
		}
	}
}

func TestPowerInitiator(t *testing.T) {
	if got := powerInitiator("  user maxi\x00 via Start menu \n"); got != "user maxi via Start menu" {
		t.Fatalf("got %q", got)
	}
	got := powerInitiator(strings.Repeat("ä", 150))
	if len(got) != 200 || !utf8.ValidString(got) {
		t.Fatalf("len %d valid %v", len(got), utf8.ValidString(got))
	}
	got = powerInitiator("x" + strings.Repeat("ä", 150))
	if len(got) != 199 || !utf8.ValidString(got) {
		t.Fatalf("len %d valid %v", len(got), utf8.ValidString(got))
	}
}

func powerTestDir(t *testing.T) {
	dir := t.TempDir()
	old := awakeStateDir
	awakeStateDir = func() string { return dir }
	t.Cleanup(func() { awakeStateDir = old })
}

func TestPowerStateFile(t *testing.T) {
	powerTestDir(t)
	if st := loadPowerState(); st.Kind != "" {
		t.Fatalf("empty dir: %+v", st)
	}
	st := powerState{Kind: "sleep", Source: "os", Boot: 5, At: time.Now().Unix()}
	savePowerState(st)
	if got := loadPowerState(); got != st {
		t.Fatalf("got %+v", got)
	}
	powerResumed()
	if _, err := os.Stat(powerStateFile()); !os.IsNotExist(err) {
		t.Fatalf("still there: %v", err)
	}
}

// NATS_URL=nats://127.0.0.1:4222 go test ./agent/ -run TestAnnouncePowerNATS
func TestAnnouncePowerNATS(t *testing.T) {
	url := os.Getenv("NATS_URL")
	if url == "" {
		t.Skip("NATS_URL not set")
	}
	powerTestDir(t)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	a := &Agent{Logger: logrus.New(), AgentID: "powertest"}
	got := make(chan *nats.Msg, 8)
	if _, err := nc.ChanSubscribe(a.AgentID+".checkin", got); err != nil {
		t.Fatal(err)
	}
	nc.Flush()
	expect := func(kind, source, by string) {
		t.Helper()
		select {
		case m := <-got:
			var r rmm.PowerReport
			if err := codec.NewDecoderBytes(m.Data, new(codec.MsgpackHandle)).Decode(&r); err != nil {
				t.Fatal(err)
			}
			if m.Reply != "agent-power" || r != (rmm.PowerReport{AgentID: a.AgentID, Kind: kind, Source: source, Initiator: by}) {
				t.Fatalf("got %q %+v", m.Reply, r)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s not received", kind)
		}
	}
	none := func() {
		t.Helper()
		select {
		case m := <-got:
			t.Fatalf("unexpected %q", m.Data)
		case <-time.After(300 * time.Millisecond):
		}
	}
	send := func(kind, source, by string) {
		t.Helper()
		if err := a.announcePower(nc, kind, source, by, 2*time.Second); err != nil {
			t.Fatal(err)
		}
	}

	send("restart", "rmm", "rmm: rebootnow")
	expect("restart", "rmm", "rmm: rebootnow")
	send("restart", "rmm", "rmm: rebootnow")
	send("shutdown_or_restart", "os", "")
	none()
	if !a.powerAnnounced() {
		t.Fatal("powerAnnounced false after restart")
	}
	send("cancel", "os", "")
	expect("cancel", "os", "")
	if a.powerAnnounced() {
		t.Fatal("powerAnnounced after cancel")
	}
	send("restart", "os", "user maxi")
	expect("restart", "os", "user maxi")

	// a new boot announces again
	st := loadPowerState()
	st.Boot -= 3600
	savePowerState(st)
	send("restart", "os", "user maxi")
	expect("restart", "os", "user maxi")
}
