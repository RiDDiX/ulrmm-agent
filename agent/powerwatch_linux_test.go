// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
)

// same layout as testdata/busctl-monitor-login1.txt
func busctlMsg(member, sig, body string) string {
	return "‣ Type=signal  Endian=l  Flags=1  Version=1 Cookie=2  Timestamp=\"Sun 2026-11-01 14:10:53.180126 UTC\"\n" +
		"  Sender=:1.20  Path=/org/freedesktop/login1  Interface=org.freedesktop.login1.Manager  Member=" + member + "\n" +
		"  UniqueName=:1.20\n  MESSAGE \"" + sig + "\" {\n" + body + "  };\n\n"
}

func metaBody(active, typ string) string {
	return "          BOOLEAN " + active + ";\n          ARRAY \"{sv}\" {\n                  DICT_ENTRY \"sv\" {\n" +
		"                          STRING \"type\";\n                          VARIANT \"s\" {\n" +
		"                                  STRING \"" + typ + "\";\n                          };\n                  };\n          };\n"
}

func TestScanLoginSignals(t *testing.T) {
	scan := func(s string) string {
		var got []string
		if err := scanLoginSignals(strings.NewReader(s), func(k string) { got = append(got, k) }); err != nil {
			t.Fatal(err)
		}
		return strings.Join(got, " ")
	}
	b, err := os.ReadFile("testdata/busctl-monitor-login1.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := scan(string(b)); got != "shutdown shutdown_or_restart" {
		t.Fatalf("captured: %q", got)
	}
	s := "Monitoring bus message stream.\n" +
		busctlMsg("PrepareForSleep", "b", "          BOOLEAN true;\n") +
		busctlMsg("PrepareForSleep", "b", "          BOOLEAN false;\n") +
		busctlMsg("PrepareForShutdownWithMetadata", "ba{sv}", metaBody("true", "reboot")) +
		busctlMsg("PrepareForShutdownWithMetadata", "ba{sv}", metaBody("true", "soft-reboot")) +
		busctlMsg("PrepareForShutdownWithMetadata", "ba{sv}", metaBody("true", "halt")) +
		busctlMsg("PrepareForShutdownWithMetadata", "ba{sv}", metaBody("false", "reboot")) +
		busctlMsg("PrepareForShutdown", "b", "          BOOLEAN false;\n") +
		busctlMsg("SessionNew", "so", "          STRING \"3\";\n          OBJECT_PATH \"/org/freedesktop/login1/session/_33\";\n")
	if got := scan(s); got != "sleep wake restart restart shutdown cancel cancel" {
		t.Fatalf("got %q", got)
	}
}

func TestShutdownKindFromJobs(t *testing.T) {
	for in, want := range map[string]string{
		"123 reboot.target start waiting\n":                                         "restart",
		"133 probe.service stop running\n":                                          "",
		"7 systemd-poweroff.service start waiting\n8 poweroff.target start waiting": "shutdown",
		"9 kexec.target start waiting":                                              "restart",
		"":                                                                          "",
	} {
		if got := shutdownKindFromJobs(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestPowerInhibitArgv(t *testing.T) {
	argv := powerInhibitArgv(4242)
	if argv[0] != "systemd-inhibit" || argv[1] != "--what=shutdown:sleep" || argv[4] != "--mode=delay" ||
		strings.Join(argv[5:], " ") != "tail --pid=4242 -f /dev/null" {
		t.Fatalf("%q", argv)
	}
	if !strings.Contains(strings.Join(loginMonitorArgv, " "), "sender='org.freedesktop.login1'") {
		t.Fatalf("monitor without sender match: %q", loginMonitorArgv)
	}
}

func TestAnnouncePowerOncePerKind(t *testing.T) {
	oldDir := nixAgentDir
	nixAgentDir = t.TempDir()
	t.Cleanup(func() { nixAgentDir = oldDir; powerResumed() })
	powerResumed()
	pubs := make(chan string, 16)
	nc, err := nats.Connect(fakeNats(t, pubs))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	a := testUpdateAgent()
	a.AgentID = "agent-1"
	sent := func(kind string) bool {
		t.Helper()
		if a.announcePower(nc, kind, "os", "user", time.Second) != nil {
			t.Fatalf("%s not flushed", kind)
		}
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
		select {
		case p := <-pubs:
			if p != "PUB agent-1.checkin agent-power" {
				t.Fatalf("published %q", p)
			}
			return true
		default:
			return false
		}
	}
	expected := filepath.Join(nixAgentDir, stopExpectedFile)

	if !sent("restart") || !a.powerAnnounced() {
		t.Fatal("first restart")
	}
	if _, err := os.Stat(expected); err != nil {
		t.Fatal("restart did not mark the stop as expected")
	}
	if sent("restart") {
		t.Fatal("restart sent twice")
	}
	if !sent("shutdown") {
		t.Fatal("another kind is a new message")
	}
	if !sent("cancel") || a.powerAnnounced() || !sent("cancel") {
		t.Fatal("cancel always goes out and resets")
	}
	if _, err := os.Stat(expected); !os.IsNotExist(err) {
		t.Fatal("cancel left the stop marked as expected")
	}
	if !sent("restart") {
		t.Fatal("restart after cancel")
	}
	recordStop(nixAgentDir, time.Now())
	if _, err := os.Stat(filepath.Join(nixAgentDir, stopManualFile)); !os.IsNotExist(err) {
		t.Fatal("an announced restart was recorded as a manual stop")
	}
	if !sent("sleep") || !a.powerAnnounced() {
		t.Fatal("sleep")
	}
	powerResumed()
	if a.powerAnnounced() || !sent("sleep") {
		t.Fatal("a wake forgets the last sleep")
	}
}

func TestUpgradeUnit(t *testing.T) {
	old := "[Unit]\nDescription=Agent\n\n[Service]\nType=simple\nExecStart=/mnt/x/agent -m svc\nKillMode=process\n\n[Install]\nWantedBy=multi-user.target\n"
	got := upgradeUnit(old)
	want := "[Unit]\nDescription=Agent\nAfter=network.target nss-lookup.target\n\n[Service]\nType=simple\nExecStart=/mnt/x/agent -m svc\nKillMode=process\nTimeoutStopSec=15\n\n[Install]\nWantedBy=multi-user.target\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
	if upgradeUnit(got) != got {
		t.Fatal("not idempotent")
	}
}
