// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHeal struct {
	dir        string
	config     bool
	installed  bool
	running    bool
	restarts   int
	ensured    int
	scheduled  string
	unschedule int
	installed2 string
}

func (f *fakeHeal) dataDir() string            { return f.dir }
func (f *fakeHeal) configPresent() bool        { return f.config }
func (f *fakeHeal) serviceState() (bool, bool) { return f.installed, f.running }
func (f *fakeHeal) ensureService(string) error {
	f.ensured++
	f.installed, f.running = true, true
	return nil
}
func (f *fakeHeal) restartService() error             { f.restarts++; f.running = true; return nil }
func (f *fakeHeal) registerSchedule(bin string) error { f.scheduled = bin; return nil }
func (f *fakeHeal) removeSchedule() error             { f.unschedule++; return nil }
func (f *fakeHeal) restoreBinary(src, main string) error {
	if err := copyFileAtomic(src, main, 0o755); err != nil {
		return err
	}
	return f.restartService()
}
func (f *fakeHeal) installDownload(path, main string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.installed2 = string(b)
	return os.WriteFile(main, b, 0o755)
}

type healFixture struct {
	t       *testing.T
	p       *fakeHeal
	h       *healer
	main    string
	now     time.Time
	server  healDownload
	srvErr  error
	payload string
	reports [][]string
	refused []string
}

func newHealFixture(t *testing.T) *healFixture {
	t.Helper()
	dir := t.TempDir()
	f := &healFixture{t: t, now: time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)}
	f.main = filepath.Join(dir, "bin", "agent")
	if err := os.MkdirAll(filepath.Dir(f.main), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.main, "good build")
	f.p = &fakeHeal{dir: filepath.Join(dir, "data"), config: true, installed: true, running: true}
	if err := os.MkdirAll(f.p.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.srvErr = errors.New("server unreachable")
	f.h = &healer{
		p:       f.p,
		version: "2.11.1",
		agentID: "agent-1",
		now:     func() time.Time { return f.now },
		current: func() (healDownload, error) { return f.server, f.srvErr },
		fetch: func(url, dest string) error {
			return os.WriteFile(dest, []byte(f.payload), 0o600)
		},
		refuse: func(why string) { f.refused = append(f.refused, why) },
		report: func(a []string) { f.reports = append(f.reports, a) },
		logf:   func(string, ...interface{}) {},
	}
	return f
}

// signedDownload is what the server answers for a build it ships.
func signedDownload(t *testing.T, version, url, sha string) healDownload {
	t.Helper()
	sig := updateSig(testEnrollKey(t), "url", url, "version", version, "sha256", sha)
	return healDownload{Version: version, URL: url, SHA256: sha, UpdateSig: sig}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func sumOf(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x")
	writeFile(t, p, content)
	s, err := fileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetupRecordsBuildAndRegistersJob(t *testing.T) {
	f := newHealFixture(t)
	if err := f.h.setup(f.main); err != nil {
		t.Fatal(err)
	}
	var m healManifest
	if err := readJSON(f.h.manifestPath(), &m); err != nil {
		t.Fatal(err)
	}
	if m.MainPath != f.main || m.SHA256 != sumOf(t, "good build") || m.Version != "2.11.1" {
		t.Fatalf("manifest %+v", m)
	}
	if readFile(t, f.h.healBin(f.main)) != "good build" {
		t.Fatal("heal copy missing")
	}
	if f.p.scheduled != f.h.healBin(f.main) {
		t.Fatalf("schedule registered for %q", f.p.scheduled)
	}
}

func TestSetupDoesNotBlessUnconfirmedChange(t *testing.T) {
	f := newHealFixture(t)
	if err := f.h.setup(f.main); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.main, "tampered, same version")
	if err := f.h.setup(f.main); err != nil {
		t.Fatal(err)
	}
	var m healManifest
	_ = readJSON(f.h.manifestPath(), &m)
	if m.SHA256 != sumOf(t, "good build") {
		t.Fatal("unconfirmed binary became the known good state")
	}

	// a rebuild the server confirms is accepted
	f.server, f.srvErr = healDownload{Version: "2.11.1", URL: "u", SHA256: sumOf(t, "tampered, same version")}, nil
	if err := f.h.setup(f.main); err != nil {
		t.Fatal(err)
	}
	_ = readJSON(f.h.manifestPath(), &m)
	if m.SHA256 != sumOf(t, "tampered, same version") {
		t.Fatal("confirmed rebuild was not recorded")
	}
}

func TestRestoresFromLocalCopyWhenServerUnreachable(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	writeFile(t, f.main, "corrupted")

	actions := f.h.run()
	if readFile(t, f.main) != "good build" {
		t.Fatal("binary not restored")
	}
	if len(actions) != 1 || !strings.Contains(actions[0], "restored from the local copy") || f.p.restarts != 1 {
		t.Fatalf("actions %v restarts %d", actions, f.p.restarts)
	}
	if len(f.reports) != 1 {
		t.Fatal("repair not reported")
	}
}

func TestReinstallsFromServerWhenCopyIsBad(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	writeFile(t, f.main, "corrupted")
	writeFile(t, f.h.healBin(f.main), "copy corrupted too")
	f.payload = "fresh build"
	f.server, f.srvErr = signedDownload(t, "2.11.2", "https://api/agentdist/x", sumOf(t, "fresh build")), nil

	actions := f.h.run()
	if f.p.installed2 != "fresh build" {
		t.Fatalf("download not installed, actions %v", actions)
	}
	if len(actions) != 1 || !strings.Contains(actions[0], "reinstalled 2.11.2") {
		t.Fatalf("actions %v", actions)
	}
}

func TestRefusesUnsignedDownload(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	_ = os.Remove(f.main)
	_ = os.Remove(f.h.healBin(f.main))
	f.payload = "fresh build"
	sha := sumOf(t, "fresh build")
	f.server, f.srvErr = healDownload{Version: "2.11.2", URL: "https://api/agentdist/x", SHA256: sha}, nil

	if actions := f.h.run(); f.p.installed2 != "" || len(actions) != 0 {
		t.Fatalf("installed %q actions %v", f.p.installed2, actions)
	}
	if len(f.refused) != 1 || !strings.Contains(f.refused[0], "unsigned selfheal") {
		t.Fatalf("refused %v", f.refused)
	}
	// a signature over another file is no better
	f.server = signedDownload(t, "2.11.2", "https://api/agentdist/other", sha)
	f.server.URL = "https://api/agentdist/x"
	if actions := f.h.run(); f.p.installed2 != "" || len(actions) != 0 || len(f.refused) != 2 {
		t.Fatalf("installed %q actions %v refused %v", f.p.installed2, actions, f.refused)
	}
	// the download goes through check before it is installed
	f.server = signedDownload(t, "2.11.2", "https://api/agentdist/x", sha)
	f.h.check = func(string, string) error { return errors.New("not an agent") }
	if actions := f.h.run(); f.p.installed2 != "" || len(actions) != 0 {
		t.Fatalf("installed %q actions %v", f.p.installed2, actions)
	}
}

func TestRefusesDownloadWithWrongChecksum(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	_ = os.Remove(f.main)
	_ = os.Remove(f.h.healBin(f.main))
	f.payload = "something else"
	f.server, f.srvErr = signedDownload(t, "2.11.2", "u", sumOf(t, "fresh build")), nil

	actions := f.h.run()
	if f.p.installed2 != "" || len(actions) != 0 {
		t.Fatalf("installed %q actions %v", f.p.installed2, actions)
	}
}

func TestRefusesOlderBuildFromServer(t *testing.T) {
	f := newHealFixture(t)
	f.h.version = "2.25.10.2026"
	_ = f.h.setup(f.main)
	_ = os.Remove(f.main)
	_ = os.Remove(f.h.healBin(f.main))
	f.payload = "old build"
	f.server, f.srvErr = signedDownload(t, "5.20.10.2026", "u", sumOf(t, "old build")), nil
	if actions := f.h.run(); f.p.installed2 != "" || len(actions) != 0 {
		t.Fatalf("installed %q actions %v", f.p.installed2, actions)
	}
	// the same version is a repair
	f.server = signedDownload(t, "2.25.10.2026", "u", f.server.SHA256)
	if actions := f.h.run(); f.p.installed2 != "old build" || len(actions) != 1 {
		t.Fatalf("installed %q actions %v", f.p.installed2, actions)
	}
}

func TestAcceptsNewerBuildConfirmedByServer(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	writeFile(t, f.main, "update 2.11.2")
	f.server, f.srvErr = healDownload{Version: "2.11.2", URL: "u", SHA256: sumOf(t, "update 2.11.2")}, nil

	if actions := f.h.run(); len(actions) != 0 {
		t.Fatalf("updated agent was repaired: %v", actions)
	}
	var m healManifest
	_ = readJSON(f.h.manifestPath(), &m)
	if m.Version != "2.11.2" || readFile(t, f.main) != "update 2.11.2" {
		t.Fatalf("manifest %+v", m)
	}
}

func TestUninstalledAgentIsNotResurrected(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	f.p.config = false
	f.p.installed, f.p.running = false, false
	_ = os.Remove(f.main)

	if actions := f.h.run(); len(actions) != 0 {
		t.Fatalf("actions %v", actions)
	}
	if f.p.unschedule != 1 || f.p.ensured != 0 || healFileExists(f.h.manifestPath()) {
		t.Fatal("job not removed or agent brought back")
	}
}

func TestServiceRepairs(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)

	f.p.running = false
	if a := f.h.run(); len(a) != 1 || f.p.restarts != 1 {
		t.Fatalf("stopped service: %v", a)
	}

	f.p.installed, f.p.running = false, false
	if a := f.h.run(); len(a) != 1 || f.p.ensured != 1 {
		t.Fatalf("missing service: %v", a)
	}
}

func TestHungAgentIsRestarted(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	if a := f.h.run(); len(a) != 0 {
		t.Fatalf("fresh heartbeat triggered %v", a)
	}
	f.now = f.now.Add(45 * time.Minute)
	if a := f.h.run(); len(a) != 1 || f.p.restarts != 1 {
		t.Fatalf("stale heartbeat: %v", a)
	}
}

// After an update the units are gone and the heartbeat is hours old: the heal
// that brings the service back must not have the next one call it hung.
func TestRestoredServiceIsNotHung(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	f.now = f.now.Add(3 * time.Hour)
	f.p.installed, f.p.running = false, false
	if a := f.h.run(); len(a) != 1 || f.p.ensured != 1 {
		t.Fatalf("missing service: %v", a)
	}
	f.now = f.now.Add(90 * time.Second)
	if a := f.h.run(); len(a) != 0 || f.p.restarts != 0 {
		t.Fatalf("the timer right after the restore: %v, %d restarts", a, f.p.restarts)
	}
	f.now = f.now.Add(45 * time.Minute)
	if a := f.h.run(); len(a) != 1 || f.p.restarts != 1 {
		t.Fatalf("no heartbeat since the restore: %v", a)
	}
}

func TestRepairsAreRateLimited(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	for i := 0; i < 5; i++ {
		f.p.running = false
		f.h.run()
		f.now = f.now.Add(time.Hour)
	}
	if f.p.restarts != healMaxRepairs {
		t.Fatalf("restarts %d", f.p.restarts)
	}
	f.now = f.now.Add(25 * time.Hour)
	f.p.running = false
	f.h.run()
	if f.p.restarts != healMaxRepairs+1 {
		t.Fatal("limit did not reset after 24h")
	}
}

func TestDisabledSwitch(t *testing.T) {
	f := newHealFixture(t)
	_ = f.h.setup(f.main)
	writeFile(t, f.h.disabledPath(), "")
	f.p.running = false
	if a := f.h.run(); len(a) != 0 {
		t.Fatalf("disabled healer acted: %v", a)
	}
}
