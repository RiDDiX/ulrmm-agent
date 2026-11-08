// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Self-healing: a job the operating system runs every few minutes, started
// from a verified copy of the agent, checks that the installed agent binary is
// intact, that the service is registered and running and that its main loop
// is not stuck. It restarts, restores the copy or reinstalls the current build
// from the rmm server. It never brings back an agent that was uninstalled.

const (
	healStaleAfter   = 30 * time.Minute
	healStaleConfirm = 10 * time.Minute
	healMaxRepairs   = 3
	healRepairWindow = 24 * time.Hour
)

type healManifest struct {
	Version  string `json:"version"`
	MainPath string `json:"main_path"`
	SHA256   string `json:"sha256"`
}

type healState struct {
	Repairs []time.Time `json:"repairs"`
	// first run that found the heartbeat stale; a run right after a wake
	// can come before the agent wrote a new one
	StaleSince time.Time `json:"stale_since,omitzero"`
}

// healDownload is what the server says the current build for this agent is.
type healDownload struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	// the same signed document an agentupdate carries
	UpdateSig string `json:"update_sig"`
	// Windows: URL and SHA256 are the setup, this is the agent exe inside it
	AgentSHA256 string `json:"agent_sha256"`
}

// binarySHA256 is what the installed agent binary hashes to once this build
// is installed.
func (d healDownload) binarySHA256() string {
	if d.AgentSHA256 != "" {
		return d.AgentSHA256
	}
	return d.SHA256
}

// healPlatform is the part that differs between Windows, Linux and macOS.
type healPlatform interface {
	dataDir() string
	configPresent() bool
	serviceState() (installed, running bool)
	ensureService(mainPath string) error
	restartService() error
	restoreBinary(src, mainPath string) error
	registerSchedule(healBin string) error
	removeSchedule() error
	installDownload(path, mainPath string) error
}

type healer struct {
	p       healPlatform
	version string
	agentID string
	now     func() time.Time
	// current asks the server for the current build; fetch downloads a file
	current func() (healDownload, error)
	fetch   func(url, dest string) error
	// check looks at a download before it is installed; refuse reports a
	// download the signature does not cover
	check  func(path, version string) error
	refuse func(why string)
	report func(actions []string)
	logf   func(format string, args ...interface{})
}

func (h *healer) dir() string          { return filepath.Join(h.p.dataDir(), "selfheal") }
func (h *healer) manifestPath() string { return filepath.Join(h.dir(), "manifest.json") }
func (h *healer) statePath() string    { return filepath.Join(h.dir(), "state.json") }
func (h *healer) heartbeatPath() string {
	return filepath.Join(h.dir(), "heartbeat")
}
func (h *healer) disabledPath() string { return filepath.Join(h.p.dataDir(), "selfheal.disabled") }

func (h *healer) healBin(mainPath string) string {
	return filepath.Join(h.dir(), filepath.Base(mainPath))
}

// setup runs inside the agent service: it records the running binary as the
// known good state, keeps a copy of it and registers the scheduled check.
func (h *healer) setup(runningExe string) error {
	if err := os.MkdirAll(h.dir(), 0o700); err != nil {
		return err
	}
	sum, err := fileSHA256(runningExe)
	if err != nil {
		return err
	}

	var m healManifest
	_ = readJSON(h.manifestPath(), &m)
	healBin := h.healBin(runningExe)

	if m.SHA256 != sum || m.MainPath != runningExe {
		// Same version but other bytes is either a rebuild the server now
		// ships or a changed file. Only the server can tell which one.
		if m.SHA256 != "" && m.Version == h.version && m.MainPath == runningExe {
			cur, cerr := h.current()
			if cerr != nil || !strings.EqualFold(cur.binarySHA256(), sum) {
				h.logf("selfheal: running binary differs from the recorded build and the server does not confirm it, keeping the record")
				return h.p.registerSchedule(healBin)
			}
		}
		if err := copyFileAtomic(runningExe, healBin, 0o700); err != nil {
			return err
		}
		m = healManifest{Version: h.version, MainPath: runningExe, SHA256: sum}
		if err := writeJSON(h.manifestPath(), m); err != nil {
			return err
		}
	} else if s, err := fileSHA256(healBin); err != nil || s != sum {
		if err := copyFileAtomic(runningExe, healBin, 0o700); err != nil {
			return err
		}
	}

	h.heartbeat()
	return h.p.registerSchedule(healBin)
}

// heartbeat is written from the agent's main loop; a stale one means the loop
// is stuck even though the process is still there.
func (h *healer) heartbeat() {
	_ = os.WriteFile(h.heartbeatPath(), []byte(h.now().UTC().Format(time.RFC3339)), 0o600)
}

// run is the scheduled check. It returns the repairs it made.
func (h *healer) run() []string {
	if healFileExists(h.disabledPath()) {
		return nil
	}

	// uninstalled on purpose: clean up, never reinstall
	if !h.p.configPresent() {
		h.logf("selfheal: agent configuration is gone, removing the self-healing job")
		_ = h.p.removeSchedule()
		_ = os.RemoveAll(h.dir())
		return nil
	}

	var m healManifest
	if err := readJSON(h.manifestPath(), &m); err != nil || m.MainPath == "" {
		// the service has not recorded a known good state yet
		return nil
	}

	var st healState
	_ = readJSON(h.statePath(), &st)
	st.prune(h.now())

	var actions []string
	repair := func(what string) bool {
		if len(st.Repairs) >= healMaxRepairs {
			h.logf("selfheal: %s needed, but %d repairs in the last 24h already; leaving it", what, len(st.Repairs))
			return false
		}
		st.Repairs = append(st.Repairs, h.now())
		// a restart from here is no tamper sign
		expectStop(h.p.dataDir())
		return true
	}

	restarted := false
	if sum, err := fileSHA256(m.MainPath); err != nil || sum != m.SHA256 {
		state := "missing"
		if err == nil {
			state = "modified"
		}
		cur, cerr := h.current()
		switch {
		case err == nil && cerr == nil && strings.EqualFold(sum, cur.binarySHA256()):
			// a newer or rebuilt agent the service has not recorded yet
			m.Version, m.SHA256 = cur.Version, sum
			_ = writeJSON(h.manifestPath(), m)
		case repair("binary " + state):
			if a, ok := h.repairBinary(m, cur, cerr); ok {
				actions = append(actions, fmt.Sprintf("agent binary was %s: %s", state, a))
				restarted = true
			}
		}
	}

	stale := h.heartbeatStale()
	if !stale {
		st.StaleSince = time.Time{}
	}
	installed, running := h.p.serviceState()
	switch {
	case !installed:
		if repair("service missing") {
			if err := h.p.ensureService(m.MainPath); err != nil {
				h.logf("selfheal: registering the service failed: %v", err)
			} else {
				actions = append(actions, "service was not registered: registered and started")
				restarted = true
			}
		}
	case !running:
		if repair("service stopped") {
			if err := h.p.restartService(); err != nil {
				h.logf("selfheal: starting the service failed: %v", err)
			} else {
				actions = append(actions, "service was not running: started")
				restarted = true
			}
		}
	case !restarted && stale:
		if st.StaleSince.IsZero() || h.now().Before(st.StaleSince) {
			st.StaleSince = h.now()
		} else if h.now().Sub(st.StaleSince) >= healStaleConfirm && repair("agent hung") {
			if err := h.p.restartService(); err != nil {
				h.logf("selfheal: restarting the hung agent failed: %v", err)
			} else {
				actions = append(actions, "agent main loop stopped responding: restarted")
				st.StaleSince = time.Time{}
			}
		}
	}

	if restarted {
		// the agent just started; its heartbeat from before (an update, a reboot) says nothing
		h.heartbeat()
		st.StaleSince = time.Time{}
	}
	_ = writeJSON(h.statePath(), st)
	if len(actions) > 0 && h.report != nil {
		h.report(actions)
	}
	return actions
}

func (h *healer) repairBinary(m healManifest, cur healDownload, cerr error) (string, bool) {
	healBin := h.healBin(m.MainPath)
	copySum, copyErr := fileSHA256(healBin)

	// the local copy is good and still what the server ships (or the server
	// is unreachable): put it back
	if copyErr == nil && copySum == m.SHA256 && (cerr != nil || strings.EqualFold(cur.binarySHA256(), m.SHA256)) {
		if err := h.p.restoreBinary(healBin, m.MainPath); err != nil {
			h.logf("selfheal: restoring the agent binary failed: %v", err)
			return "", false
		}
		return "restored from the local copy", true
	}

	if cerr != nil {
		h.logf("selfheal: no usable local copy and the server is unreachable: %v", cerr)
		return "", false
	}

	running := m.Version
	if running == "" {
		running = h.version
	}
	if c, ok := compareVersions(cur.Version, running); ok && c < 0 {
		// an older build may not read what this one stored
		h.logf("selfheal: the server ships %s, older than %s, not installing it", cur.Version, running)
		return "", false
	}
	if err := checkUpdateSig(cur.UpdateSig, h.agentID, cur.URL, cur.Version, cur.SHA256); err != nil {
		why := "unsigned selfheal: " + err.Error()
		h.logf("selfheal: %s, not installing %s", why, cur.Version)
		if h.refuse != nil {
			h.refuse(why)
		}
		return "", false
	}
	tmp := filepath.Join(h.dir(), "download.tmp")
	defer os.Remove(tmp)
	if err := h.fetch(cur.URL, tmp); err != nil {
		h.logf("selfheal: downloading the current build failed: %v", err)
		return "", false
	}
	sum, err := fileSHA256(tmp)
	if err != nil || !strings.EqualFold(sum, cur.SHA256) {
		h.logf("selfheal: downloaded build does not match the checksum from the server, not installing it")
		return "", false
	}
	if h.check != nil {
		if err := h.check(tmp, cur.Version); err != nil {
			h.logf("selfheal: downloaded build refused: %v", err)
			return "", false
		}
	}
	if err := h.p.installDownload(tmp, m.MainPath); err != nil {
		h.logf("selfheal: installing the downloaded build failed: %v", err)
		return "", false
	}
	return "reinstalled " + cur.Version + " from the server", true
}

func (h *healer) heartbeatStale() bool {
	b, err := os.ReadFile(h.heartbeatPath())
	if err != nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	return h.now().Sub(t) > healStaleAfter
}

func (s *healState) prune(now time.Time) {
	kept := s.Repairs[:0]
	for _, t := range s.Repairs {
		if now.Sub(t) < healRepairWindow {
			kept = append(kept, t)
		}
	}
	s.Repairs = kept
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func healFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// swapBinary is installDownload and restoreBinary on Linux, macOS and
// FreeBSD: the new file takes the binary's place, then the service restarts.
func swapBinary(p healPlatform, src, mainPath string) error {
	if err := copyFileAtomic(src, mainPath, 0o755); err != nil {
		return err
	}
	return p.restartService()
}

// copyFileAtomic never leaves a half written target: it writes next to it and
// renames. On Windows a running exe cannot be replaced; callers stop it first.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".selfheal-tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	// a power cut after the rename must not leave an empty binary
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(dst))
	return os.Chmod(dst, mode)
}

func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("empty file")
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSynced(path, b, 0o600)
}
