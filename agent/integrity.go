// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Self-integrity: the server signs the sha256 of every agent build it ships
// (/api/v3/integrity/). At start and every integrityEvery the service hashes
// its own executable; a build of a listed version with other bytes is
// reported and replaced through the self-healing download, at most once per
// integrityRepairEvery. Versions the server does not list (own builds) are
// not checked, nor is Windows while the server knows only the setup.

const (
	integrityTyp         = "ulrmm-integrity"
	integrityPath        = "/api/v3/integrity/"
	integrityMax         = 1 << 20
	integrityEvery       = 6 * time.Hour
	integrityRepairEvery = 24 * time.Hour
	integrityStampFile   = "integrity-repair"
)

var integrityState struct {
	sync.Mutex
	at time.Time
}

// verifyIntegrityDoc checks the manifest like a pin document and returns
// the sha256 it lists for version on goos-goarch, "" when it lists none.
func verifyIntegrityDoc(jws, host, version, platform string) (string, error) {
	pub, err := enrollPubKey()
	if err != nil {
		return "", err
	}
	var c struct {
		V      int                          `json:"v"`
		Typ    string                       `json:"typ"`
		Iss    string                       `json:"iss"`
		Builds map[string]map[string]string `json:"builds"`
	}
	bad := func(why string) error { return fmt.Errorf("integrity manifest invalid: %s", why) }
	if err := verifyJWS(pub, jws, integrityTyp, integrityMax, &c); err != nil {
		return "", bad(err.Error())
	}
	if c.V != 1 || c.Typ != integrityTyp {
		return "", bad("version or type")
	}
	if u, err := url.Parse(c.Iss); err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), host) {
		return "", bad("issued for another server")
	}
	want := strings.ToLower(c.Builds[strings.TrimPrefix(version, "v")][platform])
	if want != "" && !sha256Hex.MatchString(want) {
		return "", bad("sha256 of " + platform)
	}
	return want, nil
}

// checkIntegrity runs at service start and from the heartbeat.
func (a *Agent) checkIntegrity(now time.Time) {
	if BrandEnrollPubKey == "" || a.BaseURL == "" {
		return
	}
	integrityState.Lock()
	if !integrityState.at.IsZero() && now.Sub(integrityState.at) < integrityEvery {
		integrityState.Unlock()
		return
	}
	integrityState.at = now
	integrityState.Unlock()

	jws, err := a.getIntegrityDoc()
	if err != nil {
		a.Logger.Debugln("checkIntegrity():", err)
		return
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		a.Logger.Errorln("checkIntegrity(): executable path:", err)
		return
	}
	a.integrity(a.newHealer(), jws, exe, now)
}

// integrity compares exe with the manifest and repairs a mismatch.
func (a *Agent) integrity(h *healer, jws, exe string, now time.Time) {
	want, err := verifyIntegrityDoc(jws, a.ApiURL, a.Version, runtime.GOOS+"-"+runtime.GOARCH)
	if err != nil {
		a.Logger.Errorln("checkIntegrity():", err)
		return
	}
	if want == "" {
		return
	}
	sum, err := fileSHA256(exe)
	if err != nil {
		a.Logger.Errorln("checkIntegrity():", err)
		return
	}
	if sum == want {
		return
	}
	a.Logger.Errorf("checkIntegrity(): %s has sha256 %s, the RMM build of %s has %s", exe, sum, a.Version, want)
	a.queueSecurityEvent("integrity_mismatch", fmt.Sprintf("%s %s: sha256 %s, expected %s", exe, a.Version, sum, want))
	a.sendSecurityEvents()

	stamp := filepath.Join(h.dir(), integrityStampFile)
	if b, err := os.ReadFile(stamp); err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); err == nil && now.Sub(t) < integrityRepairEvery {
			a.Logger.Errorln("checkIntegrity(): repaired once in the last 24h already, leaving it")
			return
		}
	}
	cur, cerr := h.current()
	if cerr != nil {
		a.Logger.Errorln("checkIntegrity(): no build from the server:", cerr)
		return
	}
	if !strings.EqualFold(cur.binarySHA256(), want) {
		// the download would be another build, maybe an older one that
		// cannot read this config
		a.Logger.Errorf("checkIntegrity(): the server ships %s (sha256 %s), not the listed build, not repairing", cur.Version, cur.binarySHA256())
		return
	}
	if err := os.MkdirAll(h.dir(), 0o700); err == nil {
		err = os.WriteFile(stamp, []byte(now.UTC().Format(time.RFC3339)), 0o600)
	}
	if err != nil {
		// without the stamp a repair that does not help would loop
		a.Logger.Errorln("checkIntegrity():", err)
		return
	}
	// the local copy counts only when it is the listed build
	expectStop(h.p.dataDir())
	if act, ok := h.repairBinary(healManifest{Version: a.Version, MainPath: exe, SHA256: want}, cur, nil); ok && h.report != nil {
		h.report([]string{"agent binary did not match the RMM build: " + act})
	}
}

func (a *Agent) getIntegrityDoc() (string, error) {
	c, err := a.httpClient(a.BaseURL, 30*time.Second)
	if err != nil {
		return "", err
	}
	resp, err := c.Get(strings.TrimRight(a.BaseURL, "/") + integrityPath)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("integrity manifest: the server answered %d", resp.StatusCode)
	}
	var body struct {
		JWS string `json:"jws"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, integrityMax+64)).Decode(&body); err != nil {
		return "", err
	}
	if body.JWS == "" {
		return "", errors.New("integrity manifest: empty answer")
	}
	return body.JWS, nil
}
