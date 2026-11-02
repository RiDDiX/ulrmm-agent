// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Security events go to POST /api/v3/<agent>/security-event/ with the next
// REST answer that gets through. They wait in memory, the oldest dropped.
const (
	maxSecurityEvents = 20
	maxEventDetail    = 500
	securityEventPath = "/security-event/"
	// after a failed send (throttled, server without the endpoint)
	securityEventRetry = 5 * time.Minute
)

type securityEvent struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// queueSecurityEvent keeps one copy of an event that is already waiting.
func (a *Agent) queueSecurityEvent(kind, detail string) {
	if len(detail) > maxEventDetail {
		detail = strings.ToValidUTF8(detail[:maxEventDetail], "")
	}
	ev := securityEvent{kind, detail}
	a.eventsMu.Lock()
	defer a.eventsMu.Unlock()
	for _, e := range a.events {
		if e == ev {
			return
		}
	}
	if len(a.events) >= maxSecurityEvents {
		a.events = a.events[1:]
	}
	a.events = append(a.events, ev)
}

func (a *Agent) pendingSecurityEvents() bool {
	a.eventsMu.Lock()
	defer a.eventsMu.Unlock()
	return len(a.events) > 0
}

// sendSecurityEvents posts the queue in order. A 400 drops the event, any
// other failure keeps the rest for securityEventRetry.
func (a *Agent) sendSecurityEvents() {
	if a.AgentID == "" || a.rClient == nil || !a.sendingEvents.CompareAndSwap(false, true) {
		return
	}
	defer a.sendingEvents.Store(false)
	if time.Now().Before(a.eventsRetry) {
		return
	}
	for {
		a.eventsMu.Lock()
		if len(a.events) == 0 {
			a.eventsMu.Unlock()
			return
		}
		ev := a.events[0]
		a.eventsMu.Unlock()
		r, err := a.rClient.R().SetBody(ev).Post("/api/v3/" + a.AgentID + securityEventPath)
		if err != nil || (r.IsError() && r.StatusCode() != 400) {
			a.eventsRetry = time.Now().Add(securityEventRetry)
			return
		}
		a.eventsMu.Lock()
		for i, e := range a.events {
			if e == ev {
				a.events = append(a.events[:i:i], a.events[i+1:]...)
				break
			}
		}
		a.eventsMu.Unlock()
	}
}

// the config value the removed -insecure flag wrote
const confInsecure = "Insecure"

// dropInsecure removes the setting of the removed -insecure flag from the
// config of an older install.
func (a *Agent) dropInsecure() {
	v, err := dropConfValue(confInsecure)
	if err != nil {
		a.Logger.Errorln("dropInsecure():", err)
		return
	}
	if v == "true" {
		a.Logger.Warnln("The config turned TLS verification off; insecure mode was removed, the setting is dropped")
		a.queueSecurityEvent("insecure_dropped", "")
	}
}

// Agent versions are X.DD.MM.YYYY, compared as YYYY, MM, DD, X.
var agentVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d{1,2})\.(\d{1,2})\.(\d{4})$`)

func versionKey(v string) ([4]int, bool) {
	m := agentVersionRe.FindStringSubmatch(v)
	if m == nil {
		return [4]int{}, false
	}
	var k [4]int
	for i, j := range []int{4, 3, 2, 1} {
		k[i], _ = strconv.Atoi(m[j])
	}
	return k, true
}

// compareVersions is -1, 0 or 1 as a is older, equal or newer than b.
func compareVersions(a, b string) (int, bool) {
	ka, oka := versionKey(a)
	kb, okb := versionKey(b)
	if !oka || !okb {
		return 0, false
	}
	for i := range ka {
		switch {
		case ka[i] < kb[i]:
			return -1, true
		case ka[i] > kb[i]:
			return 1, true
		}
	}
	return 0, true
}

const updateTyp = "ulrmm-update"

// badDownload is a download that arrived but is not the file the server
// announced (hash, version), as opposed to one that failed on the way.
type badDownload struct{ error }

// checkUpdate decides on an agentupdate: https, a sha256, the server's
// signature over exactly url, version and sha256 for this agent, no
// downgrade. A build without the key cannot check the signature and takes
// no update. The same version is nothing to do (noop).
func (a *Agent) checkUpdate(link, version, sha, sig string) (noop bool, err error) {
	if !strings.HasPrefix(strings.ToLower(link), "https://") {
		return false, errors.New("the download is not https")
	}
	if !sha256Hex.MatchString(sha) {
		return false, errors.New("the update has no valid sha256")
	}
	if err := checkUpdateSig(sig, a.AgentID, link, version, sha); err != nil {
		return false, fmt.Errorf("unsigned: %w", err)
	}
	cmp, ok := compareVersions(version, a.Version)
	switch {
	case !ok:
		return false, fmt.Errorf("version %.64q cannot be compared with %s", version, a.Version)
	case cmp < 0:
		return false, fmt.Errorf("downgrade from %s to %s", a.Version, version)
	}
	return cmp == 0, nil
}

func checkUpdateSig(sig, agentID, link, version, sha string) error {
	if sig == "" {
		return errors.New("the update is not signed")
	}
	pub, err := enrollPubKey()
	if err != nil {
		return err
	}
	var c struct {
		V       int    `json:"v"`
		Typ     string `json:"typ"`
		Agent   string `json:"agent"`
		URL     string `json:"url"`
		Version string `json:"version"`
		Sha256  string `json:"sha256"`
	}
	if err := verifyJWS(pub, sig, updateTyp, 8192, &c); err != nil {
		return errors.New("update signature invalid: " + err.Error())
	}
	switch {
	case c.V != 1 || c.Typ != updateTyp:
		return errors.New("update signature invalid: version or type")
	case c.Agent != agentID:
		return errors.New("the update is signed for another agent")
	case c.URL != link || c.Version != version || c.Sha256 != sha:
		return errors.New("the signature does not cover this update")
	}
	return nil
}

// envDenied mirrors ENV_DENIED of the server (scripts/models.py): names
// that load code or swap a binary before a script starts, and the Windows
// directories library scripts build paths from. Case does not matter.
var envDenied = regexp.MustCompile(`(?i)^(?:(?:LD_|DYLD_|PYTHON|DENO_|PS|COR_|CORECLR_|COMPLUS_|DOTNET_).*` +
	`|PATH|BASH_ENV|ENV|SHELL|HOME|NODE_OPTIONS` +
	`|PROMPT_COMMAND|IFS|TMP|TEMP|TMPDIR|SYSTEMROOT|COMSPEC|PATHEXT|HOSTNAME` +
	`|USERNAME|USER|LOGNAME` +
	`|WINDIR|SYSTEMDRIVE|PROGRAMFILES|PROGRAMW6432|COMMONPROGRAMFILES` +
	`|COMMONPROGRAMW6432|PROGRAMDATA|ALLUSERSPROFILE|USERPROFILE|APPDATA` +
	`|LOCALAPPDATA` +
	`|PERL5OPT|PERL5LIB|PERLLIB|RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS` +
	`|OPENSSL_CONF|OPENSSL_MODULES|GCONV_PATH|XDG_CONFIG_HOME|XDG_DATA_HOME|GIT_SSH_COMMAND|SSLKEYLOGFILE)$`)

// dropDeniedEnv leaves out KEY=VALUE entries with a denied name; the name
// is logged, the value never.
func (a *Agent) dropDeniedEnv(env []string) []string {
	ret := make([]string, 0, len(env))
	for _, v := range env {
		if name, _, _ := strings.Cut(v, "="); envDenied.MatchString(name) {
			a.Logger.Warnln("RunScript(): dropped the denied environment variable", name)
			continue
		}
		ret = append(ret, v)
	}
	return ret
}

const maxAuthFile = 4096

// ReadAuthFile returns the installer token in path and deletes the file.
// It must be a regular file (no link) that only root may read (mode 0600
// or stricter), on Windows owned by Administrators, SYSTEM or the user
// running the installer.
func ReadAuthFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	li, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !li.Mode().IsRegular() || !os.SameFile(fi, li) {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if err := authFileOwnerOK(path, fi); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAuthFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxAuthFile {
		return "", fmt.Errorf("%s is too large for a token", path)
	}
	f.Close()
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("the token file cannot be deleted: %v", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("%s holds no token", path)
	}
	return tok, nil
}
