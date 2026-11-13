// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func (a *Agent) newHealer() *healer {
	return &healer{
		p:       newHealPlatform(a),
		version: a.Version,
		agentID: a.AgentID,
		now:     time.Now,
		current: a.selfHealCurrent,
		fetch:   a.selfHealFetch,
		check:   a.selfHealCheck,
		refuse: func(why string) {
			a.queueSecurityEvent("update_refused", why)
			a.sendSecurityEvents()
		},
		report: a.selfHealReport,
		logf:   a.Logger.Infof,
	}
}

// SelfHealSetup runs in the agent service after start.
func (a *Agent) SelfHealSetup() {
	exe, err := os.Executable()
	if err != nil {
		a.Logger.Errorln("SelfHealSetup(): executable path:", err)
		return
	}
	if err := a.newHealer().setup(exe); err != nil {
		a.Logger.Errorln("SelfHealSetup():", err)
	}
}

func (a *Agent) SelfHealHeartbeat() {
	a.newHealer().heartbeat()
}

// RunSelfHeal is the scheduled check (-m selfheal).
func (a *Agent) RunSelfHeal() {
	for _, act := range a.newHealer().run() {
		a.Logger.Infoln("selfheal:", act)
	}
}

func (a *Agent) selfHealCurrent() (healDownload, error) {
	var d healDownload
	if a.AgentID == "" {
		return d, errors.New("agent has no id")
	}
	r, err := a.rClient.R().SetResult(&d).Get(fmt.Sprintf("/api/v3/%s/selfheal/", a.AgentID))
	if err != nil {
		return d, err
	}
	if r.IsError() {
		return d, fmt.Errorf("server answered %d", r.StatusCode())
	}
	if d.URL == "" || !sha256Hex.MatchString(d.SHA256) {
		return d, errors.New("server answer is incomplete")
	}
	return d, nil
}

// sha256 is checked on the file after this returns
func (a *Agent) selfHealFetch(url, dest string) error {
	return a.fetchFile(url, dest, "", 10*time.Minute)
}

func (a *Agent) selfHealReport(actions []string) {
	payload := map[string]interface{}{"agent_id": a.AgentID, "actions": actions}
	if _, err := a.rClient.R().SetBody(payload).Post(fmt.Sprintf("/api/v3/%s/selfheal/", a.AgentID)); err != nil {
		a.Logger.Debugln("selfHealReport():", err)
	}
}

// healCmd runs a system tool with a hard timeout and returns its output.
func healCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// a child that keeps the pipe open must not hold the caller past the timeout
	cmd.WaitDelay = pipeDrain
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil
	}
	return string(out), err
}

// healExit is the exit status of a command that ran to its end; done is
// false when it timed out, was killed or could not start.
func healExit(err error) (code int, done bool) {
	if err == nil {
		return 0, true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		return ee.ExitCode(), true
	}
	return 0, false
}

// launchdServiceState reads `launchctl print system/<label>`. Only launchd
// saying it does not know the job (113) means missing; an answer it cannot
// read leaves the service alone.
func launchdServiceState(out string, err error, plist bool) (installed, running bool) {
	switch code, done := healExit(err); {
	case done && code == 0:
		return plist, strings.Contains(out, "state = running")
	case done && (code == 113 || strings.Contains(out, "Could not find service")):
		return false, false
	}
	return true, true
}

// rcServiceState reads `service <name> enabled` and `onestatus`: a non-zero
// exit is no; a query that did not finish leaves the service alone.
func rcServiceState(enabled, status error) (installed, running bool) {
	en, ok1 := healExit(enabled)
	st, ok2 := healExit(status)
	if !ok1 || !ok2 {
		return true, true
	}
	return en == 0, st == 0
}

// writeIfChanged avoids reloading service managers when nothing changed.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if b, err := os.ReadFile(path); err == nil && string(b) == content {
		return false, nil
	}
	return true, writeFileSynced(path, []byte(content), mode)
}
