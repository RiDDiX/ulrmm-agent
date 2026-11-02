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
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// writeIfChanged avoids reloading service managers when nothing changed.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if b, err := os.ReadFile(path); err == nil && string(b) == content {
		return false, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}
