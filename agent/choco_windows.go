// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/go-resty/resty/v2"
)

// Install script the server pins by sha256 when it has one.
func (a *Agent) InstallChoco() {
	conf := a.GetCheckInConfFromAPI()
	url, sha := chocoScriptSource(conf.ChocoInstallUrl, conf.ChocoInstallSha256)
	installed := false
	script, tmp, err := a.chocoScript(url, sha)
	if tmp != "" {
		defer os.Remove(tmp)
	}
	if err != nil {
		a.Logger.Errorln("InstallChoco(): download:", err)
	} else {
		_, stderr, code, err := a.RunScript(script, "powershell", []string{}, 900, false, []string{}, false, "")
		installed = err == nil && code == 0
		if !installed {
			a.Logger.Errorln("InstallChoco(): exit code", code, err, stderr)
		}
	}
	body := rmm.ChocoState{AgentID: a.AgentID, Present: installed}
	if _, err := a.rClient.R().SetBody(body).Post("/api/v3/choco/"); err != nil {
		a.Logger.Debugln("InstallChoco() post:", err)
	}
}

// Pinned copy uses the agent's TLS settings and must match sha. The public
// script is fetched with the system trust store only, kept in tmp as it came
// and run only when its signature checks out; the caller removes tmp.
func (a *Agent) chocoScript(url, sha string) (script, tmp string, err error) {
	if sha != "" {
		tmp := filepath.Join(a.WinTmpDir, fmt.Sprintf("chocoinstall-%d.ps1", time.Now().UnixNano()))
		defer os.Remove(tmp)
		if err := a.fetchFile(url, tmp, sha, 30*time.Second); err != nil {
			return "", "", err
		}
		b, err := os.ReadFile(tmp)
		return string(b), "", err
	}
	c := resty.New().SetTimeout(30 * time.Second)
	if a.Proxy != "" {
		if _, err := parseProxyURL(a.Proxy); err == nil {
			c.SetProxy(a.Proxy)
		}
	}
	r, err := c.R().Get(url)
	if err != nil {
		return "", "", err
	}
	if r.IsError() {
		return "", "", fmt.Errorf("download answered %d", r.StatusCode())
	}
	if err := createWinTempDir(); err != nil {
		return "", "", err
	}
	f, err := os.CreateTemp(a.WinTmpDir, "chocoinstall*.ps1")
	if err != nil {
		return "", "", err
	}
	_, err = f.Write(r.Body())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", f.Name(), err
	}
	return chocoSignedRun(f.Name()), f.Name(), nil
}

// chocoExe prefers the default install location over PATH.
func chocoExe() string {
	p := filepath.Join(os.Getenv("PROGRAMDATA"), "chocolatey", "bin", "choco.exe")
	if rmm.FileExists(p) {
		return p
	}
	if lp, err := exec.LookPath("choco.exe"); err == nil {
		return lp
	}
	return p
}

// Returned text is what the dashboard shows.
func (a *Agent) InstallWithChoco(name string) (string, error) {
	args, err := chocoArgs(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), chocoTimeout*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, timedOut, runErr := winExec(ctx, exec.CommandContext(ctx, chocoExe(), args...), &stdout, &stderr)
	return chocoResult(CleanString(stdout.String()), CleanString(stderr.String()), code, timedOut, runErr)
}
