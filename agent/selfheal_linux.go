// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type linuxHeal struct{ logf func(string, ...interface{}) }

func newHealPlatform(a *Agent) healPlatform {
	l := linuxHeal{logf: func(string, ...interface{}) {}}
	if a != nil && a.Logger != nil {
		l.logf = a.Logger.Errorf
	}
	return l
}

func (linuxHeal) dataDir() string          { return nixAgentDir }
func (linuxHeal) configPresent() bool      { return healFileExists(etcConfig) }
func healUnitBase() string                 { return strings.TrimSuffix(IdentNixSvc, ".service") + "-selfheal" }
func (linuxHeal) unitPath(n string) string { return "/etc/systemd/system/" + n }

func (l linuxHeal) serviceState() (bool, bool) {
	// no --value: systemd before 230 (CentOS 7) does not know it
	out, err := healCmd(30*time.Second, "systemctl", "show", "-p", "LoadState", "-p", "ActiveState", IdentNixSvc)
	return healUnitState(out, err)
}

// healUnitState reads systemctl show; an answer it cannot read leaves the
// service alone.
func healUnitState(out string, err error) (installed, running bool) {
	u := parseUnitShow(out)
	if err != nil || u.load == "" {
		return true, true
	}
	switch u.active {
	case "active", "activating", "reloading":
		running = true
	}
	return u.load == "loaded", running
}

// same unit the server's install script writes
func (l linuxHeal) ensureService(mainPath string) error {
	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=%s -m svc
User=root
Group=root
Restart=always
RestartSec=5s
LimitNOFILE=1000000
KillMode=process
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
`, BrandAgentName, mainPath)
	if _, err := writeIfChanged(l.unitPath(IdentNixSvc), unit, 0o644); err != nil {
		return err
	}
	// an update on TrueNAS replaced /etc: the mesh unit and the timer went
	// with the agent unit. Their errors do not keep the agent from starting.
	var mesh error
	if onTrueNAS {
		mesh = restoreTrueNASMesh()
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", IdentNixSvc}, {"restart", IdentNixSvc}} {
		if out, err := healCmd(time.Minute, "systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	if onTrueNAS {
		// after the start: the timer fires right away and finds the agent
		// running. The agent runs, so a failing step is logged, not the repair.
		if err := errors.Join(mesh, l.registerSchedule(filepath.Join(nixAgentDir, "selfheal", filepath.Base(mainPath)))); err != nil {
			l.logf("selfheal: %v", err)
		}
	}
	return nil
}

func (linuxHeal) restartService() error {
	if out, err := healCmd(time.Minute, "systemctl", "restart", IdentNixSvc); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func (l linuxHeal) registerSchedule(healBin string) error {
	base := healUnitBase()
	svc := fmt.Sprintf(`[Unit]
Description=%s self-healing check

[Service]
Type=oneshot
ExecStart=%s -m selfheal
`, BrandAgentName, healBin)
	timer := fmt.Sprintf(`[Unit]
Description=%s self-healing check

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=2min

[Install]
WantedBy=timers.target
`, BrandAgentName)
	c1, err := writeIfChanged(l.unitPath(base+".service"), svc, 0o644)
	if err != nil {
		return err
	}
	c2, err := writeIfChanged(l.unitPath(base+".timer"), timer, 0o644)
	if err != nil {
		return err
	}
	if c1 || c2 {
		if out, err := healCmd(time.Minute, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("daemon-reload: %v: %s", err, out)
		}
	}
	if out, err := healCmd(time.Minute, "systemctl", "enable", "--now", base+".timer"); err != nil {
		return fmt.Errorf("enable timer: %v: %s", err, out)
	}
	if onTrueNAS {
		return ensureTrueNASInitTask()
	}
	return nil
}

func (l linuxHeal) removeSchedule() error {
	base := healUnitBase()
	_, _ = healCmd(time.Minute, "systemctl", "disable", "--now", base+".timer")
	_, _ = healCmd(10*time.Second, "rm", "-f", l.unitPath(base+".timer"), l.unitPath(base+".service"))
	_, err := healCmd(time.Minute, "systemctl", "daemon-reload")
	if onTrueNAS {
		if terr := removeTrueNASInitTask(); terr != nil {
			err = terr
		}
	}
	return err
}

// TrueNAS SCALE: a POSTINIT task in the middleware config survives updates
// and runs the self-healing check, which puts the units back.

type trueNASInitTask struct {
	ID      int    `json:"id"`
	Command string `json:"command"`
	When    string `json:"when"`
	Enabled bool   `json:"enabled"`
}

func midclt(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "midclt", append([]string{"call"}, args...)...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("midclt call %s: %v %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ours: the same command, as the server's install script writes it
func trueNASInitTasks() ([]trueNASInitTask, error) {
	out, err := midclt("initshutdownscript.query")
	if err != nil {
		return nil, err
	}
	var all, ours []trueNASInitTask
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, fmt.Errorf("initshutdownscript.query: %v", err)
	}
	for _, t := range all {
		if t.Command == trueNASInitCommand() {
			ours = append(ours, t)
		}
	}
	return ours, nil
}

func ensureTrueNASInitTask() error {
	tasks, err := trueNASInitTasks()
	if err != nil {
		return err
	}
	for _, t := range tasks {
		if t.When == "POSTINIT" && !t.Enabled {
			// switched off in the TrueNAS UI: left so, but said
			return fmt.Errorf("TrueNAS init task %d is disabled, the agent units will not come back after an update", t.ID)
		}
		if t.When == "POSTINIT" {
			return nil
		}
	}
	b, _ := json.Marshal(map[string]interface{}{
		"type": "COMMAND", "command": trueNASInitCommand(), "when": "POSTINIT",
		"enabled": true, "timeout": 120, "comment": BrandAgentName,
	})
	_, err = midclt("initshutdownscript.create", string(b))
	return err
}

func removeTrueNASInitTask() error {
	tasks, err := trueNASInitTasks()
	if err != nil {
		return err
	}
	for _, t := range tasks {
		if _, derr := midclt("initshutdownscript.delete", strconv.Itoa(t.ID)); derr != nil {
			err = derr
		}
	}
	return err
}

func restoreTrueNASMesh() error {
	if healFileExists(nixMeshUnit) || !healFileExists(nixMeshAgentBin) {
		return nil
	}
	if err := os.WriteFile(nixMeshUnit, []byte(trueNASMeshUnit()), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", filepath.Base(nixMeshUnit)}} {
		if out, err := healCmd(time.Minute, "systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

func (l linuxHeal) installDownload(path, mainPath string) error {
	if err := copyFileAtomic(path, mainPath, 0o755); err != nil {
		return err
	}
	if out, _ := healCmd(10*time.Second, "getenforce"); strings.TrimSpace(out) == "Enforcing" {
		_, _ = healCmd(time.Minute, "restorecon", "-v", mainPath)
	}
	return l.restartService()
}

func (l linuxHeal) restoreBinary(src, mainPath string) error { return swapBinary(l, src, mainPath) }
