// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// The unix configuration is one flat JSON object at etcConfig, keys lower
// case. Only that file is read: a config planted in the working directory
// of a root process must not be picked up.

func readConfFile() (map[string]interface{}, error) {
	b, err := os.ReadFile(etcConfig)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: %v", etcConfig, err)
	}
	conf := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if _, dup := conf[strings.ToLower(k)]; !dup || k == strings.ToLower(k) {
			conf[strings.ToLower(k)] = v
		}
	}
	return conf, nil
}

// confText is a config value as text; hand-edited files may hold numbers
// or booleans where the installer writes strings.
func confText(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func NewAgentConfig() *rmm.LocalConfig {
	conf, err := readConfFile()
	if err != nil {
		return &rmm.LocalConfig{}
	}
	get := func(k string) string { return confText(conf[k]) }
	pk, _ := strconv.Atoi(get("agentpk"))
	ping, _ := strconv.Atoi(get("natspinginterval"))
	return &rmm.LocalConfig{
		ServerBase:    get("baseurl"),
		ID:            get("agentid"),
		APIHost:       get("apiurl"),
		AuthToken:     get("token"),
		PKText:        get("agentpk"),
		PKNum:         pk,
		CACert:        get("cert"),
		ProxyURL:      get("proxy"),
		MeshDir:       get("meshdir"),
		UnixTemp:      get("tmpdir"),
		NATSProxyPath: get("natsproxypath"),
		NATSProxyPort: get("natsproxyport"),
		NATSPort:      get("natsstandardport"),
		NATSPing:      ping,
		TLSCert:       get("clientcert"),
		TLSKey:        get("clientkey"),
		PinsJSON:      get("pins"),
	}
}

// confValue is one string value; "" when the agent is not installed.
func confValue(name string) (string, error) {
	conf, err := readConfFile()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	s, _ := conf[strings.ToLower(name)].(string)
	return s, nil
}

// confMu orders the read-modify-write of writeConfValues and dropConfValue.
var confMu sync.Mutex

// writeConfValues merges kv into the config. The file holds the agent token,
// so it is replaced by rename and never left half written.
func writeConfValues(kv map[string]string) error {
	confMu.Lock()
	defer confMu.Unlock()
	conf, err := readConfFile()
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("agent is not installed")
	}
	if err != nil {
		return err
	}
	for k, v := range kv {
		conf[strings.ToLower(k)] = v
	}
	return writeConfFile(conf, false)
}

// dropConfValue removes name from the config and returns what it held.
func dropConfValue(name string) (string, error) {
	confMu.Lock()
	defer confMu.Unlock()
	conf, err := readConfFile()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	v, ok := conf[strings.ToLower(name)]
	if !ok {
		return "", nil
	}
	delete(conf, strings.ToLower(name))
	return confText(v), writeConfFile(conf, false)
}

// writeConfFile writes the config with mode 0600 through a temp file in the
// same directory. With create set an existing config is left alone and
// reported as an error.
func writeConfFile(conf map[string]interface{}, create bool) error {
	b, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(etcConfig), ".conf*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err != nil {
		return err
	}
	if create {
		// link fails on an existing name: the create is exclusive and atomic
		return os.Link(tmp, etcConfig)
	}
	return os.Rename(tmp, etcConfig)
}

// createAgentConfig writes the config of a fresh install. The values come
// from the install flags only, never from an earlier installation.
func createAgentConfig(baseurl, agentid, apiurl, token, agentpk, cert, proxy, meshdir, natsport, tmpdir string) {
	conf := map[string]interface{}{
		"baseurl":          baseurl,
		"agentid":          agentid,
		"apiurl":           apiurl,
		"token":            token,
		"agentpk":          agentpk,
		"cert":             cert,
		"proxy":            proxy,
		"meshdir":          meshdir,
		"natsstandardport": natsport,
		"tmpdir":           tmpdir,
		"uninstallcode":    newUninstallCode(),
	}
	if err := writeConfFile(conf, true); err != nil {
		fmt.Fprintln(os.Stderr, "createAgentConfig", err)
		os.Exit(1)
	}
}

// RunMigrations tightens configs that older installs wrote group readable.
func (a *Agent) RunMigrations() {
	_ = os.Chmod(etcConfig, 0o600)
}

func (a *Agent) installerMsg(msg, alert string, _ bool) {
	if alert == "error" {
		a.Logger.Fatalln(msg)
	}
	a.Logger.Infoln(msg)
}

const (
	macMeshAgentPlist = "/Library/LaunchAgents/meshagent-agent.plist"
	freebsdMeshRc     = "/usr/local/etc/rc.d/meshagent"
)

func legacyMacMeshBin() string { return defaultMacMeshSvcDir + "/meshagent/meshagent" }

// checkExistingAndRemove clears an earlier macOS or FreeBSD installation
// before a new one is registered. Everything is best effort. Linux installs
// come from the server's script, which has already done this. The running
// binary stays.
func (a *Agent) checkExistingAndRemove(_ bool) {
	if runtime.GOOS == "freebsd" {
		if rmm.FileExists(nixMeshAgentBin) {
			a.Logger.Infoln("Existing mesh agent found, removing it")
			out, _ := healCmd(2*time.Minute, nixMeshAgentBin, "-uninstall")
			fmt.Println(out)
		}
		if rmm.FileExists(rcScriptPath()) {
			a.Logger.Infoln("Existing agent service found, stopping it")
			_, _ = healCmd(time.Minute, "service", rcName(), "onestop")
		}
		_ = newHealPlatform(a).removeSchedule()
		for _, p := range []string{nixMeshDir, etcConfig, nixAgentDir} {
			_ = os.RemoveAll(p)
		}
		return
	}
	if runtime.GOOS != "darwin" {
		return
	}
	if rmm.FileExists(a.MeshSystemEXE) {
		a.Logger.Infoln("Existing mesh agent found, removing it")
		out, _ := healCmd(time.Minute, a.MeshSystemEXE, "-fulluninstall")
		fmt.Println(out)
		time.Sleep(time.Second)
	}
	if rmm.FileExists(macPlistPath) {
		a.Logger.Infoln("Existing agent service found, removing it")
		_, _ = healCmd(time.Minute, "launchctl", "bootout", "system", macPlistPath)
	}
	// the old self-healing job would otherwise run against a deleted copy
	_ = newHealPlatform(a).removeSchedule()
	for _, p := range []string{defaultMacMeshSvcDir, nixMeshDir, etcConfig, nixAgentDir, macPlistPath} {
		_ = os.RemoveAll(p)
	}
}

// uninstallStep is one part of a local uninstall: a command or a path to
// delete.
type uninstallStep struct {
	argv    []string
	timeout time.Duration
	remove  string
}

// uninstallPlan lists what a local uninstall does, in order. meshBins are
// the mesh agent binaries that exist on this machine.
func uninstallPlan(goos string, meshBins []string) []uninstallStep {
	run := func(timeout time.Duration, argv ...string) uninstallStep {
		return uninstallStep{argv: argv, timeout: timeout}
	}
	rm := func(p string) uninstallStep { return uninstallStep{remove: p} }

	var plan []uninstallStep
	switch goos {
	case "linux":
		for _, m := range meshBins {
			plan = append(plan, run(2*time.Minute, "env", "XAUTHORITY=foo", "DISPLAY=bar", m, "-uninstall"))
		}
		plan = append(plan,
			run(time.Minute, "systemctl", "disable", "--now", "meshagent.service"),
			run(time.Minute, "systemctl", "disable", "--now", IdentNixSvc),
			rm(nixMeshUnit),
			rm("/etc/systemd/system/"+IdentNixSvc),
			run(time.Minute, "systemctl", "daemon-reload"),
			rm(nixMainBin))
	case "freebsd":
		// the mesh rc script also when its binary is gone; procfs in fstab stays
		for _, m := range meshBins {
			plan = append(plan, run(2*time.Minute, "env", "XAUTHORITY=foo", "DISPLAY=bar", m, "-uninstall"))
		}
		plan = append(plan,
			run(time.Minute, "service", "meshagent", "onestop"),
			run(time.Minute, "sysrc", "-x", "meshagent_enable"),
			rm(freebsdMeshRc),
			run(time.Minute, "service", rcName(), "onestop"),
			run(time.Minute, "sysrc", "-x", rcName()+"_enable"),
			rm(rcScriptPath()),
			rm(nixMainBin))
	case "darwin":
		for _, m := range meshBins {
			plan = append(plan, run(2*time.Minute, m, "-fulluninstall"))
		}
		plan = append(plan,
			run(time.Minute, "launchctl", "bootout", "system", macPlistPath),
			run(time.Minute, "security", "delete-generic-password", "-s", macPlistName, "-a", "kek", systemKeychain),
			rm(macPlistPath),
			rm(macMeshAgentPlist),
			rm(defaultMacMeshSvcDir))
	}
	plan = append(plan, rm(nixMeshDir), rm(etcConfig), rm(kekFile()), rm(kekCred()), rm(kekCredHost()), rm(nixAgentDir))
	for _, suffix := range []string{"", ".1", ".2"} {
		plan = append(plan, rm(NixLogFile+suffix))
	}
	return plan
}

// uninstallLocal removes the agent, its service, the self-healing job and
// the mesh agent. It also runs for an uninstall the server asks for, in a
// process of its own (AgentUninstall).
func (a *Agent) uninstallLocal() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if err := newHealPlatform(a).removeSchedule(); err != nil {
		a.Logger.Debugln("uninstall: self-healing job:", err)
	}
	var meshBins []string
	cands := []string{nixMeshAgentBin}
	if runtime.GOOS == "darwin" {
		cands = []string{legacyMacMeshBin(), nixMeshAgentBin}
	}
	for _, m := range cands {
		if rmm.FileExists(m) {
			meshBins = append(meshBins, m)
		}
	}

	var last error
	for _, s := range uninstallPlan(runtime.GOOS, meshBins) {
		if s.remove != "" {
			if err := os.RemoveAll(s.remove); err != nil {
				last = err
			}
			continue
		}
		if out, err := healCmd(s.timeout, s.argv[0], s.argv[1:]...); err != nil {
			a.Logger.Debugf("uninstall: %s: %v %s", strings.Join(s.argv, " "), err, strings.TrimSpace(out))
		}
	}
	return last
}
