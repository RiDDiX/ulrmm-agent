// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/gonutz/w32/v2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The Windows configuration is the key HKLM\SOFTWARE\<IdentWinRegKey>, all
// values REG_SZ, in the registry view of the build (a 386 agent on 64-bit
// Windows lives under WOW6432Node, where the uninstaller also looks).

var agentKeyPath = `SOFTWARE\` + IdentWinRegKey

// configKeySDDL: SYSTEM and Administrators only, not inherited from
// HKLM\SOFTWARE; the key holds the agent token.
const configKeySDDL = "D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)"

func NewAgentConfig() *rmm.LocalConfig {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return &rmm.LocalConfig{}
	}
	defer k.Close()
	get := func(name string) string {
		v, _, _ := k.GetStringValue(name)
		return v
	}
	// the installer wrote -tmpdir as TmpDir up to 2.09.10.2026
	tmp := get("WinTmpDir")
	if tmp == "" {
		tmp = get("TmpDir")
	}
	pk, _ := strconv.Atoi(get("AgentPK"))
	ping, _ := strconv.Atoi(get("NatsPingInterval"))
	return &rmm.LocalConfig{
		ServerBase:    get("BaseURL"),
		ID:            get("AgentID"),
		APIHost:       get("ApiURL"),
		AuthToken:     get("Token"),
		PKText:        get("AgentPK"),
		PKNum:         pk,
		CACert:        get("Cert"),
		ProxyURL:      get("Proxy"),
		MeshDir:       get("MeshDir"),
		WinTemp:       tmp,
		WinUserTemp:   get("WinRunAsUserTmpDir"),
		NATSProxyPath: get("NatsProxyPath"),
		NATSProxyPort: get("NatsProxyPort"),
		NATSPort:      get("NatsStandardPort"),
		NATSPing:      ping,
		TLSCert:       get(confClientCert),
		TLSKey:        get(confClientKey),
		PinsJSON:      get(confPins),
	}
}

// confValue is one string value; "" when the key or the value is missing.
func confValue(name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return v, err
}

// writeConfValues writes into the existing key; it never creates it.
func writeConfValues(kv map[string]string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return errors.New("agent is not installed")
	}
	if err != nil {
		return err
	}
	defer k.Close()
	for _, name := range confWriteOrder(kv) {
		if err := k.SetStringValue(name, kv[name]); err != nil {
			return err
		}
	}
	return nil
}

// dropConfValue removes name from the key and returns what it held.
func dropConfValue(name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err := k.DeleteValue(name); err != nil {
		return "", err
	}
	return v, nil
}

// createAgentConfig writes the configuration of a fresh install. The key is
// locked down before the token goes in. Any failure ends the installer.
func createAgentConfig(baseurl, agentid, apiurl, token, agentpk, cert, proxy, meshdir, natsport, tmpdir string) {
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "createAgentConfig:", err)
		os.Exit(1)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, agentKeyPath, registry.ALL_ACCESS)
	if err != nil {
		fail(err)
	}
	defer k.Close()
	if err := protectConfigKey(); err != nil {
		fail(err)
	}
	values := []struct{ name, v string }{
		{"BaseURL", baseurl},
		{"AgentID", agentid},
		{"ApiURL", apiurl},
		{"Token", token},
		{"AgentPK", agentpk},
		{confUninstallKey, newUninstallCode()},
		// a key left over from an earlier install keeps its values
		{confConfigMAC, ""},
		{confTrustSnapshot, ""},
	}
	for _, opt := range []struct{ name, v string }{
		{"Cert", cert},
		{"Proxy", proxy},
		{"MeshDir", meshdir},
		{"NatsStandardPort", natsport},
		{"WinTmpDir", tmpdir},
	} {
		if opt.v != "" {
			values = append(values, opt)
		}
	}
	for _, v := range values {
		if err := k.SetStringValue(v.name, v.v); err != nil {
			fail(err)
		}
	}
}

// protectConfigKey keeps standard users from reading the token. It runs at
// install and at every service start.
func protectConfigKey() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, windows.WRITE_DAC|windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer k.Close()
	sd, err := windows.SecurityDescriptorFromString(configKeySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// checkExistingAndRemove stops the installer when this machine already has
// a configured agent. Exit code 0: deployment tools treat a
// second run on an installed machine as done.
func (a *Agent) checkExistingAndRemove(silent bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	k.Close()
	text := existingInstallText(filepath.Join(a.ProgramDir, a.GetUninstallExe()))
	if !silent && w32.GetForegroundWindow() != 0 {
		w32.MessageBox(0, text, BrandProductName, w32.MB_OK|w32.MB_ICONWARNING)
	} else {
		fmt.Println(text)
	}
	os.Exit(0)
}

// installerMsg shows msg in a message box for an interactive install and
// prints it otherwise. "error" ends the installer with exit code 1.
func (a *Agent) installerMsg(msg, level string, silent bool) {
	if !silent && w32.GetForegroundWindow() != 0 {
		icon := uint(w32.MB_ICONINFORMATION)
		if level == "error" {
			icon = w32.MB_ICONERROR
		}
		w32.MessageBox(0, msg, BrandProductName, w32.MB_OK|icon)
	} else {
		fmt.Println(msg)
	}
	if level == "error" {
		a.Logger.Fatalln(msg)
	}
}
