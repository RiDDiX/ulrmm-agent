// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/go-resty/resty/v2"
)

// Installer holds the -m install flags.
type Installer struct {
	RMM, Token, Cert, Proxy string
	Headers                 map[string]string
	Timeout                 time.Duration
	NatsStandardPort        string

	ClientID, SiteID       int
	AgentType, Description string

	Power, RDP, Ping, SaltMaster bool
	Silent                       bool
	TmpDir                       string

	NoMesh                         bool
	LocalMesh, MeshDir, MeshNodeID string
	// -enroll: the file, then the verified JWS and its certificate pins
	EnrollFile string
	Enroll     string
	Pins       []string
}

// Errors end the process through installerMsg. A generic installer given as
// -enroll ends it with exit code 3.
func (a *Agent) Install(i *Installer) {
	fail := func(msg string) { a.installerMsg(msg, "error", i.Silent) }

	// before anything of an earlier installation is removed
	if i.EnrollFile != "" {
		if err := applyEnrollment(i, time.Now()); errors.Is(err, ErrNoEnrollment) {
			fmt.Println(err)
			os.Exit(3)
		} else if err != nil {
			fail(err.Error())
			return
		}
	}
	// a reinstall must not present the previous agent's certificate
	a.clientCert.Store(nil)
	a.checkExistingAndRemove(i.Silent)

	auth := "Token " + i.Token
	if i.Enroll != "" {
		auth = "Enroll " + i.Enroll
	}
	i.Headers = map[string]string{
		"content-type":  "application/json",
		"Authorization": auth,
	}
	a.AgentID = GenerateAgentID()
	a.Logger.Debugln("Agent ID:", a.AgentID)

	u, err := url.Parse(i.RMM)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		fail("Invalid URL (must start with https://)")
		return
	}
	a.ApiURL = u.Hostname()
	baseURL := u.Scheme + "://" + u.Host
	a.Logger.Debugln("API:", a.ApiURL, "Base URL:", baseURL)

	if i.Cert != "" && !rmm.FileExists(i.Cert) {
		fail(fmt.Sprintf("%s does not exist", i.Cert))
		return
	}
	// the trust of this install: its CA, proxy and pins, nothing of an earlier one
	a.BaseURL, a.Cert, a.Proxy = baseURL, i.Cert, i.Proxy
	a.pins.Store(nil)
	if len(i.Pins) > 0 {
		a.pins.Store(&pinSet{Primary: i.Pins})
	}
	if i.Proxy != "" {
		p, err := parseProxyURL(i.Proxy)
		if err != nil {
			fail(err.Error())
			return
		}
		a.Logger.Infoln("Using proxy:", p.Redacted())
	}
	client := func(timeout time.Duration) *resty.Client {
		return a.restyFor(a.ApiURL).SetTimeout(timeout).SetHeaders(i.Headers)
	}

	// the installer token is checked before anything is installed
	iClient := client(15 * time.Second)
	r, err := iClient.R().Get(baseURL + "/api/v3/installer/")
	if err != nil {
		fail(err.Error())
		return
	}
	if r.StatusCode() == 401 && i.Enroll != "" {
		fail("The server refused the enrollment data: the deployment has expired or was deleted.")
		return
	}
	if r.StatusCode() == 401 {
		fail("Installer token has expired. Please generate a new one.")
		return
	}
	r, err = iClient.R().SetBody(map[string]string{"version": a.Version}).Post(baseURL + "/api/v3/installer/")
	if err != nil {
		fail(err.Error())
		return
	}
	if r.StatusCode() != 200 {
		fail(DjangoStringResp(r.String()))
		return
	}

	rClient := client(i.Timeout)
	var meshNodeID string
	if !meshSupported(runtime.GOOS, runtime.GOARCH) {
		a.Logger.Infoln("No mesh agent for", runtime.GOOS, runtime.GOARCH)
	} else if runtime.GOOS != "linux" && !i.NoMesh {
		if meshNodeID, err = a.installMeshAgent(rClient, baseURL, i); err != nil {
			fail(err.Error())
			return
		}
	}
	if i.MeshNodeID != "" {
		meshNodeID = i.MeshNodeID
	}

	a.Logger.Infoln("Adding agent to dashboard")
	payload := map[string]interface{}{
		"agent_id": a.AgentID, "agent_ident": IdentWinSvcName, "version": a.Version,
		"hostname": a.Hostname, "plat": a.Platform, "goarch": a.GoArch,
		"site": i.SiteID, "monitoring_type": i.AgentType, "description": i.Description,
		"mesh_node_id": meshNodeID,
	}
	// the server signs it when mTLS is on; the key never leaves this machine
	csr, key, err := newCSR(a.AgentID)
	if err != nil {
		a.Logger.Errorln("Install(): certificate request:", err)
	} else {
		payload["csr"] = csr
	}
	var created struct {
		PK    int    `json:"pk"`
		Token string `json:"token"`
		Cert  string `json:"cert"`
	}
	r, err = rClient.R().SetBody(payload).SetResult(&created).Post(baseURL + "/api/v3/newagent/")
	if err != nil {
		fail(err.Error())
		return
	}
	if r.StatusCode() != 200 {
		fail(r.String())
		return
	}

	createAgentConfig(baseURL, a.AgentID, a.ApiURL, created.Token, strconv.Itoa(created.PK), i.Cert, i.Proxy,
		i.MeshDir, i.NatsStandardPort, i.TmpDir)
	if ps := a.pins.Load(); ps != nil {
		if err := savePins(ps); err != nil {
			a.Logger.Errorln("Install(): pins:", err)
		}
	}
	if created.Cert != "" {
		if _, err := keyPair(created.Cert, key); err != nil {
			a.Logger.Errorln("Install(): client certificate:", err)
		} else if err := setConfValues(map[string]string{confClientCert: created.Cert, confClientKey: key}); err != nil {
			a.Logger.Errorln("Install(): client certificate:", err)
		}
	}
	time.Sleep(time.Second)

	// from here on the agent runs with the config just written
	na := New(a.Logger, a.Version)
	time.Sleep(3 * time.Second)
	na.DoNatsCheckIn()

	switch runtime.GOOS {
	case "linux":
		if err := os.MkdirAll(nixAgentBinDir, 0o755); err != nil {
			a.Logger.Errorln("Install(): bin dir:", err)
		}
	case "darwin":
		if err := na.installMacService(); err != nil {
			fail(err.Error())
			return
		}
	case "freebsd":
		if err := na.installFreeBSDService(); err != nil {
			fail(err.Error())
			return
		}
	case "windows":
		na.installWindowsService(i)
	}

	a.installerMsg("Installation was successful!\nAllow a few minutes for the agent to properly display in the RMM", "info", i.Silent)
}

// fstabPath is a variable for the tests.
var fstabPath = "/etc/fstab"

// MeshCentral's FreeBSD agent refuses to run without procfs on /proc, which
// FreeBSD does not mount by default. The fstab line keeps it after a reboot.
func ensureProcfs() error {
	if err := addProcfsToFstab(); err != nil {
		return err
	}
	if out, _ := healCmd(time.Minute, "mount", "-t", "procfs"); strings.Contains(out, " on /proc ") {
		return nil
	}
	if out, err := healCmd(time.Minute, "mount", "/proc"); err != nil {
		return fmt.Errorf("mount /proc: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

func addProcfsToFstab() error {
	b, err := os.ReadFile(fstabPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if fstabHasProcfs(string(b)) {
		return nil
	}
	f, err := os.OpenFile(fstabPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	line := "proc\t/proc\tprocfs\trw\t0\t0\n"
	if len(b) > 0 && b[len(b)-1] != '\n' {
		line = "\n" + line
	}
	_, err = f.WriteString(line)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func fstabHasProcfs(fstab string) bool {
	for _, l := range strings.Split(fstab, "\n") {
		if f := strings.Fields(l); len(f) >= 3 && !strings.HasPrefix(f[0], "#") && f[1] == "/proc" && f[2] == "procfs" {
			return true
		}
	}
	return false
}

// MeshCentral ships no FreeBSD agent for arm64.
func meshSupported(goos, goarch string) bool {
	return goos != "freebsd" || goarch == "amd64"
}

// From the RMM, or the local copy. Linux never gets here: its install script
// handles the mesh agent.
func (a *Agent) installMeshAgent(c *resty.Client, baseURL string, i *Installer) (string, error) {
	var meshBin string
	if runtime.GOOS == "windows" {
		meshBin = filepath.Join(a.ProgramDir, a.MeshInstaller)
	} else {
		dir := i.TmpDir
		if dir == "" {
			dir = a.UnixTmpDir
		}
		f, err := createNixTmpFile(dir)
		if err != nil {
			return "", fmt.Errorf("Failed to create mesh agent file: %v", err)
		}
		meshBin = f.Name()
		f.Close()
		defer os.Remove(meshBin)
		defer os.Remove(meshBin + ".msh")
	}

	if runtime.GOOS == "windows" && i.LocalMesh != "" {
		if err := copyFile(i.LocalMesh, meshBin); err != nil {
			return "", err
		}
	} else {
		a.Logger.Infoln("Downloading mesh agent...")
		payload := map[string]string{"goarch": a.GoArch, "plat": a.Platform}
		r, err := c.R().SetBody(payload).SetOutput(meshBin).Post(baseURL + "/api/v3/meshexe/")
		if err != nil {
			return "", fmt.Errorf("Failed to download mesh agent: %v", err)
		}
		if r.StatusCode() != 200 {
			body, _ := os.ReadFile(meshBin)
			return "", fmt.Errorf("Unable to download the mesh agent from the RMM. %s", body)
		}
	}
	if err := os.Chmod(meshBin, 0o755); err != nil && runtime.GOOS != "windows" {
		return "", err
	}

	a.Logger.Infoln("Installing mesh agent...")
	time.Sleep(time.Second)
	if runtime.GOOS == "windows" {
		id, err := a.installMesh(meshBin, a.MeshSystemEXE, i.Proxy)
		if err != nil {
			return "", fmt.Errorf("Failed to install mesh agent: %v", err)
		}
		return id, nil
	}

	if runtime.GOOS == "freebsd" {
		if err := ensureProcfs(); err != nil {
			return "", err
		}
	}
	opts := a.NewCMDOpts()
	opts.IsScript = true
	opts.Shell = meshBin
	opts.Args = []string{"-install", "--installPath=" + nixMeshDir}
	opts.Timeout = time.Duration(i.Timeout / time.Second)
	out := a.CmdV2(opts)
	if out.Status.Exit != 0 {
		return "", fmt.Errorf("Error installing mesh agent: %s", out.Stderr)
	}
	fmt.Println(out.Stdout)
	return "", nil
}

func (a *Agent) installMacService() error {
	if err := os.MkdirAll(nixAgentBinDir, 0o755); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := copyFileAtomic(self, nixAgentBin, 0o755); err != nil {
		return fmt.Errorf("copy the agent to %s: %v", nixAgentBin, err)
	}
	if err := os.WriteFile(macPlistPath, []byte(macServicePlist(nixAgentBin)), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("launchctl", "bootstrap", "system", macPlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v %s", err, out)
	}
	return nil
}

// The service registers the self-healing job once it runs, as on Linux.
func (a *Agent) installFreeBSDService() error {
	if err := os.MkdirAll(nixAgentBinDir, 0o755); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self != nixMainBin {
		if err := os.MkdirAll(filepath.Dir(nixMainBin), 0o755); err != nil {
			return err
		}
		if err := copyFileAtomic(self, nixMainBin, 0o755); err != nil {
			return fmt.Errorf("copy the agent to %s: %v", nixMainBin, err)
		}
	}
	return newHealPlatform(a).ensureService(nixMainBin)
}

func (a *Agent) installWindowsService(i *Installer) {
	if err := os.MkdirAll(filepath.Join(a.ProgramDir, "bin"), 0o755); err != nil {
		a.Logger.Errorln("Install(): bin dir:", err)
	}
	a.SendSoftware()
	if err := createWinTempDir(); err != nil {
		a.Logger.Errorln("Install() createWinTempDir():", err)
	}
	// AUOptions 1: Windows Update leaves patching to the RMM
	if err := a.PatchMgmnt(true); err != nil {
		a.Logger.Errorln("Install() PatchMgmnt():", err)
	}
	if err := a.InstallService(); err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
		return
	}
	time.Sleep(time.Second)
	if r := a.ControlService(winSvcName, "start"); !r.OK {
		a.installerMsg(r.Reason, "error", i.Silent)
		return
	}
	if i.Power {
		DisableSleepHibernate()
	}
	if i.Ping {
		EnablePing()
	}
	if i.RDP {
		EnableRDP()
	}
}
