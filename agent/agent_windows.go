// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.riddix.de/RiDDiX/ulrmm-agent/internal/winapi"
	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/elastic/go-sysinfo"
	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/kardianos/service"
	nats "github.com/nats-io/nats.go"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// Security descriptors of the work directories: owner Administrators, no
// inheritance from ProgramData, SYSTEM and Administrators only. Users may
// read and run what lies in the run-as-user directory, nothing more.
const (
	adminsOnlySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	runAsUserSDDL  = adminsOnlySDDL + "(A;OICI;0x1200a9;;;BU)"
	serviceSDDL    = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
		"(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)(A;;CCLCSWLORC;;;AU)"
)

// detachedFlags start a process that outlives the agent and gets no console.
const detachedFlags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP

func (a *Agent) Start(_ service.Service) error {
	go a.RunRPC()
	return nil
}

// Service-manager stop. A stop the agent did not announce is reported at the
// next start.
func (a *Agent) Stop(_ service.Service) error {
	recordStop(a.dataDir(), time.Now())
	return nil
}

// No-op: Stop sees every stop.
func (a *Agent) watchStop(*nats.Conn) {}

// the installer replaces the files itself; no rollback copy here
func (a *Agent) armRevert() func() { return func() {} }

// the selfheal download is the signed installer, which checks itself
func (a *Agent) selfHealCheck(string, string) error { return nil }

// Setup calls -m installsvc after copying the files, which on a new install
// is before the configuration exists: that call does nothing.
func (a *Agent) InstallService() error {
	if serviceExists(winSvcName) {
		return nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	k.Close()
	s, err := service.New(a, a.ServiceConfig)
	if err != nil {
		return err
	}
	return s.Install()
}

// Recovery actions, and a DACL that lets standard users query the service but
// not stop, reconfigure or delete it.
func protectService() error {
	return withService(winSvcName, windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_START|windows.WRITE_DAC|windows.READ_CONTROL, func(s *mgr.Service) error {
		restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 12 * time.Second}
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
			return err
		}
		sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
		if err != nil {
			return err
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		return windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	})
}

func statusOrMissing(name string) string {
	st, err := GetServiceStatus(name)
	if err != nil {
		return "Not Installed"
	}
	return st
}

// No arguments: a message box when double-clicked, three lines on the console
// otherwise.
func ShowStatus(version string) {
	agentState := statusOrMissing(winSvcName)
	meshState := statusOrMissing(meshSvcName)
	if windows.GetForegroundWindow() == 0 {
		fmt.Println(BrandProductName, "Version", version)
		fmt.Printf("%s: %s\n", BrandAgentName, agentState)
		fmt.Printf("Mesh Agent: %s\n", meshState)
		return
	}
	if con := getConsoleWindow(); con != 0 {
		var pid uint32
		if _, err := windows.GetWindowThreadProcessId(con, &pid); err == nil && int(pid) == os.Getpid() {
			showWindow(con, windows.SW_HIDE)
		}
	}
	text := fmt.Sprintf("Agent: %s\n\nMesh Agent: %s", agentState, meshState)
	messageBox(text, fmt.Sprintf("%s v%s", BrandProductName, version), windows.MB_OK|windows.MB_ICONINFORMATION)
}

// PlatVer is the feature release, for example 24H2 (older builds: 2009).
func PlatVer() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "n/a", err
	}
	defer k.Close()
	if v, _, err := k.GetStringValue("DisplayVersion"); err == nil {
		return v, nil
	}
	v, _, err := k.GetStringValue("ReleaseId")
	if err != nil {
		return "n/a", err
	}
	return v, nil
}

func (a *Agent) osString() string {
	h, err := sysinfo.Host()
	if err != nil || h.Info().OS == nil {
		a.Logger.Debugln("osString():", err)
		return "error getting host info"
	}
	info := h.Info()
	ver, err := PlatVer()
	if err != nil {
		ver = ""
	}
	return formatWinOS(info.OS.Name, winOSArch(info.Architecture), ver, info.OS.Build)
}

// First user with a console or remote desktop session, without domain; "None"
// when nobody is signed in.
func (a *Agent) LoggedOnUser() string {
	names, err := sessionUserNames()
	if err != nil {
		a.Logger.Debugln("LoggedOnUser():", err)
	}
	return pickLoggedOnUser(names, err == nil, func() []string {
		users, err := winapi.ListLoggedInUsers()
		if err != nil {
			a.Logger.Debugln("LoggedOnUser() logon sessions:", err)
			return nil
		}
		ret := make([]string, 0, len(users))
		for _, u := range users {
			ret = append(ret, u.Username)
		}
		return ret
	})
}

// Local fixed drives.
func (a *Agent) GetDisks() []rmm.DiskUsage {
	ret := []rmm.DiskUsage{}
	parts, err := disk.Partitions(false)
	if err != nil {
		a.Logger.Debugln("GetDisks():", err)
		return ret
	}
	for _, p := range parts {
		root := p.Mountpoint
		if !strings.HasSuffix(root, `\`) {
			root += `\`
		}
		r, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(r) != windows.DRIVE_FIXED {
			continue
		}
		u, err := disk.Usage(p.Mountpoint)
		if err != nil {
			a.Logger.Debugln("GetDisks():", p.Mountpoint, err)
			continue
		}
		ret = append(ret, rmm.DiskUsage{
			Dev:       p.Device,
			FSType:    p.Fstype,
			TotalText: ByteCountSI(u.Total),
			UsedText:  ByteCountSI(u.Used),
			FreeText:  ByteCountSI(u.Free),
			UsedPct:   int(u.UsedPercent),
		})
	}
	return ret
}

// SystemRebootRequired: Windows Update flags a pending restart with a key.
func (a *Agent) SystemRebootRequired() (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	k.Close()
	return true, nil
}

// A -m runchecks or -m checkrunner process of this agent.
func (a *Agent) ChecksRunning() bool {
	procs, err := process.Processes()
	if err != nil {
		return false
	}
	self := int32(os.Getpid())
	for _, p := range procs {
		if p.Pid == self {
			continue
		}
		exe, err := p.Exe()
		if err != nil || !strings.EqualFold(exe, a.EXE) {
			continue
		}
		args, err := p.CmdlineSlice()
		if err == nil && isChecksRun(exe, args, a.EXE) {
			return true
		}
	}
	return false
}

// CheckIn* overrides from the agent key.
func (a *Agent) GetAgentCheckInConfig(c AgentCheckInConfig) AgentCheckInConfig {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return c
	}
	defer k.Close()
	return applyCheckInOverrides(c, func(name string) string {
		v, _, _ := k.GetStringValue(name)
		return v
	})
}

// PatchMgmnt with true sets AUOptions 1: Windows Update downloads nothing
// on its own and the RMM does the patching. false gives it back.
func (a *Agent) PatchMgmnt(enable bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	var v uint32
	if enable {
		v = 1
	}
	if err := k.SetDWordValue("AUOptions", v); err != nil {
		return err
	}
	if isHomeEdition() {
		if err := pauseConsumerUpdates(enable); err != nil {
			return err
		}
	}
	// remembered for the daily re-arm; the key is already gone at uninstall
	ak, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer ak.Close()
	return ak.SetDWordValue("PatchMgmt", v)
}

// Home editions do not honour the AU policy; the pause switch of the
// Settings app holds them for 35 days.
func pauseConsumerUpdates(enable bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	start, end := pauseWindow(time.Now())
	values := map[string]string{
		"PauseUpdatesStartTime":        start,
		"PauseFeatureUpdatesStartTime": start,
		"PauseQualityUpdatesStartTime": start,
		"PauseUpdatesExpiryTime":       end,
		"PauseFeatureUpdatesEndTime":   end,
		"PauseQualityUpdatesEndTime":   end,
	}
	for name, v := range values {
		if enable {
			err = k.SetStringValue(name, v)
		} else if err = k.DeleteValue(name); errors.Is(err, registry.ErrNotExist) {
			err = nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func isHomeEdition() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer k.Close()
	id, _, _ := k.GetStringValue("EditionID")
	return homeEdition(id)
}

// rearmPatchMgmt renews the Home pause while patch management is on.
func (a *Agent) rearmPatchMgmt() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if on, _, _ := k.GetIntegerValue("PatchMgmt"); on != 1 {
		return
	}
	if err := a.PatchMgmnt(true); err != nil {
		a.Logger.Debugln("rearmPatchMgmt():", err)
	}
}

func (a *Agent) SendSoftware() {
	payload := map[string]interface{}{"agent_id": a.AgentID, "software": a.GetInstalledSoftware()}
	if _, err := a.rClient.R().SetBody(payload).Post("/api/v3/software/"); err != nil {
		a.Logger.Debugln("SendSoftware():", err)
	}
}

// Caller has initialised COM and releases the IDispatch.
func NewCOMObject(progID string) (*ole.IDispatch, error) {
	unk, err := oleutil.CreateObject(progID)
	if err != nil {
		return nil, err
	}
	defer unk.Release()
	return unk.QueryInterface(ole.IID_IDispatch)
}

// Script directory and the run-as-user directory, registry overrides applied.
func winWorkDirs() (work, runAs string) {
	cfg := NewAgentConfig()
	work, runAs = defaultWinTmpDir, defaultWinRunAsUserTmpDir
	if cfg.WinTemp != "" {
		work = cfg.WinTemp
	}
	if cfg.WinUserTemp != "" {
		runAs = cfg.WinUserTemp
	}
	return work, runAs
}

// Both work directories exist, and only SYSTEM and Administrators can change
// what is in them. Runs at install, every service start and before every script.
func createWinTempDir() error {
	work, runAs := winWorkDirs()
	for _, d := range []struct{ path, sddl string }{{work, adminsOnlySDDL}, {runAs, runAsUserSDDL}} {
		if err := os.MkdirAll(d.path, 0o755); err != nil {
			return err
		}
		if err := setPathSecurity(d.path, d.sddl); err != nil {
			return fmt.Errorf("%s: %w", d.path, err)
		}
	}
	return nil
}

// SYSTEM and Administrators only.
func RestrictToAdmins(path string) error {
	return setPathSecurity(path, adminsOnlySDDL)
}

func setPathSecurity(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

// Outlives this process. The installer that replaces it uses this.
func startDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedFlags, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// The installer stops the service, replaces the files and starts it again.
func (a *Agent) AgentUpdate(url, inno, version, sha string) error {
	if err := checkUpdateRequest(url, inno, version, sha); err != nil {
		return err
	}
	// spread a fleet-wide update over a few seconds
	time.Sleep(time.Duration(randRange(1, 16)) * time.Second)
	a.KillHungUpdates()
	time.Sleep(time.Second)
	a.CleanupAgentUpdates()

	// the installer cannot be probed before it installs: the running
	// build's selftest at least proves the identity still reaches the RMM
	if _, err := a.SelfTest(15 * time.Second); err != nil {
		err = fmt.Errorf("selftest before the installer: %w", err)
		if errors.Is(err, ErrTransient) {
			return err
		}
		return badDownload{err}
	}
	updater := filepath.Join(a.WinTmpDir, inno)
	a.Logger.Infof("Agent updating from %s to %s", a.Version, version)
	// the installer runs as SYSTEM: never from a directory others can write
	if err := createWinTempDir(); err != nil {
		return fmt.Errorf("work directory: %w", err)
	}
	if err := a.fetchFile(url, updater, sha, 15*time.Minute); err != nil {
		return fmt.Errorf("download %s: %w", inno, err)
	}
	expectStop(a.dataDir())
	logFile := filepath.Join(a.WinTmpDir, updateLogName(version))
	if err := startDetached(updater, "/VERYSILENT", "/LOG="+logFile); err != nil {
		clearExpectedStop(a.dataDir())
		return fmt.Errorf("start %s: %w", inno, err)
	}
	time.Sleep(time.Second)
	return nil
}

// The code in the request is not used: the uninstaller checks the one stored here.
func (a *Agent) AgentUninstall(_ string) {
	code, err := storedUninstallCode()
	if err != nil {
		a.Logger.Errorln("AgentUninstall():", err)
	}
	if err := a.runUninstaller(code); err != nil {
		a.Logger.Errorln("AgentUninstall():", err)
	}
}

// -m uninstall, after the code was checked.
func (a *Agent) uninstallLocal() error {
	code, err := storedUninstallCode()
	if err != nil {
		return err
	}
	return a.runUninstaller(code)
}

// The setup's uninstaller refuses without the right code.
func (a *Agent) runUninstaller(code string) error {
	a.KillHungUpdates()
	args := []string{"/VERYSILENT"}
	if code != "" {
		args = append(args, "/UNINSTALLCODE="+code)
	}
	return startDetached(filepath.Join(a.ProgramDir, a.GetUninstallExe()), args...)
}

// -m cleanup, run by the uninstaller before it deletes the program directory.
func (a *Agent) UninstallCleanup() {
	work, runAs := a.WinTmpDir, a.WinRunAsUserTmpDir
	if err := deleteKEKStore(); err != nil {
		a.Logger.Debugln("UninstallCleanup(): key store:", err)
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, agentKeyPath); err != nil {
		a.Logger.Debugln("UninstallCleanup(): agent key:", err)
	}
	if err := a.PatchMgmnt(false); err != nil {
		a.Logger.Debugln("UninstallCleanup() PatchMgmnt():", err)
	}
	// the service is stopped; keepawake.json goes with the program directory
	if err := ReleaseKeepAwakeFile(); err != nil {
		a.Logger.Debugln("UninstallCleanup(): keep awake:", err)
	}
	a.CleanupAgentUpdates()
	CleanupSchedTasks()
	if err := newHealPlatform(a).removeSchedule(); err != nil {
		a.Logger.Debugln("UninstallCleanup(): self-heal task:", err)
	}
	// the default directory belongs to the agent; one an administrator set
	// may be shared and goes only when it is empty
	_ = os.RemoveAll(defaultWinTmpDir)
	for _, d := range []string{runAs, work} {
		if d != "" && d != defaultWinTmpDir && d != defaultWinRunAsUserTmpDir {
			_ = os.Remove(d)
		}
	}
}

func (a *Agent) RunMigrations() {
	for _, d := range []string{"py38-x64", "py38-x32"} {
		p := filepath.Join(a.ProgramDir, d)
		if _, err := os.Stat(p); err == nil {
			_ = os.RemoveAll(p)
		}
	}
	for _, f := range []string{"nssm.exe", "nssm-x86.exe"} {
		p := filepath.Join(a.ProgramDir, f)
		if rmm.FileExists(p) {
			_ = os.Remove(p)
		}
	}
}

// Waits until the new mesh agent reports its node id, at most meshIDWait.
func (a *Agent) installMesh(meshInstaller, meshExe, proxy string) (string, error) {
	out, err := CMD(meshInstaller, meshInstallArgs(proxy), 90, false)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(out[0])
	}
	time.Sleep(5 * time.Second)

	deadline := time.Now().Add(meshIDWait)
	for {
		out, err := CMD(meshExe, []string{"-nodeid"}, 30, false)
		id := StripAll(out[0])
		if err == nil && out[1] == "" && meshNodeIDUsable(id) {
			return id, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the mesh agent reported no node id within %v", meshIDWait)
		}
		a.Logger.Debugln("installMesh(): waiting for the mesh node id")
		time.Sleep(5 * time.Second)
	}
}

const meshIDWait = 5 * time.Minute

func (a *Agent) getMeshNodeID() (string, error) {
	out, err := CMD(a.MeshSystemEXE, []string{"-nodeid"}, 10, false)
	if err != nil {
		return "", err
	}
	if s := StripAll(out[1]); s != "" {
		return "", errors.New(s)
	}
	id := StripAll(out[0])
	if !meshNodeIDUsable(id) {
		return "", errors.New("failed to get mesh node id")
	}
	return id, nil
}

// -m nixmeshnodeid; posix agents only.
func (a *Agent) NixMeshNodeID() string { return "not implemented" }

// Reinstalls the mesh agent from the RMM and reports its node id again.
func (a *Agent) RecoverMesh() {
	a.Logger.Infoln("Attempting mesh recovery")
	if _, err := CMD("net", []string{"stop", meshSvcName}, 60, false); err != nil {
		a.Logger.Debugln("RecoverMesh(): net stop:", err)
	}
	a.ForceKillMesh()
	a.ReinstallMesh()
	if _, err := CMD("net", []string{"start", meshSvcName}, 60, false); err != nil {
		a.Logger.Debugln("RecoverMesh(): net start:", err)
	}
	a.SyncMeshNodeID(true)
}

// the service start and the installpython RPC share PyBaseDir.new/.old
var pythonMu sync.Mutex

// Bundled Python the checks and some scripts use.
func (a *Agent) GetPython(force bool) {
	pythonMu.Lock()
	defer pythonMu.Unlock()
	if rmm.FileExists(a.PyBin) && !force {
		return
	}
	if err := createWinTempDir(); err != nil {
		a.Logger.Errorln("GetPython():", err)
		return
	}
	runtimeInstallDelay()
	// the old python directory stays until a complete new one is unpacked
	tmp, err := os.MkdirTemp(a.WinTmpDir, "pytemp")
	if err != nil {
		a.Logger.Errorln("GetPython():", err)
		return
	}
	defer os.RemoveAll(tmp)
	zipName := a.PyDir + ".zip"
	zipPath := filepath.Join(tmp, zipName)
	if err := a.runtimeDownload(pythonZipURL(BrandPyURL, a.BaseURL, zipName), zipPath); err != nil {
		a.Logger.Errorln("GetPython(): download:", err)
		return
	}
	if err := checkPyZip(zipPath, zipName); err != nil {
		a.Logger.Errorln("GetPython():", err)
		return
	}
	newDir, oldDir := a.PyBaseDir+".new", a.PyBaseDir+".old"
	_ = os.RemoveAll(newDir)
	_ = os.RemoveAll(oldDir)
	if err := Unzip(zipPath, newDir); err != nil {
		_ = os.RemoveAll(newDir)
		a.Logger.Errorln("GetPython(): unzip:", err)
		return
	}
	// renaming fails as a whole while python runs; RemoveAll could leave half an install
	if err := os.Rename(a.PyBaseDir, oldDir); err != nil && !os.IsNotExist(err) {
		_ = os.RemoveAll(newDir)
		a.Logger.Errorln("GetPython():", err)
		return
	}
	if err := os.Rename(newDir, a.PyBaseDir); err != nil {
		_ = os.Rename(oldDir, a.PyBaseDir)
		_ = os.RemoveAll(newDir)
		a.Logger.Errorln("GetPython():", err)
		return
	}
	_ = os.RemoveAll(oldDir)
}

func (a *Agent) InstallNushell(force bool) {
	runtimeInstallDelay()
	conf := a.GetAgentCheckInConfig(a.GetCheckInConfFromAPI())
	if !conf.InstallNushell {
		return
	}
	rt := scriptRuntime{
		name:       "nushell",
		bin:        a.NuBin,
		customURL:  conf.InstallNushellUrl,
		version:    conf.InstallNushellVersion,
		sha256:     conf.InstallNushellSha256,
		releaseURL: winNushellRelease(runtime.GOARCH, conf.InstallNushellVersion),
		unpack:     unzipFind("nu.exe"),
		tmpBase:    a.WinTmpDir,
	}
	if conf.NushellEnableConfig {
		rt.prepare = func() error { return createNushellConfigIn(filepath.Join(a.ProgramDir, "etc", "nushell")) }
	}
	if err := a.installRuntime(rt, force); err != nil {
		a.Logger.Errorln("InstallNushell():", err)
	}
}

func (a *Agent) InstallDeno(force bool) {
	runtimeInstallDelay()
	conf := a.GetAgentCheckInConfig(a.GetCheckInConfFromAPI())
	if !conf.InstallDeno {
		return
	}
	rt := scriptRuntime{
		name:       "deno",
		bin:        a.DenoBin,
		customURL:  conf.InstallDenoUrl,
		version:    conf.InstallDenoVersion,
		sha256:     conf.InstallDenoSha256,
		releaseURL: winDenoRelease(runtime.GOARCH, conf.InstallDenoVersion),
		unpack:     unzipFind("deno.exe"),
		tmpBase:    a.WinTmpDir,
	}
	if err := a.installRuntime(rt, force); err != nil {
		a.Logger.Errorln("InstallDeno():", err)
	}
}

func unzipFind(name string) func(archive, dir string) (string, error) {
	return func(archive, dir string) (string, error) {
		if err := Unzip(archive, dir); err != nil {
			return "", err
		}
		return findFile(dir, name)
	}
}

// Empty config.nu and env.nu; existing files are kept.
func createNushellConfigIn(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"config.nu", "env.nu"} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY, 0o744)
		if err != nil {
			return err
		}
		f.Close()
	}
	return nil
}

// One HKLM DWORD; creates the key when needed.
func setDWord(path, name string, v uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, v)
}

// cmdLine goes to Windows as is, for tools that parse quotes themselves (netsh).
func runRaw(timeout time.Duration, exe, cmdLine string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine, HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func netshExe() string { return filepath.Join(os.Getenv("WINDIR"), "System32", "netsh.exe") }

func powercfgExe() string { return filepath.Join(os.Getenv("WINDIR"), "System32", "powercfg.exe") }

// Keeps the machine reachable: no fast startup, no sleep, hibernation or lid
// action on mains or battery.
func DisableSleepHibernate() {
	if err := setDWord(`SYSTEM\CurrentControlSet\Control\Session Manager\Power`, "HiberbootEnabled", 0); err != nil {
		fmt.Println("HiberbootEnabled:", err)
	}
	var wg sync.WaitGroup
	for _, src := range []string{"ac", "dc"} {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			for _, args := range powercfgSteps(src) {
				_, _ = healCmd(5*time.Second, powercfgExe(), args...)
			}
		}(src)
	}
	wg.Wait()
	_, _ = healCmd(5*time.Second, powercfgExe(), "-S", "SCHEME_CURRENT")
}

func EnableRDP() {
	if err := setDWord(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections", 0); err != nil {
		fmt.Println("fDenyTSConnections:", err)
	}
	// the group name is localized, its resource id is not
	if out, err := runRaw(10*time.Second, netshExe(), `netsh advfirewall firewall set rule group="@FirewallAPI.dll,-28752" new enable=Yes`); err != nil {
		fmt.Println("netsh:", err, strings.TrimSpace(out))
	}
}

const pingRuleName = "ICMP Allow incoming V4 echo request"

// Inbound ICMPv4 echo. An existing rule of that name is not added again.
func EnablePing() {
	if _, err := runRaw(10*time.Second, netshExe(), `netsh advfirewall firewall show rule name="`+pingRuleName+`"`); err == nil {
		return
	}
	cl := `netsh advfirewall firewall add rule name="` + pingRuleName + `" protocol=icmpv4:8,any dir=in action=allow`
	if out, err := runRaw(10*time.Second, netshExe(), cl); err != nil {
		fmt.Println("netsh:", err, strings.TrimSpace(out))
	}
}

// Every physical adapter wakes the machine on a magic packet.
const wakeOnLANScript = `foreach ($n in Get-NetAdapter -Physical) {
  try {
    $pm = Get-NetAdapterPowerManagement -Name $n.Name -ErrorAction Stop
    if ($pm.WakeOnMagicPacket -eq 'Disabled') {
      Set-NetAdapterPowerManagement -Name $n.Name -WakeOnMagicPacket Enabled -ErrorAction Stop
    }
  } catch { Write-Output ("{0}: {1}" -f $n.Name, $_) }
  powercfg.exe /deviceenablewake $n.InterfaceDescription | Out-Null
}`

// Arms wake on LAN, then sleeps (not hibernation). Returns after wake.
func (a *Agent) Suspend() error {
	out, err := healCmd(time.Minute, getPowershellExe(), "-NonInteractive", "-NoProfile", "-EncodedCommand", psEncoded(wakeOnLANScript))
	if err != nil || strings.TrimSpace(out) != "" {
		a.Logger.Debugln("Suspend(): wake on LAN:", err, strings.TrimSpace(out))
	}
	if err := enablePrivilege("SeShutdownPrivilege"); err != nil {
		return err
	}
	if r, _, e := procSetSuspendState.Call(0, 0, 0); r == 0 {
		return fmt.Errorf("SetSuspendState: %w", e)
	}
	return nil
}
