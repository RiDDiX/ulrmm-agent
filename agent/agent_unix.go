// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/elastic/go-sysinfo"
	"github.com/jaypipes/ghw"
	nats "github.com/nats-io/nats.go"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Linux, macOS and FreeBSD. Windows-only funcs answer with the stubs in stubs_unix.go.

// Scheduled tasks exist on Windows only; the server drives posix tasks with runtask.
type SchedTask struct {
	Name string `json:"name"`
}

// Paths the tests point elsewhere.
var (
	rebootRequiredFiles = []string{"/var/run/reboot-required", "/run/reboot-required"}
	needsRestartingBins = []string{"/usr/bin/needs-restarting", "/bin/needs-restarting"}
	cpuInfoPath         = "/proc/cpuinfo"
	meshRetryPause      = time.Second
)

// watchStop records who stopped the service: a stop the agent did not
// announce (systemctl stop, launchctl bootout, kill) is reported at the
// next start. A system shutdown the power watcher did not see is announced
// here.
func (a *Agent) watchStop(nc *nats.Conn) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
	// the probes cost seconds (log show on macOS), so they run only when
	// nothing precise went out; announcePower drops repeats
	if !a.powerAnnouncedPrecise() {
		if kind, by := classifyStop(); kind != "" {
			_ = a.announcePower(nc, kind, "os", by, 2*time.Second)
		}
	}
	recordStop(a.dataDir(), time.Now())
	os.Exit(0)
}

func (a *Agent) GetDisks() []rmm.DiskUsage {
	parts, err := disk.Partitions(false)
	if err != nil {
		a.Logger.Debugln("GetDisks():", err)
		return []rmm.DiskUsage{}
	}
	return a.diskList(parts, func(p string) (*disk.UsageStat, error) { return statBounded(p, statfsWait) })
}

func (a *Agent) diskList(parts []disk.PartitionStat, usage func(string) (*disk.UsageStat, error)) []rmm.DiskUsage {
	ret := []rmm.DiskUsage{}
	for _, p := range parts {
		if strings.Contains(p.Device, "dev/loop") || strings.Contains(p.Device, "devfs") {
			continue
		}
		// gopsutil lists every mount there, procfs and nullfs included
		if runtime.GOOS == "freebsd" && pseudoFS[p.Fstype] {
			continue
		}
		u, err := usage(p.Mountpoint)
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

// SystemRebootRequired: Debian flags a pending reboot with a file, the
// RHEL family answers through needs-restarting -r (exit 1). macOS reports
// it through the package script instead.
func (a *Agent) SystemRebootRequired() (bool, error) {
	switch runtime.GOOS {
	case "darwin":
		return false, nil
	case "freebsd":
		// freebsd-update installed a kernel that is not running yet
		k, err1 := healCmd(10*time.Second, "freebsd-version", "-k")
		r, err2 := healCmd(10*time.Second, "freebsd-version", "-r")
		return err1 == nil && err2 == nil && strings.TrimSpace(k) != strings.TrimSpace(r), nil
	}
	for _, f := range rebootRequiredFiles {
		if rmm.FileExists(f) {
			return true, nil
		}
	}
	for _, bin := range needsRestartingBins {
		if !rmm.FileExists(bin) {
			continue
		}
		opts := a.NewCMDOpts()
		opts.IsScript = true
		opts.Shell = bin
		opts.Args = []string{"-r"}
		out := a.CmdV2(opts)
		if out.Status.Error != nil {
			continue
		}
		return out.Status.Exit == 1, nil
	}
	return false, nil
}

// First user with a login session, "None" when there is none (as on Windows).
func (a *Agent) LoggedOnUser() string {
	if u := firstLoginUser(false); u != "" {
		return u
	}
	return noUser
}

// firstLoginUser: with noRoot, root's sessions (su, ssh) are passed over.
func firstLoginUser(noRoot bool) string {
	users, err := host.Users()
	if err != nil {
		return ""
	}
	return pickLoginUser(users, noRoot)
}

func pickLoginUser(users []host.UserStat, noRoot bool) string {
	for _, u := range users {
		if u.User != "" && !(noRoot && u.User == "root") {
			return u.User
		}
	}
	return ""
}

var (
	errNobodyLoggedIn = errors.New("run as user: nobody is logged in on this computer")
	errRunAsRoot      = errors.New("run as user: the logged in user is root")
)

// run_as_user: the console user (macOS: owner of /dev/console, Linux: the
// active session of seat0), else the first user with a login session (FreeBSD).
func sessionUser() string {
	if runtime.GOOS == "darwin" {
		if st, err := os.Stat("/dev/console"); err == nil {
			if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Uid != 0 {
				if u, err := user.LookupId(strconv.FormatUint(uint64(s.Uid), 10)); err == nil {
					return u.Username
				}
			}
		}
	} else if runtime.GOOS == "linux" {
		if id, err := healCmd(10*time.Second, "loginctl", "show-seat", "seat0", "-p", "ActiveSession", "--value"); err == nil && strings.TrimSpace(id) != "" {
			name, err := healCmd(10*time.Second, "loginctl", "show-session", strings.TrimSpace(id), "-p", "Name", "--value")
			if name = strings.TrimSpace(name); err == nil && name != "" {
				return name
			}
		}
	}
	return firstLoginUser(true)
}

func sessionRunAs() (*runAs, error) {
	name := sessionUser()
	if name == "" {
		return nil, errNobodyLoggedIn
	}
	return lookupRunAs(name)
}

func lookupRunAs(name string) (*runAs, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("run as user: unknown user %s", name)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("run as user: no numeric ids for %s", name)
	}
	// run as user must never mean root (a root console session, toor)
	if uid == 0 {
		return nil, errRunAsRoot
	}
	r := &runAs{name: u.Username, uid: uint32(uid), gid: uint32(gid), home: u.HomeDir}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				r.groups = append(r.groups, uint32(n))
			}
		}
	}
	return r, nil
}

func (a *Agent) osString() string {
	h, err := host.Info()
	if err != nil {
		return "error getting host info"
	}
	switch {
	case onTrueNAS:
		return fmt.Sprintf("TrueNAS %s %s %s", trueNASVersion(), h.KernelArch, h.KernelVersion)
	case runtime.GOOS == "freebsd":
		// gopsutil lowercases the release; freebsd-version -u is the userland
		rel, _ := healCmd(10*time.Second, "uname", "-r")
		user, err := healCmd(10*time.Second, "freebsd-version", "-u")
		if err != nil {
			user = rel
		}
		return fmt.Sprintf("FreeBSD %s %s %s", strings.TrimSpace(user), h.KernelArch, strings.TrimSpace(rel))
	}
	return formatOS(h.Platform, h.PlatformVersion, h.KernelArch, h.KernelVersion)
}

// TrueNAS SCALE: the POSTINIT task the agent and the server's install script
// register (selfheal_linux.go)
func trueNASInitCommand() string {
	return filepath.Join(nixAgentDir, "selfheal", IdentNixBin) + " -m selfheal"
}

// the mesh unit the server's install script writes there; /lib is read-only
func trueNASMeshUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Mesh Agent

[Service]
WorkingDirectory=%s
ExecStart=%s
StandardOutput=null
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, nixMeshDir, nixMeshAgentBin)
}

// TrueNAS keeps its version in the middleware manifest
func trueNASVersion() string {
	var m struct {
		Version string `json:"version"`
	}
	_ = readJSON(trueNASManifest, &m)
	return clip(m.Version, 64)
}

// ownDir: a directory of this process's user, not a link someone else planted
func ownDir(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not a directory owned by this user", p)
	}
	return nil
}

// go-sysinfo has no FreeBSD provider
func hostIPs() []string {
	if h, err := sysinfo.Host(); err == nil {
		return h.Info().IPs
	}
	var ret []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ret = append(ret, a.String())
		}
	}
	return ret
}

func formatOS(platform, version, arch, kernel string) string {
	return fmt.Sprintf("%s %s %s %s", cases.Title(language.AmericanEnglish).String(platform), version, arch, kernel)
}

// Hardware part of agent-wmi. A source that fails leaves its key at the empty value.
func (a *Agent) GetWMIInfo() map[string]interface{} {
	localIPs := filterLocalIPs(hostIPs())
	cpus := []string{}
	if ci, err := cpu.Info(); err == nil && len(ci) > 0 {
		cpus = append(cpus, ci[0].ModelName)
	}

	disks, gpus := []string{}, []string{}
	makeModel, serial := "", "n/a"
	switch runtime.GOOS {
	case "linux":
		disks, gpus = a.ghwDisks(), a.ghwGPUs()
		if c, err := ghw.Chassis(ghw.WithDisableWarnings()); err == nil && (c.Vendor != "" || c.Version != "") {
			makeModel = c.Vendor + " " + c.Version
		}
		if b, err := ghw.Baseboard(ghw.WithDisableWarnings()); err == nil {
			serial = b.SerialNumber
		}
	case "darwin":
		if out, err := healCmd(time.Minute, "sysctl", "-n", "hw.model"); err == nil {
			makeModel = strings.TrimSpace(strings.TrimPrefix(out, "hw.model: "))
		}
		if out, err := healCmd(time.Minute, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
			if s := ioregSerial(out); s != "" {
				serial = s
			}
		}
	case "freebsd":
		kenv := func(k string) string {
			out, _ := healCmd(time.Minute, "kenv", "-q", k)
			return strings.TrimSpace(out)
		}
		makeModel = strings.TrimSpace(kenv("smbios.system.maker") + " " + kenv("smbios.system.product"))
		if s := kenv("smbios.system.serial"); s != "" {
			serial = s
		}
		if out, err := healCmd(time.Minute, "geom", "disk", "list"); err == nil {
			disks = parseGeomDisks(out)
		}
		if out, err := healCmd(time.Minute, "pciconf", "-lv"); err == nil {
			gpus = parsePciconfGPUs(out)
		}
	}

	pi := ""
	if strings.Contains(runtime.GOARCH, "arm") {
		b, _ := os.ReadFile(cpuInfoPath)
		pi = raspberryModel(string(b))
		if makeModel == "" || makeModel == "unknown unknown" {
			makeModel = pi
		}
	}
	if len(cpus) == 0 {
		cpus = []string{pi}
	}

	ret := map[string]interface{}{
		"local_ips":    localIPs,
		"nics":         withWoL(nics()),
		"health":       a.Health(),
		"disks":        disks,
		"cpus":         cpus,
		"make_model":   makeModel,
		"gpus":         gpuValue(gpus),
		"serialnumber": serial,
	}
	if onTrueNAS {
		ret["appliance"] = map[string]string{"name": "TrueNAS", "version": trueNASVersion()}
	}
	return ret
}

func filterLocalIPs(ips []string) []string {
	ret := []string{}
	for _, ip := range ips {
		pfx, err := netip.ParsePrefix(ip)
		addr := pfx.Addr()
		if err != nil {
			addr, err = netip.ParseAddr(ip)
		}
		if err != nil || !addr.IsLoopback() {
			ret = append(ret, ip)
		}
	}
	return ret
}

func (a *Agent) ghwDisks() []string {
	ret := []string{}
	b, err := ghw.Block(ghw.WithDisableWarnings())
	if err != nil {
		a.Logger.Debugln("ghw.Block():", err)
		return ret
	}
	for _, d := range b.Disks {
		if d.IsRemovable || strings.Contains(d.Name, "ram") || strings.Contains(d.Name, "loop") {
			continue
		}
		ret = append(ret, diskLine(d.Vendor, d.Model, d.StorageController.String(), d.DriveType.String(), d.Name, d.SizeBytes))
	}
	return ret
}

// diskLine drops the library's "unknown" placeholders; the spaces around
// them stay.
func diskLine(vendor, model, controller, driveType, name string, size uint64) string {
	s := strings.Join([]string{vendor, model, controller, driveType, name, ByteCountSI(size)}, " ")
	return strings.TrimSpace(strings.ReplaceAll(s, "unknown", ""))
}

func (a *Agent) ghwGPUs() []string {
	ret := []string{}
	g, err := ghw.GPU(ghw.WithDisableWarnings())
	if err != nil {
		a.Logger.Debugln("ghw.GPU():", err)
		return ret
	}
	for _, c := range g.GraphicsCards {
		d := c.DeviceInfo
		if d == nil || d.Vendor == nil || d.Product == nil {
			continue
		}
		ret = append(ret, d.Vendor.Name+" "+d.Product.Name)
	}
	return ret
}

// gpuValue: a lone "unknown unknown" card is sent as "", which the server
// shows as no graphics card.
func gpuValue(gpus []string) interface{} {
	if len(gpus) == 1 && gpus[0] == "unknown unknown" {
		return ""
	}
	return gpus
}

func raspberryModel(cpuinfo string) string {
	for _, line := range strings.Split(cpuinfo, "\n") {
		if !strings.Contains(strings.ToLower(line), "raspberry") {
			continue
		}
		if parts := strings.Split(line, ":"); len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

var ioregSerialRe = regexp.MustCompile(`"IOPlatformSerialNumber"\s*=\s*"([^"]*)"`)

func ioregSerial(out string) string {
	if m := ioregSerialRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// scriptEnv keeps the KEY=VALUE entries with a usable name the server would
// accept too.
func (a *Agent) scriptEnv(vars []string) []string {
	ret := make([]string, 0, len(vars))
	for _, v := range vars {
		if envNameRe.MatchString(v) {
			ret = append(ret, v)
		} else {
			a.Logger.Debugln("RunScript(): dropped an environment entry without a valid name")
		}
	}
	return a.dropDeniedEnv(ret)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (a *Agent) nuBin() string   { return orDefault(a.NuBin, nixAgentBinDir+"/nu") }
func (a *Agent) denoBin() string { return orDefault(a.DenoBin, nixAgentBinDir+"/deno") }

// Script goes in the agent's tmp dir (or tmpdir) and runs as root, or with
// runAsUser as the signed-in user. Nushell and deno go to their runtime,
// anything else is started directly and needs a shebang. The script, its
// arguments and its output are not logged.
func (a *Agent) RunScript(code, shell string, args []string, timeout int, runAsUser bool, envVars []string, nushellEnableConfig bool, denoDefaultPermissions string) (stdout, stderr string, exitcode int, e error) {
	fail := func(err error) (string, string, int, error) { return "", err.Error(), 85, err }

	var ru *runAs
	if runAsUser {
		var err error
		if ru, err = sessionRunAs(); err != nil {
			return fail(err)
		}
	}
	f, err := createNixTmpFile(a.UnixTmpDir, shell)
	if err != nil {
		return fail(err)
	}
	script := f.Name()
	defer os.Remove(script)
	_, err = f.WriteString(removeWinNewLines(code))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(script, 0o770)
	}
	if err == nil && ru != nil {
		err = os.Chown(script, int(ru.uid), int(ru.gid))
	}
	if err != nil {
		return fail(err)
	}

	env := envVars
	opts := a.NewCMDOpts()
	opts.RunAsUser, opts.user = runAsUser, ru
	opts.IsScript = true
	opts.Timeout = time.Duration(positiveTimeout(timeout))
	switch shell {
	case "nushell", "deno":
		bin := a.nuBin()
		if shell == "deno" {
			bin = a.denoBin()
		}
		if !rmm.FileExists(bin) {
			a.Logger.Errorln("RunScript():", shell, "is not installed at", bin)
			return fail(fmt.Errorf("File Not Found: %s", bin))
		}
		opts.Shell = bin
		if shell == "nushell" {
			if nushellEnableConfig {
				dir := filepath.Join(nixAgentEtcDir, "nushell")
				opts.Args = []string{"--config", filepath.Join(dir, "config.nu"), "--env-config", filepath.Join(dir, "env.nu")}
			} else {
				opts.Args = []string{"--no-config-file"}
			}
		} else {
			var perms []string
			env, perms = denoPermissions(env, denoDefaultPermissions)
			opts.Args = append([]string{"run", "--no-prompt"}, perms...)
		}
		opts.Args = append(append(opts.Args, script), args...)
	default:
		opts.Shell = script
		opts.Args = args
	}
	opts.EnvVars = a.scriptEnv(env)
	a.Logger.Debugln("RunScript(): interpreter", opts.Shell)

	out := a.CmdV2(opts)
	stderr = out.Stderr
	if out.Status.Error != nil {
		stderr = CleanString(out.Status.Error.Error()) + "\n" + stderr
	}
	return out.Stdout, stderr, out.Status.Exit, nil
}

// Replaces the running binary with the build at url and restarts the service.
// The download is checked (hash, executable format, it must run and report
// version) before it takes the place of the old binary.
func (a *Agent) AgentUpdate(url, inno, version, sha string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(self), "."+IdentArtifact+"-update-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)

	a.Logger.Infof("Agent updating from %s to %s", a.Version, version)
	if err := a.fetchFile(url, tmp, sha, 15*time.Minute); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := a.checkAgentBinary(tmp, runtime.GOOS, runtime.GOARCH, version); err != nil {
		return err
	}
	if err := a.probeAgentBinary(tmp); err != nil {
		return err
	}

	prev := rollbackCopy
	if err := copyFileAtomic(self, prev, 0o700); err != nil {
		a.Logger.Debugln("AgentUpdate(): no rollback copy:", err)
		prev = ""
	}
	if err := os.Rename(tmp, self); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		if out, err := healCmd(time.Minute, "getenforce"); err == nil && strings.Contains(out, "Enforcing") {
			out, err := healCmd(time.Minute, "restorecon", "-rv", self)
			a.Logger.Debugln("AgentUpdate(): restorecon:", strings.TrimSpace(out), err)
		}
	}

	expectStop(a.dataDir())
	if err := a.restartAgentService(); err != nil {
		clearExpectedStop(a.dataDir())
		if prev != "" {
			if rerr := copyFileAtomic(prev, self, 0o755); rerr != nil {
				a.Logger.Errorln("AgentUpdate(): rollback:", rerr)
			}
		}
		return err
	}
	return nil
}

// Restarts the unit from its own process group: the service manager stops
// this process on the way.
func (a *Agent) restartAgentService() error {
	var argv []string
	switch runtime.GOOS {
	case "linux":
		argv = []string{"systemctl", "restart", IdentNixSvc}
	case "darwin":
		argv = []string{"launchctl", "kickstart", "-k", "system/" + IdentMacPlistLabel}
	case "freebsd":
		// the rc script prints after the stop has ended this process: no
		// output pipe (SIGPIPE), stderr goes to a file
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return nixAction(ctx, "service", rcName(), "onerestart")
	default:
		return nil
	}
	opts := a.NewCMDOpts()
	opts.IsScript = true
	opts.Shell = argv[0]
	opts.Args = argv[1:]
	if out := a.CmdV2(opts); out.Status.Exit != 0 {
		return fmt.Errorf("%s: exit %d %s", strings.Join(argv, " "), out.Status.Exit, strings.TrimSpace(out.Stderr))
	}
	return nil
}

var elfMachine = map[string]elf.Machine{
	"amd64": elf.EM_X86_64,
	"386":   elf.EM_386,
	"arm64": elf.EM_AARCH64,
	"arm":   elf.EM_ARM,
}

var machoCPU = map[string]macho.Cpu{
	"amd64": macho.CpuAmd64,
	"arm64": macho.CpuArm64,
}

// Refuses a download that is not an agent for this system: an error page
// answered with 200 must not replace the binary.
func (a *Agent) checkAgentBinary(path, goos, goarch, version string) error {
	if err := checkExecFormat(path, goos, goarch); err != nil {
		return err
	}
	opts := a.NewCMDOpts()
	opts.IsScript = true
	opts.Shell = path
	opts.Args = []string{"-version"}
	opts.Timeout = 10
	out := a.CmdV2(opts)
	if out.Status.Error != nil || out.Status.Exit != 0 {
		return fmt.Errorf("the downloaded agent does not run: exit %d %v", out.Status.Exit, out.Status.Error)
	}
	first, _, _ := strings.Cut(out.Stdout, "\n")
	got := strings.TrimSpace(first[strings.LastIndex(first, ": ")+1:])
	if version != "" && got != version {
		return badDownload{fmt.Errorf("the downloaded agent is version %q, the server announced %q", got, version)}
	}
	return nil
}

// probeAgentBinary runs the download's -selftest: it has to open this
// host's config and identity and reach the RMM before it replaces the
// running build. A failure is badDownload unless the RMM was not reachable.
func (a *Agent) probeAgentBinary(path string) error {
	opts := a.NewCMDOpts()
	opts.IsScript = true
	opts.Shell = path
	opts.Args = []string{"-selftest"}
	opts.Timeout = 20
	out := a.CmdV2(opts)
	if out.Status.Error == nil && out.Status.Exit == 0 {
		return nil
	}
	err := fmt.Errorf("selftest of the downloaded agent failed: exit %d %v %s",
		out.Status.Exit, out.Status.Error, strings.TrimSpace(out.Stderr))
	// exit 2: the RMM was not reachable, no verdict on the build; the
	// next run tries again
	if out.Status.Error == nil && out.Status.Exit == 2 {
		a.Logger.Warnln("AgentUpdate():", err)
		return err
	}
	return badDownload{err}
}

// revertAfter is how long a freshly updated build gets to reach the
// server before the rollback copy comes back.
var revertAfter = 10 * time.Minute

// tests swap these: the target is the running binary
var (
	revertTarget  = os.Executable
	revertRestart = (*Agent).restartAgentService
)

// armRevert runs at service start. The rollback copy is there from an
// update until the new build has a NATS connection (keepNew removes it).
// The grace counts from this start, not from the swap: a suspended laptop
// or a VM from a snapshot must not revert the moment it comes back. Once
// the time is up without a connection, the previous build takes its place
// again and the service restarts. The returned func cancels the timer and
// drops the copy; it may be called more than once.
func (a *Agent) armRevert() func() {
	if _, err := os.Stat(rollbackCopy); err != nil {
		return func() {}
	}
	t := time.AfterFunc(revertAfter, func() {
		_, err := os.Stat(rollbackCopy)
		if !shouldRevert(a.natsUp.Load(), err == nil) {
			return
		}
		self, err := revertTarget()
		if err == nil {
			err = copyFileAtomic(rollbackCopy, self, 0o755)
		}
		if err != nil {
			a.Logger.Errorln("update: revert to the previous build:", err)
			return
		}
		_ = os.Remove(rollbackCopy)
		a.Logger.Errorf("update: %s did not reach the server within %v, reverted to the previous build", a.Version, revertAfter)
		a.queueSecurityEvent("update_reverted", a.Version+" did not reach the server within "+revertAfter.String())
		a.sendSecurityEvents()
		expectStop(a.dataDir())
		if err := revertRestart(a); err != nil {
			clearExpectedStop(a.dataDir())
			a.Logger.Errorln("update: restart after revert:", err)
		}
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			t.Stop()
			_ = os.Remove(rollbackCopy)
		})
	}
}

// selfHealCheck is what an update does with a download before it replaces
// the binary: format, version and the -selftest of the new build.
func (a *Agent) selfHealCheck(path, version string) error {
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	if err := a.checkAgentBinary(path, runtime.GOOS, runtime.GOARCH, version); err != nil {
		return err
	}
	return a.probeAgentBinary(path)
}

func checkExecFormat(path, goos, goarch string) error {
	switch goos {
	case "linux", "freebsd":
		f, err := elf.Open(path)
		if err != nil {
			return errors.New("the download is not an ELF executable")
		}
		defer f.Close()
		if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
			return errors.New("the download is not an ELF executable")
		}
		if want, ok := elfMachine[goarch]; ok && f.Machine != want {
			return fmt.Errorf("the download is built for %v, not %s", f.Machine, goarch)
		}
		// Go marks FreeBSD builds in the ELF header, Linux builds stay SYSV
		if (f.OSABI == elf.ELFOSABI_FREEBSD) != (goos == "freebsd") {
			return fmt.Errorf("the download is built for another system (ELF OS ABI %v), not %s", f.OSABI, goos)
		}
	case "darwin":
		var cpus []macho.Cpu
		if fat, err := macho.OpenFat(path); err == nil {
			for _, arch := range fat.Arches {
				cpus = append(cpus, arch.Cpu)
			}
			fat.Close()
		} else if f, err := macho.Open(path); err == nil {
			cpus = append(cpus, f.Cpu)
			f.Close()
		} else {
			return errors.New("the download is not a Mach-O executable")
		}
		want, ok := machoCPU[goarch]
		for _, c := range cpus {
			if !ok || c == want {
				return nil
			}
		}
		return fmt.Errorf("the download is not built for %s", goarch)
	}
	return nil
}

// Uninstall the server asks for. The script text the server sends is not run;
// a separate agent process does the local uninstall, so it survives the service
// stop it causes. Stopping the unit ends this process on the way.
func (a *Agent) AgentUninstall(_ string) {
	a.Logger.Infoln("Uninstall requested by the server")
	self, err := os.Executable()
	if err != nil {
		a.Logger.Errorln("AgentUninstall():", err)
		return
	}
	code, err := storedUninstallCode()
	if err != nil {
		a.Logger.Errorln("AgentUninstall():", err)
	}
	var out bytes.Buffer
	cmd := exec.Command(self, "-m", "uninstall")
	cmd.Env = append(os.Environ(), "ULRMM_UNINSTALL_CODE="+code)
	cmd.Stdout, cmd.Stderr = &out, &out
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		a.Logger.Errorln("AgentUninstall():", err)
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			a.Logger.Errorln("AgentUninstall():", err, strings.TrimSpace(out.String()))
		}
	case <-time.After(10 * time.Minute):
		a.Logger.Errorln("AgentUninstall(): the uninstall is still running, leaving it")
	}
}

func (a *Agent) getMeshNodeID() (string, error) { return a.NixMeshNodeID(), nil }

// Asks the mesh agent for its node id. Right after an install it may not
// answer yet, or print a desktop warning instead.
func (a *Agent) NixMeshNodeID() string {
	if !rmm.FileExists(a.MeshSystemEXE) {
		a.Logger.Debugln("NixMeshNodeID(): no mesh agent at", a.MeshSystemEXE)
		return ""
	}
	for i := 0; i < 10; i++ {
		out := a.CmdV2(&CmdOptions{Shell: a.MeshSystemEXE, Command: "-nodeid", IsExecutable: true, Timeout: 10})
		if meshNodeIDReady(out.Stdout) {
			return out.Stdout
		}
		a.Logger.Debugln("NixMeshNodeID(): mesh agent not ready, attempt", i+1)
		time.Sleep(meshRetryPause)
	}
	return "error getting meshnodeid"
}

func meshNodeIDReady(out string) bool {
	l := strings.ToLower(out)
	return out != "" && !strings.Contains(l, "graphical version") && !strings.Contains(l, "zenity")
}

func (a *Agent) RecoverMesh() {
	a.Logger.Infoln("Attempting mesh recovery")
	argv := []string{"systemctl", "restart", "meshagent.service"}
	switch runtime.GOOS {
	case "darwin":
		argv = []string{"launchctl", "kickstart", "-k", "system/meshagent"}
	case "freebsd":
		argv = []string{"service", "meshagent", "onerestart"}
	}
	if out, err := healCmd(time.Minute, argv[0], argv[1:]...); err != nil {
		a.Logger.Errorln("RecoverMesh():", err, strings.TrimSpace(out))
	}
	a.SyncMeshNodeID(true)
}

// Arms Wake-on-LAN where the system allows it, then sleeps.
func (a *Agent) Suspend() error {
	run := func(argv ...string) error {
		out, err := healCmd(time.Minute, argv[0], argv[1:]...)
		if err != nil {
			return fmt.Errorf("%s: %v %s", strings.Join(argv, " "), err, strings.TrimSpace(out))
		}
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		if err := run("pmset", "-a", "womp", "1"); err != nil {
			a.Logger.Debugln("Suspend():", err)
		}
		return run("pmset", "sleepnow")
	case "freebsd":
		// a nic without the capability takes the option silently
		for _, n := range nics() {
			if err := run("ifconfig", n.Name, "wol_magic"); err != nil {
				a.Logger.Debugln("Suspend():", err)
			}
		}
		return run("acpiconf", "-s", "3")
	}
	if _, err := exec.LookPath("ethtool"); err == nil {
		for _, n := range nics() {
			if err := run("ethtool", "-s", n.Name, "wol", "g"); err != nil {
				a.Logger.Debugln("Suspend():", err)
			}
		}
	}
	return run("systemctl", "suspend")
}

func nushellRelease(goos, goarch, ver string) string {
	triple := map[string]string{
		"darwin/arm64": "aarch64-apple-darwin",
		"linux/amd64":  "x86_64-unknown-linux-musl",
		"linux/arm64":  "aarch64-unknown-linux-musl",
	}[goos+"/"+goarch]
	if triple == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/nu-%s-%s.tar.gz", nuReleaseURL, ver, ver, triple)
}

func denoRelease(goos, goarch, ver string) string {
	triple := map[string]string{
		"darwin/arm64": "aarch64-apple-darwin",
		"darwin/amd64": "x86_64-apple-darwin",
		"linux/amd64":  "x86_64-unknown-linux-gnu",
	}[goos+"/"+goarch]
	if triple == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/deno-%s.zip", denoReleaseURL, ver, triple)
}

func (a *Agent) InstallNushell(force bool) {
	runtimeInstallDelay()
	conf := a.GetCheckInConfFromAPI()
	if !conf.InstallNushell {
		return
	}
	rt := scriptRuntime{
		name:       "nushell",
		bin:        a.nuBin(),
		customURL:  conf.InstallNushellUrl,
		version:    conf.InstallNushellVersion,
		sha256:     conf.InstallNushellSha256,
		releaseURL: nushellRelease(runtime.GOOS, runtime.GOARCH, conf.InstallNushellVersion),
		unpack: func(archive, dir string) (string, error) {
			root, err := a.ExtractTarGz(archive, dir)
			return filepath.Join(dir, root, "nu"), err
		},
	}
	if conf.NushellEnableConfig {
		rt.prepare = createNushellConfig
	}
	if err := a.installRuntime(rt, force); err != nil {
		a.Logger.Errorln("InstallNushell():", err)
	}
}

func (a *Agent) InstallDeno(force bool) {
	runtimeInstallDelay()
	conf := a.GetCheckInConfFromAPI()
	if !conf.InstallDeno {
		return
	}
	rt := scriptRuntime{
		name:       "deno",
		bin:        a.denoBin(),
		customURL:  conf.InstallDenoUrl,
		version:    conf.InstallDenoVersion,
		sha256:     conf.InstallDenoSha256,
		releaseURL: denoRelease(runtime.GOOS, runtime.GOARCH, conf.InstallDenoVersion),
		unpack: func(archive, dir string) (string, error) {
			return filepath.Join(dir, "deno"), Unzip(archive, dir)
		},
	}
	if err := a.installRuntime(rt, force); err != nil {
		a.Logger.Errorln("InstallDeno():", err)
	}
}

func createNushellConfig() error {
	dir := filepath.Join(nixAgentEtcDir, "nushell")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"config.nu", "env.nu"} {
		p := filepath.Join(dir, name)
		if !rmm.FileExists(p) {
			f, err := os.Create(p)
			if err != nil {
				return err
			}
			f.Close()
		}
		if err := os.Chmod(p, 0o744); err != nil {
			return err
		}
	}
	return nil
}
