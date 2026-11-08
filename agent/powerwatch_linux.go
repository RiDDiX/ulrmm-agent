// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	nats "github.com/nats-io/nats.go"
)

// logind announces shutdown and sleep with PrepareForShutdown(WithMetadata)
// and PrepareForSleep. A delay inhibitor gives the agent up to
// InhibitDelayMaxSec (5 s by default) to tell the server first. busctl and
// systemd-inhibit do the D-Bus part.

const powerBudget = 3 * time.Second

// sender is logind's name: any bus client can send signals with this path
// and interface
var loginMonitorArgv = []string{"busctl", "monitor", "--system", "--match",
	"type='signal',sender='org.freedesktop.login1',path='/org/freedesktop/login1',interface='org.freedesktop.login1.Manager'"}

// held around `tail --pid` like the keep-awake hold, so it ends with the agent
func powerInhibitArgv(pid int) []string {
	return []string{"systemd-inhibit", "--what=shutdown:sleep", "--who=" + BrandAgentName, "--why=report power event", "--mode=delay",
		"tail", "--pid=" + strconv.Itoa(pid), "-f", "/dev/null"}
}

func systemdBooted() bool { return rmm.FileExists("/run/systemd/system") }

func (a *Agent) watchPower(nc *nats.Conn) {
	if !systemdBooted() {
		return
	}
	refreshUnit()
	// without it only the stop signal is left (watchStop)
	if _, err := exec.LookPath("busctl"); err != nil {
		return
	}
	var held chan struct{}
	var pgid int
	take := func() {
		if held != nil {
			select {
			case <-held:
			default:
				return
			}
		}
		argv := powerInhibitArgv(os.Getpid())
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			a.Logger.Debugln("power watch: inhibitor:", err)
			held = nil
			return
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		held, pgid = done, cmd.Process.Pid
	}
	release := func() {
		if held != nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			held = nil
		}
	}
	// the lock comes back only after wake or cancel; taken while logind
	// waits, it would hold up that sleep or shutdown
	onSignal := func(kind string) {
		switch kind {
		case "wake":
			take()
			a.powerBack(nc)
		case "cancel":
			_ = a.announcePower(nc, kind, "os", "", powerBudget)
			take()
		default:
			// before systemd 255 only the plain signal comes; with 255 it
			// comes next to the one that carries the type, announcePower
			// keeps the precise kind
			_ = a.announcePower(nc, kind, "os", "", powerBudget)
			release()
		}
	}
	wait := 5 * time.Second
	for {
		take()
		start := time.Now()
		cmd := exec.Command(loginMonitorArgv[0], loginMonitorArgv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			_ = scanLoginSignals(out, onSignal)
			err = cmd.Wait()
		}
		// nobody would release it
		release()
		// the system bus is not up yet, or busctl is missing
		a.Logger.Debugln("power watch: busctl monitor:", err)
		if time.Since(start) > time.Minute {
			wait = 5 * time.Second
		} else if wait < 5*time.Minute {
			wait *= 2
		}
		time.Sleep(wait)
	}
}

// scanLoginSignals reads `busctl monitor` text and calls fn with shutdown,
// restart, shutdown_or_restart, sleep, wake or cancel. A message ends with an
// empty line.
func scanLoginSignals(r io.Reader, fn func(kind string)) error {
	var member, typ string
	var active, gotBool, wantType bool
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(l, "‣"):
			member, typ, gotBool, wantType = "", "", false, false
		case strings.Contains(l, "Member="):
			for _, f := range strings.Fields(l) {
				if m, ok := strings.CutPrefix(f, "Member="); ok {
					member = m
				}
			}
		case !gotBool && strings.HasPrefix(l, "BOOLEAN "):
			gotBool, active = true, l == "BOOLEAN true;"
		case l == `STRING "type";`:
			wantType = true
		case wantType && strings.HasPrefix(l, `STRING "`):
			typ, wantType = strings.TrimSuffix(strings.TrimPrefix(l, `STRING "`), `";`), false
		case l == "" && gotBool:
			if k := loginKind(member, active, typ); k != "" {
				fn(k)
			}
			member, typ, gotBool, wantType = "", "", false, false
		}
	}
	return sc.Err()
}

func loginKind(member string, active bool, typ string) string {
	switch {
	case member == "PrepareForSleep" && active:
		return "sleep"
	case member == "PrepareForSleep":
		return "wake"
	case member != "PrepareForShutdown" && member != "PrepareForShutdownWithMetadata":
		return ""
	case !active:
		return "cancel"
	}
	switch typ {
	case "power-off", "halt":
		return "shutdown"
	case "reboot", "kexec", "soft-reboot":
		return "restart"
	}
	return "shutdown_or_restart"
}

// classifyStop runs at the stop signal: is the whole system going down?
// systemctl start reboot.target and --force pass logind by.
func classifyStop() (kind, initiator string) {
	if !systemdBooted() {
		b, _ := os.ReadFile("/run/openrc/softlevel")
		switch strings.TrimSpace(string(b)) {
		case "shutdown":
			return "shutdown", ""
		case "reboot":
			return "restart", ""
		}
		return "", ""
	}
	jobs, _ := healCmd(2*time.Second, "systemctl", "list-jobs", "--no-legend", "--no-pager")
	if k := shutdownKindFromJobs(jobs); k != "" {
		return k, ""
	}
	// exits non-zero for anything but running
	state, _ := healCmd(2*time.Second, "systemctl", "is-system-running")
	if strings.TrimSpace(state) == "stopping" {
		return "shutdown_or_restart", ""
	}
	return "", ""
}

// `systemctl list-jobs --no-legend`: "123 reboot.target start waiting"
func shutdownKindFromJobs(out string) string {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[1] {
		case "reboot.target", "kexec.target", "soft-reboot.target":
			return "restart"
		case "poweroff.target", "halt.target":
			return "shutdown"
		}
	}
	return ""
}

// refreshUnit adds the stop order and timeout the stop-signal notice needs to
// a unit installed before them; the rest of the unit (ExecStart differs on
// TrueNAS) stays. daemon-reload, no restart.
func refreshUnit() {
	path := linuxHeal{}.unitPath(IdentNixSvc)
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), "KillMode=process\n") {
		return
	}
	if s := upgradeUnit(string(b)); s != string(b) && writeFileSynced(path, []byte(s), 0o644) == nil {
		_, _ = healCmd(time.Minute, "systemctl", "daemon-reload")
	}
}

func upgradeUnit(s string) string {
	if !strings.Contains(s, "\nAfter=") {
		s = strings.Replace(s, "\n\n[Service]", "\nAfter=network.target nss-lookup.target\n\n[Service]", 1)
	}
	if !strings.Contains(s, "\nTimeoutStopSec=") {
		s = strings.Replace(s, "KillMode=process\n", "KillMode=process\nTimeoutStopSec=15\n", 1)
	}
	return s
}
