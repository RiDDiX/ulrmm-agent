// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"git.riddix.de/RiDDiX/ulrmm-agent/agent"
	"github.com/sirupsen/logrus"
)

var (
	// the server build reads this line: keep it `version = "X.DD.MM.YYYY"`
	version = "2.03.11.2026"
	log     = logrus.New()
)

// secondsFlag is -timeout: bare seconds ("600") or a Go duration ("10m").
type secondsFlag time.Duration

func (s *secondsFlag) String() string { return strconv.Itoa(int(time.Duration(*s) / time.Second)) }

func (s *secondsFlag) Set(v string) error {
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		*s = secondsFlag(time.Duration(n) * time.Second)
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fmt.Errorf("want seconds or a duration like 10m")
	}
	*s = secondsFlag(d)
	return nil
}

func main() {
	installTimeout := secondsFlag(900 * time.Second)
	var (
		ver        = flag.Bool("version", false, "print the version and exit")
		selftest   = flag.Bool("selftest", false, "open the config and reach the RMM, then exit (0 ok, 1 failed, 2 RMM not reachable)")
		mode       = flag.String("m", "", "mode")
		taskPK     = flag.Int("p", 0, "task id (taskrunner)")
		logLevel   = flag.String("log", "INFO", "log level")
		logTo      = flag.String("logto", "file", "file or stdout")
		api        = flag.String("api", "", "RMM URL")
		clientID   = flag.Int("client-id", 0, "client id")
		siteID     = flag.Int("site-id", 0, "site id")
		desc       = flag.String("desc", "", "agent description")
		agentType  = flag.String("agent-type", "server", "server or workstation")
		token      = flag.String("auth", "", "installer token")
		authFile   = flag.String("auth-file", "", "file with the installer token, deleted after reading")
		power      = flag.Bool("power", false, "Windows: disable sleep and hibernate")
		rdp        = flag.Bool("rdp", false, "Windows: enable RDP")
		ping       = flag.Bool("ping", false, "Windows: allow ICMP echo")
		localMesh  = flag.String("local-mesh", "", "Windows: local mesh agent installer")
		noMesh     = flag.Bool("nomesh", false, "do not install the mesh agent")
		meshDir    = flag.String("meshdir", "", "custom mesh agent directory")
		tmpDir     = flag.String("tmpdir", "", "directory for script files")
		meshNodeID = flag.String("meshnodeid", "", "mesh node id to register")
		cert       = flag.String("cert", "", "CA certificate (PEM) of the RMM")
		silent     = flag.Bool("silent", false, "no message boxes")
		proxy      = flag.String("proxy", "", "HTTP proxy URL")
		insecure   = flag.Bool("insecure", false, "removed, use -cert")
		natsPort   = flag.String("natsport", "", "NATS TCP port instead of websockets")
		code       = flag.String("code", "", "uninstall code (or ULRMM_UNINSTALL_CODE)")
		enroll     = flag.String("enroll", "", "setup exe or text file with signed enrollment data")
	)
	flag.Var(&installTimeout, "timeout", "installer download timeout in seconds")
	flag.Parse()

	if *insecure {
		fmt.Fprintln(os.Stderr, "insecure mode was removed; use -cert <ca.pem>")
		os.Exit(1)
	}
	if *ver {
		showVersionInfo()
		return
	}
	if *selftest {
		setupLogging(*logLevel, "stdout")
		log.SetOutput(os.Stderr)
		out, err := agent.New(log, version).SelfTest(15 * time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, "selftest failed:", err)
			if errors.Is(err, agent.ErrTransient) {
				os.Exit(2)
			}
			os.Exit(1)
		}
		fmt.Println(out)
		return
	}
	if *mode == "licenses" {
		if err := printLicenses(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	// runs inside a user session started by the service: no config, no log
	if *mode == "idle" {
		agent.PrintUserIdle()
		return
	}
	if len(os.Args) == 1 {
		if runtime.GOOS == "windows" {
			agent.ShowStatus(version)
		} else {
			showVersionInfo()
		}
		return
	}

	setupLogging(*logLevel, *logTo)
	a := agent.New(log, version)

	actions := map[string]func(){
		"checkin":        a.DoNatsCheckIn,
		"rpc":            a.RunRPC,
		"software":       a.SendSoftware,
		"cleanup":        a.UninstallCleanup,
		"runmigrations":  a.RunMigrations,
		"recovermesh":    a.RecoverMesh,
		"macventurafix":  a.FixVenturaMesh,
		"selfheal":       a.RunSelfHeal,
		"getpython":      func() { a.GetPython(true) },
		"installdeno":    func() { a.InstallDeno(true) },
		"installnushell": func() { a.InstallNushell(true) },
		"pk":             func() { fmt.Println(a.AgentPK) },
		"publicip":       func() { fmt.Println(a.PublicIP()) },
		"getenv":         func() { fmt.Println(os.Getenv(flag.Arg(0))) },
		"nixmeshnodeid":  func() { fmt.Print(a.NixMeshNodeID()) },
	}
	if run, ok := actions[*mode]; ok {
		run()
		return
	}

	switch *mode {
	case "installsvc":
		if err := a.InstallService(); err != nil {
			log.Errorln("InstallService():", err)
		}
	case "svc":
		// only the Windows service manager needs the wrapper (agent/powerwatch_windows.go)
		w, ok := any(a).(interface{ RunService() error })
		if runtime.GOOS != "windows" || !ok {
			a.RunRPC()
			return
		}
		if err := w.RunService(); err != nil {
			log.Errorln("service:", err)
		}
	case "runchecks", "checkrunner":
		if err := a.RunChecks(*mode == "runchecks"); err != nil {
			log.Errorln("RunChecks():", err)
		}
	case "uninstall":
		c := *code
		if c == "" {
			c = os.Getenv("ULRMM_UNINSTALL_CODE")
		}
		if err := a.UninstallWithCode(c); err != nil {
			fmt.Println("uninstall:", err)
			os.Exit(1)
		}
	case "taskrunner":
		if *taskPK == 0 {
			return
		}
		if err := a.RunTask(*taskPK, true); err != nil {
			log.Errorln("RunTask():", err)
		}
	case "install":
		log.SetOutput(os.Stdout)
		if runtime.GOOS != "windows" {
			if u, err := user.Current(); err != nil {
				log.Fatalln(err)
			} else if u.Uid != "0" {
				log.Fatalln("must run as root")
			}
		}
		if *authFile != "" {
			if *token != "" {
				fmt.Fprintln(os.Stderr, "use -auth or -auth-file, not both")
				os.Exit(1)
			}
			t, err := agent.ReadAuthFile(*authFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "-auth-file:", err)
				os.Exit(1)
			}
			*token = t
		}
		// with -enroll the signed data supplies server, client, site, type and flags
		if *enroll == "" && (*api == "" || *clientID == 0 || *siteID == 0 || *token == "") {
			fmt.Fprintln(os.Stderr, "install needs -enroll, or -api, -client-id, -site-id and -auth or -auth-file")
			os.Exit(1)
		}
		a.Install(&agent.Installer{
			EnrollFile: *enroll,
			RMM:        *api,
			Token:      *token,
			Cert:       *cert,
			Proxy:      *proxy,
			Timeout:    time.Duration(installTimeout),

			ClientID:    *clientID,
			SiteID:      *siteID,
			AgentType:   *agentType,
			Description: *desc,

			Power: *power, RDP: *rdp, Ping: *ping,
			Silent: *silent,
			TmpDir: *tmpDir,

			NoMesh: *noMesh, LocalMesh: *localMesh,
			MeshDir: *meshDir, MeshNodeID: *meshNodeID,
			NatsStandardPort: *natsPort,
		})
	default:
		agent.ShowStatus(version)
	}
}

// setupLogging: a file only root and Administrators can read, or stdout.
func setupLogging(level, to string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	log.SetLevel(lvl)
	if to == "stdout" {
		log.SetOutput(os.Stdout)
		return
	}
	path := agent.NixLogFile
	var created func(string)
	if runtime.GOOS == "windows" {
		path = filepath.Join(os.Getenv("ProgramFiles"), agent.IdentWinProgDir, "agent.log")
		// Program Files is readable by every local user
		created = func(p string) { _ = agent.RestrictToAdmins(p) }
	}
	f, err := agent.OpenLogFile(path, created)
	if err != nil {
		log.SetOutput(os.Stderr)
		return
	}
	log.SetOutput(f)
}

// showVersionInfo: the build reads the text after the last ": " of the
// first line.
func showVersionInfo() {
	fmt.Println(agent.BrandAgentName+":", version)
	fmt.Println("Arch:", runtime.GOARCH)
	if runtime.GOOS == "windows" {
		fmt.Println("Program Directory:", filepath.Join(os.Getenv("ProgramFiles"), agent.IdentWinProgDir))
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Println(bi.String())
	}
}
