// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/elastic/go-sysinfo"
	"github.com/go-resty/resty/v2"
	"github.com/kardianos/service"
	nats "github.com/nats-io/nats.go"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/sirupsen/logrus"
)

// Tests build Agent with only Logger (and UnixTmpDir) set; other fields may be zero.
type Agent struct {
	Logger         *logrus.Logger
	Debug          bool
	Version        string
	LogTo, LogFile string

	Hostname, Arch, Platform, GoArch string
	AgentID, AgentHeader             string
	AgentPK                          int

	BaseURL, ApiURL, Proxy string
	Token, Cert            string
	Headers                map[string]string
	rClient                *resty.Client

	ProgramDir, EXE, SystemDrive              string
	WinTmpDir, WinRunAsUserTmpDir, UnixTmpDir string

	MeshInstaller, MeshSystemEXE, MeshSVC string
	PyBin, PyVer, PyBaseDir, PyDir        string
	NuBin, DenoBin                        string

	ServiceConfig *service.Config

	NatsPingInterval                         int
	NatsWSCompression                        bool
	NatsServer, NatsProxyPath, NatsProxyPort string

	TerminalSessions       map[string]*TerminalSession
	TerminalSessionsMu     sync.Mutex
	PendingTerminalResizes map[string]PendingTerminalResize

	// mTLS client certificate, read on every handshake; nil: none
	clientCert atomic.Pointer[tls.Certificate]
	// one renewal at a time; certRetry is the end of a backoff
	certMu    sync.Mutex
	certRetry time.Time
	// the renewed pair while the config does not hold it yet
	certUnsaved map[string]string

	// certificate pins of the RMM; nil: none stored
	pins  atomic.Pointer[pinSet]
	pinMu sync.Mutex
	// one pin rescue at a time, rescueAt is the last
	rescueMu sync.Mutex
	rescueAt time.Time

	eventsMu      sync.Mutex
	events        []securityEvent
	sendingEvents atomic.Bool
	// set and read by the one running sendSecurityEvents
	eventsRetry time.Time
	// why the last NATS handshake was refused, "" once one passed
	natsTLSErr atomic.Value
	// true while a NATS connection is up; keepNew cancels the revert of
	// the last update (armRevert) once the server was reached
	natsUp  atomic.Bool
	keepNew func()

	// identity, sessions and tokens of signed commands
	sec2 sec2State
}

// Paths from brand.go, set by setNixLayout. Tests point etcConfig at a temp file.
var (
	etcConfig       string
	nixAgentDir     string
	nixAgentBin     string
	nixAgentBinDir  string
	nixAgentEtcDir  string
	nixMeshDir      string
	nixMeshAgentBin string
	// unit the mesh installer writes (Linux)
	nixMeshUnit string
	// where the install puts the binary on Linux and FreeBSD
	nixMainBin string
	// the binary an update on Linux, macOS and FreeBSD replaced
	rollbackCopy string
	// script files when no tmpdir is configured
	nixTmpDir string
	onTrueNAS bool

	macPlistName = IdentMacPlistLabel
	macPlistPath = "/Library/LaunchDaemons/" + IdentMacPlistLabel + ".plist"

	winSvcName                = IdentWinSvcName
	winExeName                = IdentWinExe
	progFilesName             = IdentWinProgDir
	defaultWinTmpDir          = filepath.Join(os.Getenv("PROGRAMDATA"), IdentWinRegKey)
	defaultWinRunAsUserTmpDir = filepath.Join(defaultWinTmpDir, "runasuser")
	winMeshDir                = filepath.Join(os.Getenv("PROGRAMFILES"), "Mesh Agent")

	// check-in messages in the order the service start sends them
	natsCheckin = []string{"agent-hello", "agent-agentinfo", "agent-disks", "agent-winsvc", "agent-publicip", "agent-wmi"}
	// left out of that start burst when the server asks for limited data
	limitNatsData = []string{"agent-winsvc", "agent-wmi"}
)

const (
	meshSvcName          = "mesh agent"
	defaultMacMeshSvcDir = "/usr/local/mesh_services"
	trueNASManifest      = "/data/manifest.json"
)

// TrueNAS SCALE is told apart by these files.
var trueNASMarkers = []string{trueNASManifest, "/usr/bin/midclt"}

func isTrueNAS() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, m := range trueNASMarkers {
		if !rmm.FileExists(m) {
			return false
		}
	}
	return true
}

func init() { setNixLayout(isTrueNAS()) }

// setNixLayout is the one place that derives the unix paths; TrueNAS keeps only /root across updates.
func setNixLayout(truenas bool) {
	onTrueNAS = truenas
	nixAgentDir, etcConfig = IdentNixDir, IdentNixConf
	nixMeshDir, nixMeshUnit = "/opt/ulrmm-mesh", "/lib/systemd/system/meshagent.service"
	nixMainBin = "/usr/local/bin/" + IdentNixBin
	if truenas {
		nixAgentDir = "/root/" + IdentNixBin
		etcConfig = nixAgentDir + "/" + IdentNixBin + ".conf"
		nixMeshDir, nixMeshUnit = "/root/ulrmm-mesh", "/etc/systemd/system/meshagent.service"
		nixMainBin = nixAgentDir + "/" + IdentNixBin
	}
	nixAgentBin = nixAgentDir + "/" + IdentNixBin
	nixAgentBinDir = nixAgentDir + "/bin"
	nixAgentEtcDir = nixAgentDir + "/etc"
	nixMeshAgentBin = nixMeshDir + "/meshagent"
	rollbackCopy = nixAgentDir + "/" + IdentNixBin + ".previous"
	nixTmpDir = nixAgentDir + "/tmp"
	if truenas {
		// /root is 0700 and /tmp noexec there: run_as_user scripts need /var/tmp
		nixTmpDir = "/var/tmp/" + IdentNixBin
	}
}

func New(logger *logrus.Logger, version string) *Agent {
	cfg := NewAgentConfig()
	if err := openConfigSecrets(cfg); err != nil {
		logger.Errorln("config:", err)
	}
	tampered := checkConfigMAC(cfg)

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		if h, herr := sysinfo.Host(); herr == nil {
			hostname = h.Info().Hostname
		} else if hi, herr := host.Info(); herr == nil {
			hostname = hi.Hostname
		}
	}

	programDir := filepath.Join(os.Getenv("ProgramFiles"), progFilesName)
	exe := filepath.Join(programDir, winExeName)

	pyBin, pyVer, pyBaseDir, pyDir := "n/a", "n/a", "n/a", "n/a"
	nuBin, denoBin := nixAgentBinDir+"/nu", nixAgentBinDir+"/deno"
	if runtime.GOOS == "windows" {
		pyVer = windowsPythonVersion()
		pyDir = fmt.Sprintf("py%s_%s", pyVer, runtime.GOARCH)
		pyBaseDir = filepath.Join(programDir, "python")
		pyBin = filepath.Join(pyBaseDir, pyDir, "python.exe")
		nuBin = filepath.Join(programDir, "bin", "nu.exe")
		denoBin = filepath.Join(programDir, "bin", "deno.exe")
	}

	winTmpDir := defaultWinTmpDir
	if cfg.WinTemp != "" {
		winTmpDir = cfg.WinTemp
	}
	winRunAsUserTmpDir := defaultWinRunAsUserTmpDir
	if cfg.WinUserTemp != "" {
		winRunAsUserTmpDir = cfg.WinUserTemp
	}

	var meshSystemEXE string
	switch runtime.GOOS {
	case "windows":
		dir := winMeshDir
		if cfg.MeshDir != "" {
			dir = cfg.MeshDir
		}
		meshSystemEXE = filepath.Join(dir, "MeshAgent.exe")
	case "darwin":
		meshSystemEXE = defaultMacMeshSvcDir + "/meshagent/meshagent"
		if rmm.FileExists(nixMeshAgentBin) {
			meshSystemEXE = nixMeshAgentBin
		}
	default:
		meshSystemEXE = nixMeshAgentBin
	}

	headers := map[string]string{}
	if cfg.AuthToken != "" {
		headers["Content-Type"] = "application/json"
		headers["Authorization"] = "Token " + cfg.AuthToken
	}

	natsProxyPath := cfg.NATSProxyPath
	if natsProxyPath == "" {
		natsProxyPath = "natsws"
	}
	natsProxyPort := cfg.NATSProxyPort
	if natsProxyPort == "" {
		natsProxyPort = "443"
	}
	natsServer := "wss://" + net.JoinHostPort(cfg.APIHost, natsProxyPort)
	compression := true
	if cfg.NATSPort != "" {
		natsServer = "tls://" + net.JoinHostPort(cfg.APIHost, cfg.NATSPort)
		compression = false
	}
	pingInterval := cfg.NATSPing
	if pingInterval <= 0 {
		pingInterval = randRange(35, 45)
	}

	a := &Agent{
		Logger:  logger,
		Debug:   logger.IsLevelEnabled(logrus.DebugLevel),
		Version: version,

		ServiceConfig: agentServiceConfig(exe),

		Hostname:    hostname,
		Platform:    runtime.GOOS,
		GoArch:      runtime.GOARCH,
		AgentID:     cfg.ID,
		AgentPK:     cfg.PKNum,
		AgentHeader: fmt.Sprintf("ulrmm/%s/%s/%s", version, runtime.GOOS, runtime.GOARCH),

		BaseURL: cfg.ServerBase,
		ApiURL:  cfg.APIHost,
		Proxy:   cfg.ProxyURL,
		Token:   cfg.AuthToken,
		Cert:    cfg.CACert,
		Headers: headers,

		ProgramDir:         programDir,
		EXE:                exe,
		SystemDrive:        os.Getenv("SystemDrive"),
		WinTmpDir:          winTmpDir,
		WinRunAsUserTmpDir: winRunAsUserTmpDir,
		UnixTmpDir:         cfg.UnixTemp,

		MeshInstaller: "meshagent.exe",
		MeshSystemEXE: meshSystemEXE,
		MeshSVC:       meshSvcName,
		PyBin:         pyBin,
		PyVer:         pyVer,
		PyBaseDir:     pyBaseDir,
		PyDir:         pyDir,
		NuBin:         nuBin,
		DenoBin:       denoBin,

		NatsServer: natsServer, NatsProxyPath: natsProxyPath, NatsProxyPort: natsProxyPort,
		NatsPingInterval:  pingInterval,
		NatsWSCompression: compression,

		TerminalSessions:       make(map[string]*TerminalSession),
		PendingTerminalResizes: make(map[string]PendingTerminalResize),
	}
	if cfg.TLSCert != "" {
		if c, err := keyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			logger.Errorln("client certificate:", err)
		} else {
			a.clientCert.Store(c)
		}
	}
	if ps, err := loadPins(cfg.PinsJSON); err != nil {
		logger.Errorln(err)
	} else if ps != nil {
		a.pins.Store(ps)
	}
	if tampered != "" {
		logger.Errorln("config:", tampered)
		a.queueSecurityEvent("config_tampered", tampered)
	}
	a.rClient = a.newAPIClient(cfg.ServerBase, headers)
	return a
}

// The service restarts itself 12s after a crash; failure counts reset after 10s.
func agentServiceConfig(exe string) *service.Config {
	return &service.Config{
		Name:        winSvcName,
		DisplayName: BrandServiceDisplay,
		Description: BrandServiceDisplay,
		Executable:  exe,
		Arguments:   []string{"-m", "svc"},
		Option:      service.KeyValue{"StartType": "automatic", "OnFailure": "restart", "OnFailureDelayDuration": "12s", "OnFailureResetPeriod": 10},
	}
}

func (a *Agent) newAPIClient(baseURL string, headers map[string]string) *resty.Client {
	host := ""
	if u, err := url.Parse(baseURL); err == nil {
		host = u.Hostname()
	}
	c := a.restyFor(host).
		SetBaseURL(baseURL).
		SetTimeout(15 * time.Second).
		SetHeaders(headers)
	c.OnBeforeRequest(func(_ *resty.Client, r *resty.Request) error {
		switch tok := a.sec2.access.Load(); {
		case r.Context().Value(noAuthKey{}) != nil:
			r.SetHeader("Authorization", "")
		case tok != nil:
			r.SetHeader("Authorization", "Token "+*tok)
		}
		r.SetContext(context.WithValue(r.Context(), sentCertKey{}, a.clientCert.Load()))
		return nil
	})
	if tr, err := c.Transport(); err == nil {
		c.SetTransport(&sealTransport{base: tr, a: a})
	}
	// nginx answers 400 to a certificate it cannot verify (a new agent CA),
	// the server 401 to one it revoked: go on without it, the service's
	// renewal asks for a new one. Both answers mean a certificate went out;
	// a newer one from a renewal in between stays.
	c.OnAfterResponse(func(_ *resty.Client, r *resty.Response) error {
		refused := (r.StatusCode() == 400 && strings.Contains(r.String(), "SSL certificate error")) ||
			(r.StatusCode() == 401 && strings.Contains(r.String(), "client certificate does not belong"))
		sent, _ := r.Request.Context().Value(sentCertKey{}).(*tls.Certificate)
		if refused && sent != nil && a.clientCert.CompareAndSwap(sent, nil) {
			a.Logger.Errorln("The server refused the client certificate, continuing without it")
		}
		// a token or recover answer brings tokens not stored yet; storeTokens
		// sends the queue
		if !r.IsError() && !strings.HasSuffix(r.Request.URL, securityEventPath) && !strings.Contains(r.Request.URL, "/token/") &&
			!strings.Contains(r.Request.URL, "/recover/") && a.pendingSecurityEvents() {
			go a.sendSecurityEvents()
		}
		a.credentialAnswer(r.Request.URL, r.StatusCode(), r.String())
		return nil
	})
	return c
}

// restyFor is a REST client for the RMM at host: its TLS setup, https
// only. Redirects follow checkRedirect; without it the client would carry
// Authorization on to plain http on the same host.
func (a *Agent) restyFor(host string) *resty.Client {
	c := resty.New().SetCloseConnection(true)
	if a.Proxy != "" {
		// resty would log a parse error with the credentials in it
		if _, err := parseProxyURL(a.Proxy); err != nil {
			a.Logger.Errorln("API client:", err)
		} else {
			c.SetProxy(a.Proxy)
		}
	}
	c.SetTLSClientConfig(a.tlsFor(host))
	c.SetRedirectPolicy(resty.RedirectPolicyFunc(a.checkRedirect(host)))
	c.SetPreRequestHook(func(_ *resty.Client, r *http.Request) error {
		if r.URL.Scheme != "https" {
			return errors.New("refusing a request to the RMM that is not https")
		}
		return nil
	})
	return c
}

// sentCertKey holds the client certificate a request could present.
type sentCertKey struct{}

// clientCertFor is GetClientCertificate. An expired certificate, or one
// from a CA the server does not name, stays home: nginx would refuse every
// request that carries it. One that is not valid yet by this clock goes
// out, the server checks it with its own.
func (a *Agent) clientCertFor(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := a.clientCert.Load()
	if c == nil || c.Leaf == nil {
		return &tls.Certificate{}, nil
	}
	if time.Now().After(c.Leaf.NotAfter) || cri.SupportsCertificate(c) != nil {
		return &tls.Certificate{}, nil
	}
	return c, nil
}

// keyPair parses a stored certificate and its key; Leaf is set.
func keyPair(certPEM, keyPEM string) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil {
		return nil, errors.New("the certificate was not parsed")
	}
	return &c, nil
}

// windowsPythonVersion picks the bundled Python the OS can still run.
func windowsPythonVersion() string {
	h, err := sysinfo.Host()
	if err != nil || h.Info().OS == nil {
		return "3.14.5"
	}
	return pythonForWindows(h.Info().OS.Major, h.Info().OS.Minor)
}

func pythonForWindows(major, minor int) string {
	switch {
	case major >= 10:
		return "3.14.5"
	case major == 6 && minor >= 3:
		return "3.11.9"
	default:
		return "3.8.7"
	}
}

// No agent token (the file host is not the API). With wantSha256 set the file
// must match; whatever fails, dest is gone afterwards.
func (a *Agent) fetchFile(link, dest, wantSha256 string, timeout time.Duration) (err error) {
	defer func() {
		if err != nil {
			os.Remove(dest)
		}
	}()
	client, err := a.httpClient(link, timeout)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(link)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("download answered %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || wantSha256 == "" {
		return err
	}
	got, err := fileSHA256(dest)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, wantSha256) {
		return badDownload{fmt.Errorf("sha256 of the download is %s, the server expects %s", got, wantSha256)}
	}
	return nil
}

// natsTLSResult logs why NATS handshakes are refused when the reason
// changes: the client retries every few seconds and reports only timeouts.
func (a *Agent) natsTLSResult(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	prev, _ := a.natsTLSErr.Swap(msg).(string)
	switch {
	case msg == prev:
	case msg != "":
		a.Logger.Errorf("NATS: the TLS connection to %s was refused: %s", a.ApiURL, msg)
	default:
		a.Logger.Infoln("NATS: the TLS connection to", a.ApiURL, "is accepted again")
	}
}

func parseProxyURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		// the parse error quotes the URL, credentials included
		return nil, errors.New("the proxy URL cannot be parsed")
	}
	return u, nil
}

func (a *Agent) setupNatsOptions() []nats.Option {
	opts := []nats.Option{
		nats.Name(a.AgentID),
		nats.ReconnectWait(time.Duration(randRange(2, 8)) * time.Second),
		nats.ReconnectJitter(500*time.Millisecond, 4*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.IgnoreAuthErrorAbort(),
		nats.MaxReconnects(-1),
		nats.ReconnectBufSize(-1),
		nats.PingInterval(time.Duration(a.NatsPingInterval) * time.Second),
		nats.Compression(a.NatsWSCompression),
		nats.NoEcho(),
		nats.ConnectHandler(func(nc *nats.Conn) {
			a.Logger.Debugln("NATS connected to", nc.ConnectedUrlRedacted())
			a.natsUp.Store(true)
			if a.keepNew != nil {
				a.keepNew()
			}
		}),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			a.natsUp.Store(false)
			if err != nil {
				a.Logger.Errorf("NATS disconnected from %s: %v", nc.ConnectedUrlRedacted(), err)
			} else {
				a.Logger.Debugln("NATS disconnected")
			}
			a.Logger.Debugf("NATS stats: %+v", nc.Stats())
		}),
		nats.ReconnectHandler(func(*nats.Conn) {
			a.Logger.Debugln("NATS reconnected")
			a.natsUp.Store(true)
			if a.keepNew != nil {
				a.keepNew()
			}
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			a.Logger.Errorln("NATS error:", err)
		}),
	}
	opts = append(opts, a.natsAuth()...)
	// wss:// and tls:// turn TLS on anyway; this is the RMM's trust and the client certificate
	t := a.tlsFor(a.ApiURL)
	verify := t.VerifyConnection
	t.VerifyConnection = func(cs tls.ConnectionState) error {
		err := verify(cs)
		a.natsTLSResult(err)
		return err
	}
	opts = append(opts, nats.Secure(t))
	if a.Proxy != "" {
		u, err := parseProxyURL(a.Proxy)
		switch {
		case err != nil:
			a.Logger.Errorln("setupNatsOptions(): failed to parse proxy URL:", err)
			opts = append(opts, nats.SetCustomDialer(refuseDialer{errors.New("the proxy URL cannot be parsed")}))
		case u.Scheme != "http" && u.Scheme != "https":
			a.Logger.Errorln("setupNatsOptions(): unsupported proxy scheme:", u.Scheme, "- not connecting")
			opts = append(opts, nats.SetCustomDialer(refuseDialer{fmt.Errorf("unsupported proxy scheme %q", u.Scheme)}))
		default:
			opts = append(opts, nats.SetCustomDialer(newHTTPConnectDialer(u)))
		}
	}
	return opts
}

// LaunchDaemon for the agent service; self-heal writes the same file.
func macServicePlist(bin string) string {
	return launchdPlist(macPlistName, []string{bin, "-m", "svc"},
		"<key>ServiceDescription</key><string>"+brandPlistSafe(BrandServiceDisplay)+"</string>",
		"<key>WorkingDirectory</key><string>"+brandPlistSafe(nixAgentDir)+"/</string>",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><true/>")
}

// launchdPlist renders a launchd job. Label and arguments are escaped here,
// props are finished key/value pairs.
func launchdPlist(label string, argv []string, props ...string) string {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	fmt.Fprintf(&b, "\t<key>Label</key><string>%s</string>\n\t<key>ProgramArguments</key>\n\t<array>\n", brandPlistSafe(label))
	for _, arg := range argv {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", brandPlistSafe(arg))
	}
	b.WriteString("\t</array>\n")
	for _, kv := range props {
		b.WriteString("\t" + kv + "\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// Without a usable id nothing is sent, so a stored good id survives a mesh
// agent that is not ready yet.
func (a *Agent) SyncMeshNodeID(runSyncTask bool) {
	id, err := a.getMeshNodeID()
	if err != nil {
		a.Logger.Errorln("SyncMeshNodeID() getMeshNodeID()", err)
		return
	}
	id = StripAll(id)
	if id == "" || id == "error getting meshnodeid" {
		a.Logger.Debugln("SyncMeshNodeID(): no mesh node id yet")
		return
	}
	payload := rmm.MeshNode{Op: "syncmesh", AgentID: a.AgentID, Node: id, SyncNow: runSyncTask}
	if _, err := a.rClient.R().SetBody(payload).Post("/api/v3/syncmesh/"); err != nil {
		a.Logger.Debugln("SyncMeshNodeID() Post:", err)
	}
}

// Every mesh agent process (Windows recovery).
func (a *Agent) ForceKillMesh() {
	for _, p := range listProcs(true) {
		if strings.Contains(strings.ToLower(p.name), "meshagent") {
			if err := KillProc(p.pid); err != nil {
				a.Logger.Debugln("ForceKillMesh():", err)
			}
		}
	}
}

// Fetches the mesh installer from the server and installs from scratch (Windows recovery).
func (a *Agent) ReinstallMesh() {
	meshBin := filepath.Join(a.ProgramDir, a.MeshInstaller)
	r, err := a.rClient.R().SetOutput(meshBin).Get(fmt.Sprintf("/api/v3/%s/meshreinstall/", a.AgentID))
	if err != nil {
		a.Logger.Errorln("ReinstallMesh(): download:", err)
		return
	}
	if r.IsError() {
		a.Logger.Errorln("ReinstallMesh(): download answered", r.StatusCode())
		return
	}
	if _, err := CMD(meshBin, []string{"-fulluninstall"}, 30, false); err != nil {
		a.Logger.Debugln("ReinstallMesh(): -fulluninstall:", err)
	}
	time.Sleep(2 * time.Second)
	if dir := filepath.Dir(a.MeshSystemEXE); filepath.Dir(dir) != dir {
		if err := os.RemoveAll(dir); err != nil {
			a.Logger.Debugln("ReinstallMesh(): remove mesh dir:", err)
		}
	}
	time.Sleep(time.Second)
	if _, err := a.installMesh(meshBin, a.MeshSystemEXE, a.Proxy); err != nil {
		a.Logger.Errorln("ReinstallMesh(): install:", err)
	}
}

func (a *Agent) CleanupAgentUpdates() {
	for _, dir := range []string{a.WinTmpDir, os.Getenv("TMP"), a.ProgramDir} {
		if dir == "" {
			continue
		}
		for _, pattern := range []string{IdentArtifact + "-v*", "is-*.tmp"} {
			matches, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				continue
			}
			for _, m := range matches {
				if err := os.Remove(m); err != nil {
					a.Logger.Debugln("CleanupAgentUpdates():", err)
				}
			}
		}
	}
	if tmp := os.Getenv("TMP"); tmp != "" {
		entries, err := os.ReadDir(tmp)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), winSvcName) {
				os.RemoveAll(filepath.Join(tmp, e.Name()))
			}
		}
	}
}

// Inno uninstaller in the program dir.
func (a *Agent) GetUninstallExe() string {
	matches, _ := filepath.Glob(filepath.Join(a.ProgramDir, "unins*.exe"))
	for _, m := range matches {
		if name := filepath.Base(m); strings.Contains(name, "001") {
			return name
		}
	}
	return "unins000.exe"
}
