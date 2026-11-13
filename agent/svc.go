// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"
)

// AgentCheckInConfig is GET /api/v3/<agent>/config/. Intervals are seconds.
type AgentCheckInConfig struct {
	Hello                  int    `json:"checkin_hello"`
	AgentInfo              int    `json:"checkin_agentinfo"`
	WinSvc                 int    `json:"checkin_winsvc"`
	State                  int    `json:"checkin_state"`
	PubIP                  int    `json:"checkin_pubip"`
	Disks                  int    `json:"checkin_disks"`
	SW                     int    `json:"checkin_sw"`
	WMI                    int    `json:"checkin_wmi"`
	Drivers                int    `json:"checkin_drivers"`
	SyncMesh               int    `json:"checkin_syncmesh"`
	LimitData              bool   `json:"limit_data"`
	NushellEnableConfig    bool   `json:"nushell_enable_config"`
	DenoDefaultPermissions string `json:"deno_default_permissions"`
	// pinned choco install script; both empty when the server has none
	ChocoInstallUrl       string `json:"choco_install_url"`
	ChocoInstallSha256    string `json:"choco_install_sha256"`
	InstallNushell        bool   `json:"install_nushell"`
	InstallNushellVersion string `json:"install_nushell_version"`
	InstallNushellUrl     string `json:"install_nushell_url"`
	InstallNushellSha256  string `json:"install_nushell_sha256"`
	InstallDeno           bool   `json:"install_deno"`
	InstallDenoVersion    string `json:"install_deno_version"`
	InstallDenoUrl        string `json:"install_deno_url"`
	InstallDenoSha256     string `json:"install_deno_sha256"`
}

// minCheckInInterval: a server or registry value below it is raised to it.
const minCheckInInterval = 5

var lastCheckInConf struct {
	sync.Mutex
	conf *AgentCheckInConfig
}

// checkInIntervals pairs each interval with the range its default is
// drawn from (the server uses the same ranges).
func checkInIntervals(c *AgentCheckInConfig) []struct {
	v      *int
	lo, hi int
} {
	return []struct {
		v      *int
		lo, hi int
	}{
		{&c.Hello, 30, 60},
		{&c.AgentInfo, 200, 400},
		{&c.WinSvc, 2400, 3000},
		{&c.PubIP, 300, 500},
		{&c.Disks, 1000, 2000},
		{&c.SW, 2800, 3500},
		{&c.WMI, 3000, 4000},
		{&c.SyncMesh, 800, 1200},
		{&c.State, 270, 330},
		{&c.Drivers, 80000, 90000},
	}
}

// sanitizeIntervals replaces missing (zero or negative) intervals with a
// default and raises tiny ones, so no ticker gets a period it cannot take.
func sanitizeIntervals(c AgentCheckInConfig) AgentCheckInConfig {
	for _, iv := range checkInIntervals(&c) {
		switch {
		case *iv.v <= 0:
			*iv.v = randRange(iv.lo, iv.hi)
		case *iv.v < minCheckInInterval:
			*iv.v = minCheckInInterval
		}
	}
	return c
}

// Without an answer the last good one is used; before the first, the defaults.
func (a *Agent) GetCheckInConfFromAPI() AgentCheckInConfig {
	var conf AgentCheckInConfig
	r, err := a.rClient.R().SetResult(&conf).Get(fmt.Sprintf("/api/v3/%s/config/", a.AgentID))
	if err == nil && r.IsError() {
		err = fmt.Errorf("server answered %d", r.StatusCode())
	}
	if err != nil {
		a.Logger.Debugln("GetAgentCheckInConfig()", err)
		lastCheckInConf.Lock()
		defer lastCheckInConf.Unlock()
		if lastCheckInConf.conf != nil {
			return *lastCheckInConf.conf
		}
		return sanitizeIntervals(AgentCheckInConfig{})
	}
	for _, u := range []*string{&conf.InstallNushellUrl, &conf.InstallDenoUrl} {
		// Downloaded and executed; anything but https is dropped.
		if *u != "" && !strings.HasPrefix(strings.ToLower(*u), "https://") {
			a.Logger.Errorln("GetCheckInConfFromAPI(): ignoring non-https download url", *u)
			*u = ""
		}
	}
	conf = sanitizeIntervals(conf)
	lastCheckInConf.Lock()
	lastCheckInConf.conf = &conf
	lastCheckInConf.Unlock()
	return conf
}

func (a *Agent) RunAsService(nc *nats.Conn) {
	go a.AgentSvc(nc)
	go a.CheckRunner()
	select {}
}

// A panic is logged instead of ending the process.
func (a *Agent) guard(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			a.Logger.Errorf("recovered from panic in %s: %v\n%s", name, r, debug.Stack())
		}
	}()
	fn()
}

func sleepSeconds(n int) { time.Sleep(time.Duration(n) * time.Second) }

func (a *Agent) AgentSvc(nc *nats.Conn) {
	win := runtime.GOOS == "windows"
	a.RunMigrations()
	a.dropInsecure()
	if win {
		if err := protectConfigKey(); err != nil {
			a.Logger.Errorln("AgentSvc() protectConfigKey():", err)
		}
		if err := protectService(); err != nil {
			a.Logger.Errorln("AgentSvc() protectService():", err)
		}
		go a.guard("GetPython", func() { a.GetPython(false) })
		if err := createWinTempDir(); err != nil {
			a.Logger.Errorln("AgentSvc() createWinTempDir():", err)
		}
	} else {
		// right after install the server does not know the node id yet
		go a.guard("SyncMeshNodeID", func() { a.SyncMeshNodeID(true) })
	}
	go a.guard("pkgCleanup", a.pkgCleanup)

	delay := randRange(7, 25)
	a.Logger.Debugf("AgentSvc() sleeping for %v seconds", delay)
	sleepSeconds(delay)

	a.guard("RefreshPins", a.RefreshPins)
	go a.guard("checkIntegrity", func() { a.checkIntegrity(time.Now()) })
	// before the first API call: with mTLS required nothing else gets through
	a.guard("renewClientCert", func() { a.renewClientCert(time.Now()) })

	if win {
		a.guard("KillHungUpdates", a.KillHungUpdates)
		time.Sleep(time.Second)
		a.guard("CleanupAgentUpdates", a.CleanupAgentUpdates)
	}

	conf := sanitizeIntervals(a.GetAgentCheckInConfig(a.GetCheckInConfFromAPI()))
	a.Logger.Debugf("AgentCheckInConf: %+v", conf)

	for _, mode := range natsCheckin {
		if conf.LimitData && stringInSlice(mode, limitNatsData) {
			continue
		}
		a.guard(mode, func() { a.NatsMessage(nc, mode) })
		time.Sleep(time.Duration(randRange(100, 400)) * time.Millisecond)
	}

	if conf.InstallNushell {
		go a.guard("InstallNushell", func() { a.InstallNushell(false) })
	}
	if conf.InstallDeno {
		go a.guard("InstallDeno", func() { a.InstallDeno(false) })
	}
	go a.guard("SyncMeshNodeID", func() { a.SyncMeshNodeID(true) })

	if err := RestoreKeepAwake(); err != nil {
		a.Logger.Debugln("RestoreKeepAwake():", err)
	}

	sleepSeconds(randRange(1, 3))
	a.guard("AgentStartup", func() {
		report := a.startupReport()
		if (win && !conf.LimitData) || len(report) > 0 {
			a.AgentStartup(report)
		}
		if win && !conf.LimitData {
			a.SendSoftware()
		}
	})

	if runtime.GOOS == "darwin" {
		go a.guard("FixVenturaMesh", a.FixVenturaMesh)
	}

	tick := func(secs int) *time.Ticker { return time.NewTicker(time.Duration(secs) * time.Second) }
	helloTicker := tick(conf.Hello)
	agentInfoTicker := tick(conf.AgentInfo)
	winSvcTicker := tick(conf.WinSvc)
	pubIPTicker := tick(conf.PubIP)
	disksTicker := tick(conf.Disks)
	swTicker := tick(conf.SW)
	wmiTicker := tick(conf.WMI)
	syncMeshTicker := tick(conf.SyncMesh)
	// limit_data: a quarter of the pushes and no container stats
	stateEvery := conf.State
	if conf.LimitData {
		stateEvery *= 4
	}
	stateTicker := tick(stateEvery)
	heartbeatTicker := time.NewTicker(heartbeatEvery)
	patchTicker := time.NewTicker(patchRearmEvery)

	go a.guard("SelfHealSetup", a.SelfHealSetup)
	if win {
		go a.driversLoop(conf.Drivers)
	}

	var syncing, stating, sec2Running atomic.Bool
	publish := func(mode string) { a.guard(mode, func() { a.NatsMessage(nc, mode) }) }
	sendState := func() {
		if !stating.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer stating.Store(false)
			a.guard("SendState", func() { a.SendState(!conf.LimitData) })
		}()
	}
	sendState()
	for {
		select {
		case <-helloTicker.C:
			publish("agent-hello")
		case <-agentInfoTicker.C:
			publish("agent-agentinfo")
		case <-winSvcTicker.C:
			publish("agent-winsvc")
		case <-pubIPTicker.C:
			publish("agent-publicip")
		case <-disksTicker.C:
			publish("agent-disks")
		case <-wmiTicker.C:
			publish("agent-wmi")
		case <-swTicker.C:
			a.guard("SendSoftware", a.SendSoftware)
		case <-syncMeshTicker.C:
			if !syncing.CompareAndSwap(false, true) {
				a.Logger.Debugln("syncMeshTicker SyncMeshNodeID already running, skipping tick")
				continue
			}
			go func() {
				defer syncing.Store(false)
				a.guard("SyncMeshNodeID", func() { a.SyncMeshNodeID(false) })
			}()
		case <-stateTicker.C:
			sendState()
		case <-patchTicker.C:
			a.guard("rearmPatchMgmt", a.rearmPatchMgmt)
		case <-heartbeatTicker.C:
			a.guard("SelfHealHeartbeat", a.SelfHealHeartbeat)
			go a.guard("checkIntegrity", func() { a.checkIntegrity(time.Now()) })
			// a slow run (timeouts, registration backoff) must not overlap the next
			if !sec2Running.CompareAndSwap(false, true) {
				a.Logger.Debugln("sec2Heartbeat already running, skipping tick")
				continue
			}
			go func() {
				defer sec2Running.Store(false)
				a.guard("sec2Heartbeat", func() {
					a.sec2Heartbeat(time.Now())
					a.renewClientCert(time.Now())
				})
			}()
		}
	}
}

// certRetryAfter: the pause after the server answered 409 (mTLS off), 403
// (the current certificate is needed) or 404 (no such endpoint yet).
const certRetryAfter = 6 * time.Hour

// renewClientCert asks for a client certificate, with a fresh key, when the
// agent has none or the renewal share of its lifetime is over (certDue).
// TLS reads the new one on the next handshake.
func (a *Agent) renewClientCert(now time.Time) {
	if !a.certMu.TryLock() {
		return
	}
	defer a.certMu.Unlock()
	if a.certUnsaved != nil {
		a.storeClientCert()
	}
	force := a.sec2.forceCert.Load()
	if now.Before(a.certRetry) && !force {
		return
	}
	if c := a.clientCert.Load(); c != nil && !certDue(c.Leaf, now, int(confMs(confCertRenewPct))) && !force {
		return
	}
	csr, key, err := newCSR(a.AgentID)
	if err != nil {
		a.Logger.Errorln("renewClientCert():", err)
		return
	}
	var res struct {
		Cert     string `json:"cert"`
		RenewPct int    `json:"renew_pct"`
	}
	r, err := a.rClient.R().SetBody(map[string]string{"csr": csr}).SetResult(&res).Post(fmt.Sprintf("/api/v3/%s/cert/", a.AgentID))
	if err != nil {
		a.Logger.Debugln("renewClientCert():", err)
		return
	}
	switch r.StatusCode() {
	case 403, 404, 409:
		a.certRetry = now.Add(certRetryAfter)
		a.sec2.forceCert.Store(false)
		a.Logger.Debugln("renewClientCert(): server answered", r.StatusCode())
		return
	}
	if !r.IsSuccess() {
		a.Logger.Debugln("renewClientCert(): server answered", r.StatusCode())
		return
	}
	c, err := keyPair(res.Cert, key)
	if err != nil {
		a.Logger.Errorln("renewClientCert():", err)
		return
	}
	// the server has revoked the previous certificate: use the new one even
	// when it cannot be stored
	a.clientCert.Store(c)
	a.sec2.forceCert.Store(false)
	a.certUnsaved = map[string]string{confClientCert: res.Cert, confClientKey: key}
	if res.RenewPct > 0 {
		a.certUnsaved[confCertRenewPct] = strconv.Itoa(res.RenewPct)
	}
	a.storeClientCert()
	a.Logger.Infoln("Client certificate valid until", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

// storeClientCert writes the renewed pair to the config. Until that works
// every heartbeat tries again: after a restart the agent would load the
// revoked certificate.
func (a *Agent) storeClientCert() {
	kv := make(map[string]string, len(a.certUnsaved))
	for k, v := range a.certUnsaved {
		kv[k] = v
	}
	err := sealValues(kv)
	if err == nil {
		err = setConfValues(kv)
	}
	if err != nil {
		a.Logger.Errorln("renewClientCert(): store:", err)
		return
	}
	a.certUnsaved = nil
}

// confCertRenewPct is the share of the lifetime, in percent, after which the
// server wants the certificate renewed; it comes with every certificate.
const confCertRenewPct = "CertRenewPct"

// certDue: no certificate, or pct percent of its lifetime are over; two
// thirds without a valid pct.
func certDue(leaf *x509.Certificate, now time.Time, pct int) bool {
	if leaf == nil {
		return true
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	if pct < 10 || pct > 90 {
		return now.After(leaf.NotBefore.Add(life * 2 / 3))
	}
	return now.After(leaf.NotBefore.Add(life / 100 * time.Duration(pct)))
}

// Check-in at service start, with the stop reason and the uninstall code when
// the server has not taken them yet.
func (a *Agent) AgentStartup(report map[string]interface{}) {
	body := map[string]interface{}{"agent_id": a.AgentID}
	for k, v := range report {
		body[k] = v
	}
	r, err := a.rClient.R().SetBody(body).Post("/api/v3/checkin/")
	if err != nil {
		a.Logger.Debugln("AgentStartup():", err)
		return
	}
	if r.IsSuccess() {
		a.startupReported(report)
		var ans struct {
			Rotate []string `json:"rotate"`
			NowMs  int64    `json:"now_ms"`
		}
		if json.Unmarshal(r.Body(), &ans) == nil && a.registered() {
			a.learnClock(ans.NowMs)
			a.setRotate(ans.Rotate)
		}
	}
}

// minCheckInterval keeps a broken server answer from spinning the loop.
const minCheckInterval = 15

// 120 s, with an error, when the server cannot be asked. The answer is
// also the periodic channel for what the server asks a registered agent
// to rotate, and for the server time.
func (a *Agent) GetCheckInterval() (int, error) {
	var info struct {
		Agent    int      `json:"agent"`
		Interval int      `json:"check_interval"`
		Rotate   []string `json:"rotate"`
		NowMs    int64    `json:"now_ms"`
	}
	r, err := a.rClient.R().SetResult(&info).Get(fmt.Sprintf("/api/v3/%s/checkinterval/", a.AgentID))
	if err != nil {
		return 120, err
	}
	if r.IsError() {
		return 120, fmt.Errorf("checkinterval answered %d", r.StatusCode())
	}
	if a.registered() {
		a.learnClock(info.NowMs)
		a.setRotate(info.Rotate)
	}
	if info.Interval < minCheckInterval {
		return minCheckInterval, nil
	}
	return info.Interval, nil
}

// Due checks for the life of the service: a child process on Windows, in-process
// elsewhere.
func (a *Agent) CheckRunner() {
	sleepSeconds(randRange(14, 22))
	for {
		interval, err := a.GetCheckInterval()
		if err != nil {
			a.Logger.Debugln("CheckRunner():", err)
		} else if !a.ChecksRunning() {
			if runtime.GOOS == "windows" {
				if _, err := CMD(a.EXE, []string{"-m", "checkrunner"}, checkRunnerBudget); err != nil {
					a.Logger.Errorln("Checkrunner RunChecks", err)
				}
			} else {
				a.guard("RunChecks", func() {
					if err := a.RunChecks(false); err != nil {
						a.Logger.Debugln("Checkrunner RunChecks", err)
					}
				})
			}
		}
		a.Logger.Debugln("Checkrunner sleeping for", interval)
		sleepSeconds(interval)
	}
}
