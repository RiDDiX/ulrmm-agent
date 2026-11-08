// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// Token family of a registered agent: a short-lived access token for REST
// and a single-use refresh token, both bound to the identity by signatures.
// The legacy token of the install is exchanged once (grant); an agent that
// was offline past both lifetimes comes back through recover.

const (
	confRefresh        = "Refresh"
	confAccessExpires  = "AccessExpires"
	confRefreshExpires = "RefreshExpires"
	confAccessIssued   = "AccessIssued"
	heartbeatEvery     = 5 * time.Minute
	recoverEvery       = 30 * time.Minute
	pinsEvery          = time.Hour
	// the share of the access lifetime after which it is refreshed
	refreshAt = 0.7
)

// noAuthKey marks requests that carry no token: the refresh token or the
// identity signature is the credential.
type noAuthKey struct{}

var noAuth = context.WithValue(context.Background(), noAuthKey{}, true)

type tokenAnswer struct {
	Access         string          `json:"access"`
	AccessExpires  json.RawMessage `json:"access_expires"`
	Refresh        string          `json:"refresh"`
	RefreshExpires json.RawMessage `json:"refresh_expires"`
	NowMs          int64           `json:"now_ms"`
	Cert           string          `json:"cert"`
	Detail         string          `json:"detail"`
}

// expiry reads an ISO 8601 time or epoch seconds/milliseconds as unix ms.
func expiry(raw json.RawMessage) int64 {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UnixMilli()
		}
		raw = json.RawMessage(s)
	}
	n, err := strconv.ParseFloat(string(raw), 64)
	switch {
	case err != nil || n <= 0:
		return 0
	case n < 1e12:
		return int64(n * 1000)
	}
	return int64(n)
}

// refreshSecret is the refresh token in use: a pair not written yet comes
// before the stored one.
func (a *Agent) refreshSecret() ([]byte, error) {
	if p := a.sec2.pending.Load(); p != nil {
		return []byte((*p)[confRefresh]), nil
	}
	return unprotect(confRefresh)
}

// haveRefresh: a refresh token is stored or pending. One the keystore
// cannot open now counts too: its refresh fails and is tried again, a
// grant is only for none or an unreadable one.
func (a *Agent) haveRefresh() bool {
	r, err := a.refreshSecret()
	return len(r) > 0 || (err != nil && !errors.Is(err, errUnwrap))
}

// tokenMs is a time of the pair in use.
func (a *Agent) tokenMs(name string) int64 {
	if p := a.sec2.pending.Load(); p != nil {
		n, _ := strconv.ParseInt((*p)[name], 10, 64)
		return n
	}
	return confMs(name)
}

// storeTokens writes the pair in one config write before it is used. The
// server has used the old refresh token up: when the write fails the pair
// is used anyway, and the heartbeat writes it again.
func (a *Agent) storeTokens(t *tokenAnswer, extra map[string]string) error {
	if t.Access == "" || t.Refresh == "" {
		return errors.New("the answer has no token pair")
	}
	issued := t.NowMs
	if issued <= 0 {
		issued = time.Now().UnixMilli()
	}
	kv := map[string]string{
		"Token":            t.Access,
		confRefresh:        t.Refresh,
		confAccessExpires:  strconv.FormatInt(expiry(t.AccessExpires), 10),
		confRefreshExpires: strconv.FormatInt(expiry(t.RefreshExpires), 10),
		confAccessIssued:   strconv.FormatInt(issued, 10),
	}
	for k, v := range extra {
		kv[k] = v
	}
	err := a.writeTokens(kv)
	// no learnClock: a refresh retried within the server's grace gets the
	// cached pair with the time of its first issue
	a.sec2.access.Store(&t.Access)
	a.sec2.refreshBad.Store(false)
	if a.pendingSecurityEvents() {
		go a.sendSecurityEvents()
	}
	return err
}

// writeTokens stores the plain values kv of a pair, or keeps them pending.
func (a *Agent) writeTokens(kv map[string]string) error {
	sealed := maps.Clone(kv)
	err := sealValues(sealed)
	if err == nil {
		err = setConfValues(sealed)
	}
	if err != nil {
		a.sec2.pending.Store(&kv)
		return err
	}
	a.sec2.pending.Store(nil)
	return nil
}

// storePending writes a pair whose config write failed once more.
func (a *Agent) storePending() {
	if a.sec2.pending.Load() == nil {
		return
	}
	a.sec2.credMu.Lock()
	defer a.sec2.credMu.Unlock()
	if p := a.sec2.pending.Load(); p != nil {
		if err := a.writeTokens(*p); err != nil {
			a.Logger.Errorln("token store:", err)
		}
	}
}

// confWriteOrder is the order in which a config without an atomic write
// (the Windows registry) stores kv. The refresh token goes first: a crash
// in between then leaves the new refresh token with the old access token,
// never the used refresh token with the new access token, which the server
// would take for a clone. Cleared values go last.
func confWriteOrder(kv map[string]string) []string {
	names := make([]string, 0, len(kv))
	for k := range kv {
		names = append(names, k)
	}
	rank := func(k string) int {
		switch {
		case k == confRefresh:
			return 0
		case kv[k] == "":
			return 2
		}
		return 1
	}
	sort.Slice(names, func(i, j int) bool {
		if ri, rj := rank(names[i]), rank(names[j]); ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	return names
}

func tsBytes(b []byte, ts int64) []byte { return binary.BigEndian.AppendUint64(b, uint64(ts)) }

func signedMsg(prefix, agentID string, parts ...[]byte) []byte {
	b := append([]byte(prefix), agentID...)
	b = append(b, 0)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// challenge is a single-use nonce of the server.
func (a *Agent) challenge(path string, withToken bool) ([]byte, string, error) {
	var res struct {
		Nonce string `json:"nonce"`
		NowMs int64  `json:"now_ms"`
	}
	req := a.rClient.R().SetResult(&res)
	if !withToken {
		req.SetContext(noAuth)
	}
	r, err := req.Get(path)
	if err != nil {
		return nil, "", err
	}
	if !r.IsSuccess() {
		return nil, "", fmt.Errorf("challenge: the server answered %d", r.StatusCode())
	}
	n, err := base64.StdEncoding.DecodeString(res.Nonce)
	if err != nil || len(n) != 32 {
		return nil, "", errors.New("challenge: no nonce in the answer")
	}
	a.learnClock(res.NowMs)
	return n, res.Nonce, nil
}

// grantToken exchanges the install token for a token family.
func (a *Agent) grantToken() bool { return a.grant(false) }

// grant asks for a new token family. identityOnly sends no token: inside
// a release window (after a quarantine or a restored database) the server
// takes the identity signature alone, once. A 409 says a family exists:
// the grant is not tried again, the refresh token or recover is the way.
func (a *Agent) grant(identityOnly bool) bool {
	a.sec2.credMu.Lock()
	defer a.sec2.credMu.Unlock()
	id := a.sec2.ident.Load()
	if id == nil || !a.registered() || (!identityOnly && a.sec2.grantRefused.Load()) {
		return false
	}
	nonce, nonceText, err := a.challenge(fmt.Sprintf("/api/v3/%s/token/challenge/", a.AgentID), !identityOnly)
	if err != nil {
		a.Logger.Debugln("token grant:", err)
		return false
	}
	ts := a.serverNowMs()
	sig := id.sign(signedMsg("ulrmm-grant-v1\x00", a.AgentID, nonce, tsBytes(nil, ts)))
	var t tokenAnswer
	req := a.rClient.R()
	if identityOnly {
		req.SetContext(noAuth)
	}
	r, err := req.SetBody(map[string]interface{}{
		"nonce": nonceText, "ts": ts, "sig": base64.StdEncoding.EncodeToString(sig),
	}).SetResult(&t).Post(fmt.Sprintf("/api/v3/%s/token/grant/", a.AgentID))
	if err == nil && r.StatusCode() == 409 {
		a.sec2.grantRefused.Store(true)
		a.sec2.refreshBad.Store(true)
	}
	if err != nil || !r.IsSuccess() {
		a.Logger.Errorln("token grant: failed", err, statusOf(r))
		return false
	}
	if err := a.storeTokens(&t, nil); err != nil {
		a.Logger.Errorln("token grant: store:", err)
		return false
	}
	a.sec2.grantRefused.Store(false)
	a.Logger.Infoln("Token family issued")
	return true
}

// refreshToken swaps the refresh token for a new pair. When the server
// refuses it: expired, recover at once; unknown or revoked (released after
// a quarantine, a restored database), a grant on the identity signature
// alone, which works inside a release window, else recover.
func (a *Agent) refreshToken() bool {
	ok, refused := a.refreshPair()
	if ok || refused == "" {
		return ok
	}
	now := time.Now()
	if !strings.Contains(refused, "token expired") && a.sec2.refusedNow("grant", now) && a.grant(true) {
		a.certAfterGrant()
		return true
	}
	return a.recoverDue(now) && a.recoverAgent(now)
}

// refreshPair is the refresh call; refused is the answer to a 401.
func (a *Agent) refreshPair() (ok bool, refused string) {
	if !a.sec2.credMu.TryLock() {
		return false, ""
	}
	defer a.sec2.credMu.Unlock()
	id := a.sec2.ident.Load()
	ref, err := a.refreshSecret()
	if id == nil || err != nil || len(ref) == 0 {
		return false, ""
	}
	sum := sha256.Sum256(ref)
	var t tokenAnswer
	var r *resty.Response
	for try := 0; ; try++ {
		ts := a.serverNowMs()
		sig := id.sign(signedMsg("ulrmm-refresh-v1\x00", a.AgentID, sum[:], tsBytes(nil, ts)))
		t = tokenAnswer{}
		r, err = a.rClient.R().SetContext(noAuth).SetBody(map[string]interface{}{
			"refresh": string(ref), "ts": ts, "sig": base64.StdEncoding.EncodeToString(sig),
		}).SetResult(&t).Post(fmt.Sprintf("/api/v3/%s/token/refresh/", a.AgentID))
		if err != nil {
			a.Logger.Debugln("token refresh:", err)
			return false, ""
		}
		// the server refuses the timestamp before it looks at the token and
		// names its time: once more with that
		if r.StatusCode() != 400 || try > 0 || json.Unmarshal(r.Body(), &t) != nil || t.Detail != "clock" || t.NowMs <= 0 {
			break
		}
		a.learnClock(t.NowMs)
	}
	switch {
	case r.StatusCode() == 401:
		a.sec2.refreshBad.Store(true)
		return false, r.String() + " "
	case !r.IsSuccess():
		a.Logger.Errorln("token refresh: the server answered", r.StatusCode())
	default:
		if err := a.storeTokens(&t, nil); err != nil {
			a.Logger.Errorln("token refresh: store:", err)
			return false, ""
		}
		return true, ""
	}
	return false, ""
}

// certAfterGrant: a release revoked the client certificate with the
// tokens, and NATS refuses it until a new one comes; the certificate view
// takes the revoked one for the renewal.
func (a *Agent) certAfterGrant() {
	if a.clientCert.Load() == nil {
		return
	}
	a.sec2.forceCert.Store(true)
	a.renewClientCert(time.Now())
}

func confMs(name string) int64 {
	s, _ := confValue(name)
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// refreshDue: 70 % of the access lifetime is used.
func refreshDue(issuedMs, expiresMs, nowMs int64) bool {
	if expiresMs <= 0 || issuedMs <= 0 || expiresMs <= issuedMs {
		return expiresMs > 0 && nowMs >= expiresMs
	}
	return nowMs >= issuedMs+int64(float64(expiresMs-issuedMs)*refreshAt)
}

// recoverDue: the client certificate expired, or the refresh token is gone
// or expired, and the last try is 30 minutes ago.
func (a *Agent) recoverDue(now time.Time) bool {
	if !a.registered() || now.UnixMilli() < a.sec2.recoverAt.Load() {
		return false
	}
	certGone := false
	if c := a.clientCert.Load(); c != nil && c.Leaf != nil && now.After(c.Leaf.NotAfter) {
		certGone = true
	}
	ref := a.tokenMs(confRefreshExpires)
	tokensGone := a.sec2.refreshBad.Load() || (ref > 0 && now.UnixMilli() > ref)
	return certGone || tokensGone
}

// recoverAgent brings an agent back that was offline past its certificate
// or tokens: the identity signature alone, within the server's grace.
func (a *Agent) recoverAgent(now time.Time) bool {
	a.sec2.recoverAt.Store(now.Add(recoverEvery).UnixMilli())
	a.sec2.credMu.Lock()
	defer a.sec2.credMu.Unlock()
	id := a.sec2.ident.Load()
	if id == nil {
		return false
	}
	nonce, nonceText, err := a.challenge(fmt.Sprintf("/api/v3/%s/recover/challenge/", a.AgentID), false)
	if err != nil {
		a.Logger.Debugln("recover:", err)
		return false
	}
	csr, key, err := newCSR(a.AgentID)
	if err != nil {
		return false
	}
	ts := a.serverNowMs()
	csrSum := sha256.Sum256([]byte(csr))
	sig := id.sign(signedMsg("ulrmm-recover-v1\x00", a.AgentID, nonce, tsBytes(nil, ts), csrSum[:]))
	var t tokenAnswer
	r, err := a.rClient.R().SetContext(noAuth).SetBody(map[string]interface{}{
		"nonce": nonceText, "ts": ts, "sig": base64.StdEncoding.EncodeToString(sig), "csr": csr,
	}).SetResult(&t).Post(fmt.Sprintf("/api/v3/%s/recover/", a.AgentID))
	if err != nil || !r.IsSuccess() {
		a.Logger.Errorln("recover: refused", err, statusOf(r))
		return false
	}
	extra := map[string]string{}
	if t.Cert != "" {
		c, err := keyPair(t.Cert, key)
		if err != nil {
			a.Logger.Errorln("recover:", err)
			return false
		}
		a.clientCert.Store(c)
		extra[confClientCert], extra[confClientKey] = t.Cert, key
	}
	if err := a.storeTokens(&t, extra); err != nil {
		a.Logger.Errorln("recover: store:", err)
		return false
	}
	a.Logger.Infoln("Recovered after the offline time")
	return true
}

func statusOf(r *resty.Response) string {
	if r == nil {
		return ""
	}
	return strconv.Itoa(r.StatusCode())
}

// sec2Heartbeat runs every 5 minutes in the service.
func (a *Agent) sec2Heartbeat(now time.Time) {
	if a.sec2.ident.Load() == nil {
		return
	}
	// before the registration: a server without the endpoint is asked again
	// once its pin document lists command keys
	if now.UnixMilli() > a.sec2.pinsAt.Load() {
		a.sec2.pinsAt.Store(now.Add(pinsEvery).UnixMilli())
		a.RefreshPins()
	}
	if a.registrationDue(now) {
		if ok, _ := a.registerIdentity(); ok && !a.sec2.nkeyLogin.Load() {
			a.restartForLogin()
		}
		return
	}
	if !a.registered() {
		return
	}
	a.storePending()
	if !a.haveRefresh() {
		a.grantToken()
	}
	if a.recoverDue(now) {
		a.recoverAgent(now)
	} else if refreshDue(a.tokenMs(confAccessIssued), a.tokenMs(confAccessExpires), a.serverNowMs()) {
		a.refreshToken()
	}
	a.doRotations()
}

// doRotations runs what the server asked for; the server drops an entry
// once it saw it done.
func (a *Agent) doRotations() {
	identity := a.sec2.rotRetry.Load()
	if p := a.sec2.rotate.Swap(nil); p != nil {
		for _, what := range *p {
			switch what {
			case "cert":
				a.sec2.forceCert.Store(true)
			case "token":
				a.refreshToken()
			case "identity":
				identity = true
			}
		}
	}
	// the restart ends this process before the service's renewal runs
	if identity && a.rotateIdentity() {
		if a.sec2.forceCert.Load() {
			a.renewClientCert(time.Now())
		}
		a.restartForLogin()
	}
}

// credentialAnswer reacts to what a REST answer says about the credential:
// an expired access token is refreshed, a revoked one (released after a
// quarantine) granted again, and an identity the admin reset replaced. A
// token the server does not know (its database restored from a backup)
// is refreshed, and recovered when the refresh token is unknown too.
// The identity registration handles its own answers.
func (a *Agent) credentialAnswer(url string, code int, body string) {
	if a.sec2.ident.Load() == nil || strings.HasSuffix(url, "/identity/") {
		return
	}
	now := time.Now()
	switch {
	case code == 401 && a.registered() && strings.Contains(body, `"refresh"`):
		go a.refreshToken()
	case code == 401 && a.registered() && strings.Contains(body, "token revoked"):
		if a.sec2.refusedNow("grant", now) {
			go func() {
				if a.grant(true) {
					a.certAfterGrant()
				}
			}()
		}
	case code == 401 && a.registered() && !strings.Contains(url, "/token/") && !strings.Contains(url, "/recover/") &&
		!strings.Contains(body, "client certificate") && a.sec2.refusedNow("unknown-token", now):
		go a.refreshToken()
	case code == 403 && strings.Contains(body, `"new_identity"`) && a.sec2.refusedNow("new-identity", now):
		go func() {
			if a.resetIdentity() {
				a.restartForLogin()
			}
		}()
	}
}
