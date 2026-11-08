// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Agent identity: one random master seed in the config (protect.go) from
// which the identity signing key, the static X25519 key and the NATS nkey
// are derived. The service makes it at its first start and registers the
// public keys with the server; from then on NATS takes the nkey instead of
// the token.

const (
	confIdentityKey  = "IdentityKey"
	confIdentityNext = "IdentityKeyNext"
	confIdentityKid  = "IdentityKid"
	identityPath     = "/api/v3/%s/identity/"
	identityRetry    = 30 * time.Minute
)

var identityBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second}

type identity struct {
	ed      ed25519.PrivateKey
	x       *ecdh.PrivateKey
	nkey    nkeys.KeyPair
	nkeyPub string
	kid     string
}

func deriveIdentity(m []byte) (*identity, error) {
	if len(m) != 32 {
		return nil, errors.New("the identity seed is not 32 bytes")
	}
	d := func(info string) []byte {
		k, _ := hkdf.Key(sha256.New, m, nil, info, 32)
		return k
	}
	x, err := ecdh.X25519().NewPrivateKey(d("ulrmm identity x25519 v1"))
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromRawSeed(nkeys.PrefixByteUser, d("ulrmm nats nkey v1"))
	if err != nil {
		return nil, err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	ed := ed25519.NewKeyFromSeed(d("ulrmm identity ed25519 v1"))
	return &identity{ed: ed, x: x, nkey: kp, nkeyPub: pub, kid: keyID(ed.Public().(ed25519.PublicKey))}, nil
}

func keyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

func (id *identity) edPub() []byte { return id.ed.Public().(ed25519.PublicKey) }

func (id *identity) sign(b []byte) []byte { return ed25519.Sign(id.ed, b) }

func newSeed() []byte {
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		panic(err)
	}
	return m
}

// loadIdentity reads the master seed or makes one. An unreadable seed (a
// DPAPI blob after a machine reset, a broken config) is replaced; the
// server then refuses the new keys until an admin resets the identity. A
// keystore or config that does not open now is no such case: the service
// goes on with the token and tries again at its next start.
func (a *Agent) loadIdentity() *identity {
	m, err := unprotect(confIdentityKey)
	if err == nil && m != nil && len(m) != 32 {
		err = errUnwrap
	}
	if err != nil {
		a.queueSecurityEvent("identity_unreadable", err.Error())
		if !errors.Is(err, errUnwrap) {
			a.Logger.Errorln("identity:", err)
			return nil
		}
		a.Logger.Errorln("identity:", err, "- making a new one")
		m = nil
	}
	if m == nil {
		m = newSeed()
		s, err := wrapSecret(confIdentityKey, m)
		if err == nil {
			err = setConfValues(map[string]string{confIdentityKey: s, confIdentityKid: ""})
		}
		if err != nil {
			a.Logger.Errorln("identity: cannot store it:", err)
			return nil
		}
	}
	id, err := deriveIdentity(m)
	if err != nil {
		a.Logger.Errorln("identity:", err)
		return nil
	}
	a.sec2.ident.Store(id)
	if kid, _ := confValue(confIdentityKid); kid != "" {
		a.sec2.kid.Store(&kid)
	}
	return id
}

// registered: the server acknowledged the identity in use.
func (a *Agent) registered() bool {
	id, kid := a.sec2.ident.Load(), a.sec2.kid.Load()
	return id != nil && kid != nil && *kid == id.kid
}

// sec2Armed: registered and the pin document turns signed commands on.
// From then on plaintext commands are refused.
func (a *Agent) sec2Armed() bool {
	if !a.registered() {
		return false
	}
	p := a.pins.Load()
	return p != nil && (p.Sec2 == "optional" || p.Sec2 == "required")
}

func (a *Agent) serverNowMs() int64 { return time.Now().UnixMilli() + a.sec2.offset.Load() }

// learnClock takes the server time of an authenticated REST answer.
func (a *Agent) learnClock(nowMs int64) {
	if nowMs > 0 {
		a.sec2.offset.Store(nowMs - time.Now().UnixMilli())
	}
}

func idregMsg(prefix, agentID string, id *identity, ts int64) []byte {
	b := append([]byte(prefix), agentID...)
	b = append(b, 0)
	b = append(append(b, id.edPub()...), id.x.PublicKey().Bytes()...)
	b = append(b, id.nkeyPub...)
	return binary.BigEndian.AppendUint64(b, uint64(ts))
}

type identityAnswer struct {
	Kid         string   `json:"kid"`
	State       string   `json:"state"`
	Sec2        string   `json:"sec2"`
	PinSeq      int64    `json:"pin_seq"`
	Rotate      []string `json:"rotate"`
	NowMs       int64    `json:"now_ms"`
	Detail      string   `json:"detail"`
	NewIdentity bool     `json:"new_identity"`
}

// postIdentity sends the keys of id; prev signs a rotation.
func (a *Agent) postIdentity(id, prev *identity) (int, *identityAnswer, error) {
	var ans identityAnswer
	for try := 0; ; try++ {
		ts := a.serverNowMs()
		body := map[string]interface{}{
			"ed25519": base64.StdEncoding.EncodeToString(id.edPub()),
			"x25519":  base64.StdEncoding.EncodeToString(id.x.PublicKey().Bytes()),
			"nkey":    id.nkeyPub,
			"caps":    identityCaps(),
			"idreg":   "",
			"ts":      ts,
			"sig":     base64.StdEncoding.EncodeToString(id.sign(idregMsg("ulrmm-idreg-v1\x00", a.AgentID, id, ts))),
		}
		nsig, err := id.nkey.Sign(idregMsg("ulrmm-idreg-v1\x00", a.AgentID, id, ts))
		if err != nil {
			return 0, nil, err
		}
		body["nsig"] = base64.StdEncoding.EncodeToString(nsig)
		if prev != nil {
			body["idreg"] = base64.StdEncoding.EncodeToString(prev.sign(idregMsg("ulrmm-idrot-v1\x00", a.AgentID, id, ts)))
		}
		ans = identityAnswer{}
		r, err := a.rClient.R().SetBody(body).Post(fmt.Sprintf(identityPath, a.AgentID))
		if err != nil {
			return 0, nil, err
		}
		_ = json.Unmarshal(r.Body(), &ans)
		if r.StatusCode() == 400 && ans.Detail == "clock" && ans.NowMs > 0 && try == 0 {
			a.learnClock(ans.NowMs)
			continue
		}
		if r.IsSuccess() {
			a.learnClock(ans.NowMs)
		}
		return r.StatusCode(), &ans, nil
	}
}

// registerIdentity registers the identity and reports whether the server
// took it and whether the request failed on the way. Afterwards the token
// is exchanged for a token family.
func (a *Agent) registerIdentity() (ok, netErr bool) {
	id := a.sec2.ident.Load()
	if id == nil || a.rClient == nil {
		return false, false
	}
	a.sec2.regRetry.Store(time.Now().Add(identityRetry).UnixMilli())
	code, ans, err := a.postIdentity(id, nil)
	if err != nil {
		a.Logger.Debugln("identity registration:", err)
		a.sec2.regRetry.Store(time.Now().Add(heartbeatEvery).UnixMilli())
		return false, true
	}
	a.sec2.noEndpoint.Store(code == 404)
	switch {
	case code == 200 || code == 201:
		if err := setConfValues(map[string]string{confIdentityKid: id.kid, confKeyStoreSent: keyStoreCap()}); err != nil {
			a.Logger.Errorln("identity registration: store:", err)
			return false, false
		}
		a.sec2.kid.Store(&id.kid)
		a.setRotate(ans.Rotate)
		a.Logger.Infoln("Agent identity", id.kid, "registered")
		if !a.haveRefresh() {
			a.grantToken()
		}
		return true, false
	case code == 403 && ans.NewIdentity:
		a.Logger.Warnln("identity registration: the server asks for a new identity")
		return a.resetIdentity(), false
	case code != 404:
		a.Logger.Errorf("identity registration: the server answered %d %s", code, ans.Detail)
	}
	return false, false
}

// resetIdentity drops the master seed for a new one (the admin reset the
// identity on the server) and registers it.
func (a *Agent) resetIdentity() bool {
	s, err := wrapSecret(confIdentityKey, newSeed())
	if err == nil {
		err = setConfValues(map[string]string{confIdentityKey: s, confIdentityKid: ""})
	}
	if err != nil {
		a.Logger.Errorln("identity reset:", err)
		return false
	}
	a.sec2.kid.Store(nil)
	id := a.loadIdentity()
	if id == nil {
		return false
	}
	code, ans, err := a.postIdentity(id, nil)
	if err != nil || (code != 200 && code != 201) {
		return false
	}
	if err := setConfValues(map[string]string{confIdentityKid: id.kid}); err != nil {
		return false
	}
	a.sec2.kid.Store(&id.kid)
	a.setRotate(ans.Rotate)
	a.grantToken()
	return true
}

// rotateIdentity replaces the keys, signed by the current identity. The new
// seed is kept as IdentityKeyNext until the server took it, so an answer
// lost on the way is retried with the same keys.
func (a *Agent) rotateIdentity() bool {
	prev := a.sec2.ident.Load()
	if prev == nil || !a.registered() {
		return false
	}
	m, err := unprotect(confIdentityNext)
	if err != nil && !errors.Is(err, errUnwrap) {
		// a new seed would lose the one the server may have taken already
		a.Logger.Errorln("identity rotation:", err)
		return false
	}
	if err != nil || len(m) != 32 {
		m = newSeed()
		if err := protect(confIdentityNext, m); err != nil {
			a.Logger.Errorln("identity rotation:", err)
			return false
		}
	}
	next, err := deriveIdentity(m)
	if err != nil {
		return false
	}
	code, ans, err := a.postIdentity(next, prev)
	// the server may have the new keys and no longer ask for them
	a.sec2.rotRetry.Store(err != nil || code >= 500)
	if err != nil || (code != 200 && code != 201) {
		a.Logger.Errorln("identity rotation: the server answered", code, err)
		return false
	}
	// the value name is part of the sealing: the seed is wrapped anew
	cur, err := wrapSecret(confIdentityKey, m)
	if err == nil {
		err = setConfValues(map[string]string{confIdentityKey: cur, confIdentityNext: "", confIdentityKid: next.kid})
	}
	if err != nil {
		a.Logger.Errorln("identity rotation: store:", err)
		a.sec2.rotRetry.Store(true)
		return false
	}
	a.sec2.ident.Store(next)
	a.sec2.kid.Store(&next.kid)
	a.setRotate(ans.Rotate)
	a.Logger.Infoln("Agent identity rotated to", next.kid)
	return true
}

// setupIdentity runs before the NATS connection of the service. Network
// errors are retried for a while, then the service goes on with the token.
func (a *Agent) setupIdentity() {
	a.setupKeystore()
	startConfigMAC()
	if a.loadIdentity() == nil {
		return
	}
	if a.registered() {
		// a rotation whose answer got lost or was not stored: the server
		// takes the same keys again
		if m, err := unprotect(confIdentityNext); err == nil && len(m) == 32 {
			a.rotateIdentity()
		}
		if !a.haveRefresh() {
			a.grantToken()
		} else if a.recoverDue(time.Now()) {
			// offline past the refresh lifetime
			a.recoverAgent(time.Now())
		}
	} else {
		for i := 0; ; i++ {
			ok, netErr := a.registerIdentity()
			if ok || !netErr || i >= len(identityBackoff) {
				break
			}
			time.Sleep(identityBackoff[i])
		}
	}
	if a.registered() {
		a.reportKeyStore()
		// the first sealed commands may need a newer pin document (command
		// keys, the sec2 claim) than the stored one
		a.sec2.pinsAt.Store(time.Now().Add(pinsEvery).UnixMilli())
		a.RefreshPins()
	}
}

func identityCaps() []string {
	if ks := keyStoreCap(); ks != "" {
		return []string{"sec2", ks}
	}
	return []string{"sec2"}
}

// reportKeyStore sends the keys once more when the keystore changed since
// the server took them: the same keys only update the capabilities.
func (a *Agent) reportKeyStore() {
	ks := keyStoreCap()
	if sent, _ := confValue(confKeyStoreSent); ks == "" || sent == ks {
		return
	}
	code, _, err := a.postIdentity(a.sec2.ident.Load(), nil)
	if err != nil || code != 200 && code != 201 {
		a.Logger.Debugln("identity: keystore not reported:", code, err)
		return
	}
	if err := setConfValues(map[string]string{confKeyStoreSent: ks}); err != nil {
		a.Logger.Errorln("identity: keystore:", err)
	}
}

// registrationDue: the heartbeat retries a registration that failed. A
// server without the endpoint is asked again once its pin document lists
// command keys.
func (a *Agent) registrationDue(now time.Time) bool {
	if a.sec2.ident.Load() == nil || a.registered() || now.UnixMilli() < a.sec2.regRetry.Load() {
		return false
	}
	return !a.sec2.noEndpoint.Load() || len(a.pins.Load().cmdKeys()) > 0
}

// natsAuth is the login of the NATS connection: the nkey once the server
// took the identity (on the path that names the agent), else the token.
func (a *Agent) natsAuth() []nats.Option {
	id := a.sec2.ident.Load()
	if id == nil {
		id = a.storedIdentity()
	}
	kid := a.sec2.kid.Load()
	if id != nil && kid != nil && *kid == id.kid {
		a.sec2.nkeyLogin.Store(true)
		kp := id.nkey
		return []nats.Option{
			nats.Nkey(id.nkeyPub, func(nonce []byte) ([]byte, error) { return kp.Sign(nonce) }),
			nats.ProxyPath(a.NatsProxyPath + "/" + a.AgentID),
		}
	}
	a.sec2.nkeyLogin.Store(false)
	return []nats.Option{nats.UserInfo(a.AgentID, a.Token), nats.ProxyPath(a.NatsProxyPath)}
}

// storedIdentity reads the identity without making one (-m checkin and
// other runs outside the service).
func (a *Agent) storedIdentity() *identity {
	m, err := unprotect(confIdentityKey)
	if err != nil || len(m) != 32 {
		return nil
	}
	id, err := deriveIdentity(m)
	if err != nil {
		return nil
	}
	if kid, _ := confValue(confIdentityKid); kid != "" {
		a.sec2.kid.Store(&kid)
	}
	return id
}

// clientCertFP is the SHA-1 of the client certificate in use, "" without one.
func (a *Agent) clientCertFP() string {
	c := a.clientCert.Load()
	if c == nil || len(c.Certificate) == 0 {
		return ""
	}
	sum := sha1.Sum(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func (a *Agent) setRotate(r []string) {
	if len(r) > 0 {
		a.sec2.rotate.Store(&r)
	}
}

// On Windows a stop from inside the service ends the process before the
// start runs. An unclean exit instead lets the recovery actions of the
// service (protectService) start it again.
var (
	restartByExit = runtime.GOOS == "windows"
	exitProcess   = os.Exit
)

// restartForLogin restarts the service when the NATS login method changed
// (a registration or key rotation while connected).
func (a *Agent) restartForLogin() {
	a.Logger.Infoln("Restarting the service for the new NATS login")
	expectStop(a.dataDir())
	if restartByExit {
		exitProcess(1)
		return
	}
	if err := newHealPlatform(a).restartService(); err != nil {
		a.Logger.Errorln("restart:", err)
	}
}
