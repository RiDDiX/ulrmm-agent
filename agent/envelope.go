// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/chacha20poly1305"
)

// Command envelopes (sec2). A command on the agent's subject is a msgpack
// map signed with a command key of the pin document and encrypted with the
// session key; the answer is encrypted and signed with the identity key.
// Without "v" it is a plaintext command, which an armed agent refuses.

// refusals the agent reports, at most one event per reason in this time
const refusalEvery = 10 * time.Minute

type sec2State struct {
	ident atomic.Pointer[identity]
	// the kid the server acknowledged, "" while not registered
	kid atomic.Pointer[string]
	// server time minus local time in ms, learned from REST answers only
	offset atomic.Int64
	// the access token after a grant or refresh in this process
	access atomic.Pointer[string]
	// the NATS connection logged in with the nkey
	nkeyLogin atomic.Bool
	// rotations the server asked for (cert, token, identity)
	rotate atomic.Pointer[[]string]

	mu        sync.Mutex
	sessions  []*session
	nonces    nonceLRU
	sids      map[[16]byte]time.Time
	refusedAt map[string]time.Time

	credMu     sync.Mutex
	regRetry   time.Time
	noEndpoint bool
	recoverAt  time.Time
	pinsAt     time.Time
	forceCert  atomic.Bool
	refreshBad atomic.Bool
	// the server answered a grant with 409: a family exists
	grantRefused atomic.Bool
}

type envelope struct {
	V int    `codec:"v"`
	Y string `codec:"y"`
	K string `codec:"k"`
	S []byte `codec:"s"`
	E int64  `codec:"e"`
	Q int64  `codec:"q"`
	T int64  `codec:"t"`
	N []byte `codec:"n"`
	C []byte `codec:"c"`
	G []byte `codec:"g"`
}

// cmdCtx is what the answer to a command needs. It keeps the keys of its
// session and epoch, so the answer goes out even when a newer handshake or
// the age limit ended the session in the meantime (the server keeps the
// keys of the request too).
type cmdCtx struct {
	sid [16]byte
	e   uint32
	q   uint64
	s   *session
	k   *epochKeys
}

// binHandle writes []byte as msgpack bin and strings as str: envelope
// fields are binary. The payload inside keeps encodeMsgpack.
var binHandle = &codec.MsgpackHandle{WriteExt: true}

func encodeBin(v interface{}) []byte {
	var b []byte
	_ = codec.NewEncoderBytes(&b, binHandle).Encode(v)
	return b
}

func decodeEnvelope(data []byte) (*envelope, bool) {
	var env envelope
	mh := codec.MsgpackHandle{}
	if err := codec.NewDecoderBytes(data, &mh).Decode(&env); err != nil || env.V == 0 {
		return nil, false
	}
	return &env, true
}

func cmdHeader(agentID, y, kid string, s []byte, e uint32, q, t uint64, n []byte) []byte {
	b := append([]byte("ulrmm-cmd-v2\x00"), agentID...)
	b = append(b, 0)
	b = append(b, y...)
	b = append(b, 0)
	b = append(b, kid...)
	var sid [16]byte
	copy(sid[:], s)
	b = append(b, sid[:]...)
	b = binary.BigEndian.AppendUint32(b, e)
	b = binary.BigEndian.AppendUint64(b, q)
	b = binary.BigEndian.AppendUint64(b, t)
	return append(b, n...)
}

func replyHeader(agentID string, sid []byte, e uint32, q, reqQ uint64) []byte {
	b := append([]byte("ulrmm-rsp-v2\x00"), agentID...)
	b = append(b, 0)
	b = append(b, sid...)
	b = binary.BigEndian.AppendUint32(b, e)
	b = binary.BigEndian.AppendUint64(b, q)
	return binary.BigEndian.AppendUint64(b, reqQ)
}

func frameHeader(subject string, sid []byte, e uint32, q uint64) []byte {
	b := append([]byte("ulrmm-frm-v2\x00"), subject...)
	b = append(b, 0)
	b = append(b, sid...)
	b = binary.BigEndian.AppendUint32(b, e)
	return binary.BigEndian.AppendUint64(b, q)
}

func aeadNonce(e uint32, q uint64) []byte {
	return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint32(nil, e), q)
}

func signedBytes(h, c []byte) []byte {
	sum := sha256.Sum256(c)
	return append(append([]byte(nil), h...), sum[:]...)
}

func seal(key, nonce, plain, aad []byte) []byte {
	a, _ := chacha20poly1305.New(key)
	return a.Seal(nil, nonce, plain, aad)
}

func unseal(key, nonce, c, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, c, aad)
}

// opened is a verified envelope: a command payload or a handshake answer.
type opened struct {
	plain []byte
	ctx   *cmdCtx
	hs2   map[string]interface{}
	hs1   *hs1Body
}

// hsInput is what the handshake answer needs from the agent.
type hsInput struct {
	cfp, version string
	pinSeq       int64
	ephemeral    []byte
}

// open checks an envelope in the order of the contract; the reason of a
// refusal is one of signature, kid, clock, session, replay, decrypt.
// Nothing of the payload is decoded before the AEAD opened it.
func (st *sec2State) open(agentID string, env *envelope, pins *pinSet, now time.Time, hs func() hsInput) (*opened, string) {
	if env.V != 2 || len(env.N) != 16 || len(env.G) != ed25519.SignatureSize ||
		env.E < 0 || env.E > math.MaxUint32 || env.Q < 0 || env.T < 0 {
		return nil, "signature"
	}
	pub := pins.cmdKey(env.K)
	if len(pub) != ed25519.PublicKeySize {
		return nil, "kid"
	}
	e, q := uint32(env.E), uint64(env.Q)
	h := cmdHeader(agentID, env.Y, env.K, env.S, e, q, uint64(env.T), env.N)
	if !ed25519.Verify(pub, signedBytes(h, env.C), env.G) {
		return nil, "signature"
	}
	srvNow := now.UnixMilli() + st.offset.Load()
	if d := env.T - srvNow; d > e2eClockWindow.Milliseconds() || -d > e2eClockWindow.Milliseconds() {
		return nil, "clock"
	}
	var n [16]byte
	copy(n[:], env.N)
	st.mu.Lock()
	defer st.mu.Unlock()
	switch env.Y {
	case "hs1":
		if st.nonces.has(n, now) {
			return nil, "replay"
		}
		var body hs1Body
		if err := codec.NewDecoderBytes(env.C, &codec.MsgpackHandle{}).Decode(&body); err != nil {
			return nil, "session"
		}
		id := st.ident.Load()
		if id == nil {
			return nil, "session"
		}
		in := hs()
		ans, why := st.answerHandshake(id, agentID, &body, in.cfp, in.version, in.pinSeq, srvNow, in.ephemeral, now)
		if why != "" {
			return nil, why
		}
		st.nonces.add(n, now)
		return &opened{hs2: ans, hs1: &body}, ""
	case "cmd":
	default:
		return nil, "signature"
	}
	s := st.session(env.S, now)
	if s == nil || !s.usable(e, now) {
		return nil, "session"
	}
	k := s.epoch(e)
	if k == nil || k.inMsgs >= e2eCapMessages || k.inBytes+int64(len(env.C)) > e2eCapBytes {
		return nil, "session"
	}
	if !k.win.ok(q) {
		return nil, "replay"
	}
	if st.nonces.has(n, now) {
		return nil, "replay"
	}
	plain, err := unseal(k.s2a, aeadNonce(e, q), env.C, h)
	if err != nil {
		return nil, "decrypt"
	}
	k.win.mark(q)
	k.inMsgs++
	k.inBytes += int64(len(env.C))
	st.nonces.add(n, now)
	if e == s.cur+1 {
		s.advance(e, now)
	}
	return &opened{plain: plain, ctx: &cmdCtx{sid: s.sid, e: e, q: q, s: s, k: k}}, ""
}

// sealReply is the answer to a command in its session and epoch.
func (st *sec2State) sealReply(agentID string, c *cmdCtx, plain []byte, now time.Time) ([]byte, bool) {
	id := st.ident.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	k := c.k
	if k == nil || id == nil || k.outQ >= e2eCapMessages {
		return nil, false
	}
	k.outQ++
	k.outBytes += int64(len(plain))
	h := replyHeader(agentID, c.sid[:], c.e, k.outQ, c.q)
	ct := seal(k.a2s, aeadNonce(c.e, k.outQ), plain, h)
	return encodeBin(map[string]interface{}{
		"v": 2, "s": c.sid[:], "e": c.e, "q": k.outQ, "c": ct, "g": id.sign(signedBytes(h, ct)),
	}), true
}

// sealFrame encrypts stream or terminal output in the newest session, or
// in the session of the command c when none is left. It moves to the next
// epoch once this direction reached the server's limits.
func (st *sec2State) sealFrame(c *cmdCtx, subject string, plain []byte, now time.Time) ([]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.newest(now)
	if s == nil && c != nil {
		s = c.s
	}
	if s == nil {
		return nil, false
	}
	k := s.epoch(s.cur)
	if k.outQ >= e2eRekeyMessages || k.outBytes >= e2eRekeyBytes {
		s.advance(s.cur+1, now)
		k = s.epoch(s.cur)
	}
	k.outQ++
	k.outBytes += int64(len(plain))
	h := frameHeader(subject, s.sid[:], s.cur, k.outQ)
	return encodeBin(map[string]interface{}{
		"v": 2, "s": s.sid[:], "e": s.cur, "q": k.outQ, "c": seal(k.a2s, aeadNonce(s.cur, k.outQ), plain, h),
	}), true
}

// refusedNow reports whether an event for reason is due.
func (st *sec2State) refusedNow(reason string, now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.refusedAt == nil {
		st.refusedAt = map[string]time.Time{}
	}
	if t, ok := st.refusedAt[reason]; ok && now.Sub(t) < refusalEvery {
		return false
	}
	st.refusedAt[reason] = now
	return true
}

// frameAgent is the agent of the service process; output frames of
// streams and terminals are sealed in its session.
var frameAgent atomic.Pointer[Agent]

// frameModes holds, by output subject, the command that started a stream
// or a terminal: its *cmdCtx when it came sealed, a nil one in the clear.
// The server reads the output the way it sent the command.
var frameModes sync.Map

// framesOf records the mode of r for the output on subject.
func (r *rpcReq) framesOf(subject string) { frameModes.Store(subject, r.ctx) }

// forgetFrames drops the mode of subject after the last frames went out.
func forgetFrames(subject string, after time.Duration) {
	time.AfterFunc(after, func() { frameModes.Delete(subject) })
}

// publishFrame sends stream or terminal output.
func publishFrame(nc *nats.Conn, subject string, v interface{}) error {
	b, err := frameBytes(frameAgent.Load(), subject, v, time.Now())
	if err != nil {
		return err
	}
	return nc.Publish(subject, b)
}

// frameBytes seals the output of a sealed command. Output of a plaintext
// command stays plaintext, unless the agent got armed since: then, as for
// a sealed command without any session, nothing is sent. Output of no
// known command is sealed while the agent is armed.
func frameBytes(a *Agent, subject string, v interface{}, now time.Time) ([]byte, error) {
	b, err := encodeMsgpack(v)
	if err != nil || a == nil {
		return b, err
	}
	sealed := a.sec2Armed()
	var c *cmdCtx
	if m, ok := frameModes.Load(subject); ok {
		c, _ = m.(*cmdCtx)
		if c == nil && sealed {
			return nil, errors.New("plaintext output of an armed agent")
		}
		sealed = c != nil
	}
	if !sealed {
		return b, nil
	}
	if b, ok := a.sec2.sealFrame(c, subject, b, now); ok {
		return b, nil
	}
	return nil, errors.New("no session for the output")
}

// openRequest is the payload of a command: as it came while the agent is
// not armed and the command is plaintext, else from a verified envelope.
// Refused and handshake requests are answered here.
func (a *Agent) openRequest(msg *nats.Msg) ([]byte, *cmdCtx, bool) {
	env, isEnv := decodeEnvelope(msg.Data)
	if !isEnv {
		if a.sec2Armed() {
			// the server may have lowered sec2: a newer pin document disarms
			if a.sec2.refusedNow("pins", time.Now()) {
				go a.RefreshPins()
			}
			a.refuseRequest(msg, "unsigned_command", "unsigned", "unsigned command refused")
			return nil, nil, false
		}
		return msg.Data, nil, true
	}
	now := time.Now()
	o, why := a.sec2.open(a.AgentID, env, a.pins.Load(), now, a.hsInput)
	if why != "" {
		kind := "envelope_refused"
		if why == "clock" {
			kind = "clock_skew"
		}
		if why == "kid" && a.sec2.refusedNow("pins", now) {
			go a.RefreshPins()
		}
		a.refuseRequest(msg, kind, why, "envelope refused: "+why)
		return nil, nil, false
	}
	if o.hs2 != nil {
		a.setRotate(o.hs1.Rotate)
		if msg.Reply != "" {
			_ = msg.Respond(encodeBin(o.hs2))
		}
		return nil, nil, false
	}
	return o.plain, o.ctx, true
}

func (a *Agent) hsInput() hsInput {
	var seq int64
	if p := a.pins.Load(); p != nil {
		seq = p.Seq
	}
	return hsInput{cfp: a.clientCertFP(), version: a.Version, pinSeq: seq}
}

// refuseRequest answers with an error in the clear and reports the
// refusal at most once per reason in refusalEvery.
func (a *Agent) refuseRequest(msg *nats.Msg, kind, reason, text string) {
	a.Logger.Errorln("rpc:", text)
	if msg.Reply != "" {
		if b, err := encodeMsgpack(map[string]string{"error": text}); err == nil {
			_ = msg.Respond(b)
		}
	}
	if a.sec2.refusedNow(kind+":"+reason, time.Now()) {
		a.queueSecurityEvent(kind, "reason "+reason)
	}
}
