// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/ugorji/go/codec"
)

type sec2Vectors struct {
	AgentID    string `json:"agent_id"`
	T          int64  `json:"t"`
	CommandKey struct {
		Seed, Ed25519, Kid string
	} `json:"command_key"`
	Identity struct {
		Master       string `json:"master"`
		Ed25519      string `json:"ed25519"`
		X25519       string `json:"x25519"`
		NkeyPublic   string `json:"nkey_public"`
		Nkey         string `json:"nkey"`
		Kid          string `json:"kid"`
		IdregMessage string `json:"idreg_message"`
		IdregTs      int64  `json:"idreg_ts"`
		Sig          string `json:"sig"`
		Nsig         string `json:"nsig"`
	} `json:"identity"`
	Hs1 struct {
		Sid, Es, Header, Sig string
		Body                 string `json:"body_msgpack"`
		Envelope             string `json:"envelope_msgpack_py"`
	} `json:"hs1"`
	Hs2 struct {
		EaSeed string `json:"ea_seed"`
		Ea     string `json:"ea"`
		Cfp    string `json:"cfp"`
		PinSeq int64  `json:"pin_seq"`
		Ver    string `json:"ver"`
		Ts     int64  `json:"ts"`
		Signed string `json:"signed"`
		Sig    string `json:"sig"`
	} `json:"hs2"`
	Keys struct {
		Shared string `json:"shared"`
		KS2A   string `json:"k_s2a"`
		KA2S   string `json:"k_a2s"`
		KS2AE1 string `json:"k_s2a_e1"`
		KA2SE1 string `json:"k_a2s_e1"`
	} `json:"keys"`
	Cmd struct {
		E, Q                        int64
		Nonce, Plaintext, Header, C string
		Sig                         string
		Envelope                    string `json:"envelope_msgpack_py"`
	} `json:"cmd"`
	CmdE1 struct {
		E, Q                 int64
		Plaintext, Header, C string
	} `json:"cmd_e1"`
	Reply struct {
		E, Q                      int64
		RequestQ                  int64 `json:"request_q"`
		Plaintext, Header, C, Sig string
	} `json:"reply"`
	Frame struct {
		Subject              string
		E, Q                 int64
		Plaintext, Header, C string
	} `json:"frame"`
	Sealed struct {
		Path, Plaintext, Key, C, Signed, Sig string
		T                                    int64
		Body                                 json.RawMessage
	} `json:"sealed"`
}

func loadVectors(t *testing.T) *sec2Vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/sec2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v sec2Vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func eqHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s:\n got %x\nwant %s", name, got, want)
	}
}

// sec2Agent is an agent with the vector identity, registered and armed,
// whose pin document lists the vector command key.
func sec2Agent(t *testing.T, v *sec2Vectors) (*Agent, ed25519.PrivateKey) {
	t.Helper()
	id, err := deriveIdentity(unhex(t, v.Identity.Master))
	if err != nil {
		t.Fatal(err)
	}
	cmd := ed25519.NewKeyFromSeed(unhex(t, v.CommandKey.Seed))
	a := &Agent{AgentID: v.AgentID, Logger: logrus.New(), Version: v.Hs2.Ver}
	a.Logger.SetOutput(io.Discard)
	a.sec2.ident.Store(id)
	a.sec2.kid.Store(&id.kid)
	a.pins.Store(&pinSet{Seq: v.Hs2.PinSeq, Sec2: "optional", Cmd: []cmdKey{{
		Kid: keyID(cmd.Public().(ed25519.PublicKey)), Ed: base64.StdEncoding.EncodeToString(cmd.Public().(ed25519.PublicKey)), State: "current",
	}}})
	return a, cmd
}

func vecNow(v *sec2Vectors) time.Time { return time.UnixMilli(v.T) }

func vecHs(t *testing.T, v *sec2Vectors) func() hsInput {
	return func() hsInput {
		return hsInput{cfp: v.Hs2.Cfp, version: v.Hs2.Ver, pinSeq: v.Hs2.PinSeq, ephemeral: unhex(t, v.Hs2.EaSeed)}
	}
}

// srvEnvelope is what the server sends: signed header, ciphertext (or the
// hs1 body in clear).
func srvEnvelope(cmd ed25519.PrivateKey, agentID, y string, s []byte, e uint32, q uint64, tms int64, n, c []byte) []byte {
	kid := keyID(cmd.Public().(ed25519.PublicKey))
	h := cmdHeader(agentID, y, kid, s, e, q, uint64(tms), n)
	return encodeBin(map[string]interface{}{
		"v": 2, "y": y, "k": kid, "s": s, "e": e, "q": q, "t": tms, "n": n, "c": c,
		"g": ed25519.Sign(cmd, signedBytes(h, c)),
	})
}

func srvCmd(cmd ed25519.PrivateKey, agentID string, sid []byte, key []byte, e uint32, q uint64, tms int64, n, plain []byte) []byte {
	h := cmdHeader(agentID, "cmd", keyID(cmd.Public().(ed25519.PublicKey)), sid, e, q, uint64(tms), n)
	return srvEnvelope(cmd, agentID, "cmd", sid, e, q, tms, n, seal(key, aeadNonce(e, q), plain, h))
}

func openBytes(a *Agent, b []byte, now time.Time, hs func() hsInput) (*opened, string) {
	env, ok := decodeEnvelope(b)
	if !ok {
		return nil, "not an envelope"
	}
	return a.sec2.open(a.AgentID, env, a.pins.Load(), now, hs)
}

func handshake(t *testing.T, a *Agent, cmd ed25519.PrivateKey, sid []byte, now time.Time, n byte) (s2a, a2s []byte) {
	t.Helper()
	es, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{n}, 32))
	body := encodeBin(map[string]interface{}{"sid": sid, "es": es.PublicKey().Bytes(), "ts": now.UnixMilli()})
	o, why := openBytes(a, srvEnvelope(cmd, a.AgentID, "hs1", nil, 0, 0, now.UnixMilli(), bytes.Repeat([]byte{n}, 16), body), now, a.hsInput)
	if why != "" {
		t.Fatal("hs1 refused:", why)
	}
	ea, _ := ecdh.X25519().NewPublicKey(o.hs2["ea"].([]byte))
	shared, _ := es.ECDH(ea)
	s2a, a2s, _ = sessionKeys(shared, sid, a.AgentID, es.PublicKey().Bytes(), ea.Bytes())
	return
}

// Every byte of the shared vectors: derivation, registration, handshake,
// command, reply, frame, ratchet, sealed REST body.
func TestSec2SharedVectors(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	id := a.sec2.ident.Load()
	eqHex(t, "command ed25519", cmd.Public().(ed25519.PublicKey), v.CommandKey.Ed25519)
	if k := keyID(cmd.Public().(ed25519.PublicKey)); k != v.CommandKey.Kid {
		t.Errorf("command kid %s", k)
	}
	eqHex(t, "identity ed25519", id.edPub(), v.Identity.Ed25519)
	eqHex(t, "identity x25519", id.x.PublicKey().Bytes(), v.Identity.X25519)
	if id.nkeyPub != v.Identity.Nkey || id.kid != v.Identity.Kid {
		t.Errorf("nkey %s kid %s", id.nkeyPub, id.kid)
	}
	msg := idregMsg("ulrmm-idreg-v1\x00", v.AgentID, id, v.Identity.IdregTs)
	eqHex(t, "idreg message", msg, v.Identity.IdregMessage)
	eqHex(t, "idreg sig", id.sign(msg), v.Identity.Sig)
	nsig, _ := id.nkey.Sign(msg)
	eqHex(t, "idreg nsig", nsig, v.Identity.Nsig)

	now := vecNow(v)
	eqHex(t, "hs1 header", cmdHeader(v.AgentID, "hs1", v.CommandKey.Kid, nil, 0, 0, uint64(v.T), bytes.Repeat([]byte{6}, 16)), v.Hs1.Header)
	o, why := openBytes(a, unhex(t, v.Hs1.Envelope), now, vecHs(t, v))
	if why != "" {
		t.Fatal("hs1 refused:", why)
	}
	eqHex(t, "hs2 ea", o.hs2["ea"].([]byte), v.Hs2.Ea)
	signed := hs2Signed(v.AgentID, unhex(t, v.Hs1.Sid), unhex(t, v.Hs1.Es), unhex(t, v.Hs2.Ea), v.Hs2.Cfp, v.Hs2.PinSeq, v.Hs2.Ts)
	eqHex(t, "hs2 signed", signed, v.Hs2.Signed)
	eqHex(t, "hs2 sig", o.hs2["g"].([]byte), v.Hs2.Sig)
	s := a.sec2.sessions[0]
	eqHex(t, "k_s2a", s.epochs[0].s2a, v.Keys.KS2A)
	eqHex(t, "k_a2s", s.epochs[0].a2s, v.Keys.KA2S)
	eqHex(t, "k_s2a e1", ratchetKey(s.epochs[0].s2a, 1), v.Keys.KS2AE1)
	eqHex(t, "k_a2s e1", ratchetKey(s.epochs[0].a2s, 1), v.Keys.KA2SE1)

	// the server's msgpack of the command decodes and opens; the vectors
	// use one nonce for hs1 and the command
	a.sec2.nonces = nonceLRU{}
	o, why = openBytes(a, unhex(t, v.Cmd.Envelope), now, nil)
	if why != "" {
		t.Fatal("cmd refused:", why)
	}
	eqHex(t, "cmd plaintext", o.plain, v.Cmd.Plaintext)
	eqHex(t, "cmd header", cmdHeader(v.AgentID, "cmd", v.CommandKey.Kid, unhex(t, v.Hs1.Sid), 0, 1, uint64(v.T), unhex(t, v.Cmd.Nonce)), v.Cmd.Header)

	// answer "pong" to q 1, then a terminal frame takes agent seq 2
	rep, ok := a.sec2.sealReply(v.AgentID, o.ctx, unhex(t, v.Reply.Plaintext), now)
	if !ok {
		t.Fatal("no reply")
	}
	var r map[string]interface{}
	_ = codec.NewDecoderBytes(rep, &codec.MsgpackHandle{}).Decode(&r)
	eqHex(t, "reply header", replyHeader(v.AgentID, unhex(t, v.Hs1.Sid), 0, 1, 1), v.Reply.Header)
	eqHex(t, "reply c", r["c"].([]byte), v.Reply.C)
	eqHex(t, "reply sig", r["g"].([]byte), v.Reply.Sig)
	fr, _ := a.sec2.sealFrame(nil, v.Frame.Subject, unhex(t, v.Frame.Plaintext), now)
	r = nil
	_ = codec.NewDecoderBytes(fr, &codec.MsgpackHandle{}).Decode(&r)
	eqHex(t, "frame header", frameHeader(v.Frame.Subject, unhex(t, v.Hs1.Sid), 0, 2), v.Frame.Header)
	eqHex(t, "frame c", r["c"].([]byte), v.Frame.C)
	if _, has := r["g"]; has {
		t.Error("frames carry no signature")
	}

	// the same command in epoch 1
	eqHex(t, "cmd e1 header", cmdHeader(v.AgentID, "cmd", v.CommandKey.Kid, unhex(t, v.Hs1.Sid), 1, 1, uint64(v.T), unhex(t, v.Cmd.Nonce)), v.CmdE1.Header)
	a.sec2.nonces = nonceLRU{}
	o, why = openBytes(a, srvEnvelope(cmd, v.AgentID, "cmd", unhex(t, v.Hs1.Sid), 1, 1, v.T, unhex(t, v.Cmd.Nonce), unhex(t, v.CmdE1.C)), now, nil)
	if why != "" {
		t.Fatal("cmd e1 refused:", why)
	}
	eqHex(t, "cmd e1 plaintext", o.plain, v.CmdE1.Plaintext)

	plain, err := openSealed(id, v.AgentID, v.Sealed.Path, a.pins.Load(), v.Sealed.Body, v.T)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "sealed plaintext", plain, v.Sealed.Plaintext)
}

// Each check refuses before the next one runs, and a refusal returns no
// payload.
func TestEnvelopeVerifyOrder(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	s2a, _ := handshake(t, a, cmd, sid, now, 3)
	ping := []byte("\x81\xa4func\xa4ping")
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	n := func(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }
	good := srvCmd(cmd, a.AgentID, sid, s2a, 0, 1, now.UnixMilli(), n(0x10), ping)

	forged, _ := decodeEnvelope(good)
	forged.G = ed25519.Sign(other, []byte("x"))
	unknownKid := srvCmd(other, a.AgentID, sid, s2a, 0, 2, now.UnixMilli(), n(0x11), ping)
	// a forged signature is refused before the clock is looked at
	staleForged, _ := decodeEnvelope(srvCmd(cmd, a.AgentID, sid, s2a, 0, 3, now.UnixMilli()-31_000, n(0x12), ping))
	staleForged.C[0] ^= 1
	stale := srvCmd(cmd, a.AgentID, sid, s2a, 0, 3, now.UnixMilli()-31_000, n(0x12), ping)
	// the clock before the session
	staleNoSession := srvCmd(cmd, a.AgentID, n(0x55), s2a, 0, 3, now.UnixMilli()+31_000, n(0x13), ping)
	noSession := srvCmd(cmd, a.AgentID, n(0x55), s2a, 0, 3, now.UnixMilli(), n(0x13), ping)
	wrongKey := srvCmd(cmd, a.AgentID, sid, bytes.Repeat([]byte{1}, 32), 0, 4, now.UnixMilli(), n(0x14), ping)
	h := cmdHeader(a.AgentID, "cmd", keyID(cmd.Public().(ed25519.PublicKey)), sid, 0, 5, uint64(now.UnixMilli()), n(0x15))
	ct := seal(s2a, aeadNonce(0, 5), ping, h)
	ct[0] ^= 1
	flipped := srvEnvelope(cmd, a.AgentID, "cmd", sid, 0, 5, now.UnixMilli(), n(0x15), ct)
	forAnother := srvCmd(cmd, a.AgentID+"x", sid, s2a, 0, 6, now.UnixMilli(), n(0x16), ping)

	for _, c := range []struct {
		name string
		env  *envelope
		raw  []byte
		want string
	}{
		{"forged signature", forged, nil, "signature"},
		{"unknown kid", nil, unknownKid, "kid"},
		{"forged and stale", staleForged, nil, "signature"},
		{"stale", nil, stale, "clock"},
		{"future and no session", nil, staleNoSession, "clock"},
		{"no session", nil, noSession, "session"},
		{"wrong key", nil, wrongKey, "decrypt"},
		{"bit flip", nil, flipped, "decrypt"},
		{"other agent", nil, forAnother, "signature"},
	} {
		env := c.env
		if env == nil {
			env, _ = decodeEnvelope(c.raw)
		}
		o, why := a.sec2.open(a.AgentID, env, a.pins.Load(), now, a.hsInput)
		if why != c.want || o != nil {
			t.Errorf("%s: %q %v, want %q", c.name, why, o, c.want)
		}
	}
	if o, why := openBytes(a, good, now, nil); why != "" || !bytes.Equal(o.plain, ping) {
		t.Fatal("good command refused:", why)
	}
	if _, why := openBytes(a, good, now, nil); why != "replay" {
		t.Error("the same command twice:", why)
	}
	// a refused decrypt does not use up the sequence number
	if _, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 4, now.UnixMilli(), n(0x17), ping), now, nil); why != "" {
		t.Error("q of a refused command:", why)
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWin
	try := func(q uint64) bool {
		ok := w.ok(q)
		if ok {
			w.mark(q)
		}
		return ok
	}
	for _, c := range []struct {
		q  uint64
		ok bool
	}{
		{0, false}, {1, true}, {1, false}, {5, true}, {3, true}, {3, false}, {2, true}, {5, false},
		{2000, true}, {2000 - 1023, true}, {2000 - 1024, false}, {1500, true}, {1500, false}, {1999, true},
		{5000, true}, {1999, false}, {4999, true},
	} {
		if got := try(c.q); got != c.ok {
			t.Errorf("q %d: %v, want %v", c.q, got, c.ok)
		}
	}
}

func TestNonceLRU(t *testing.T) {
	var l nonceLRU
	now := time.Unix(1000, 0)
	n := func(i int) (b [16]byte) { b[0], b[1] = byte(i), byte(i>>8); return }
	l.add(n(1), now)
	if !l.has(n(1), now.Add(59*time.Second)) || l.has(n(2), now) {
		t.Fatal("lookup")
	}
	if l.has(n(1), now.Add(61*time.Second)) {
		t.Error("a nonce older than twice the clock window is forgotten")
	}
	for i := 2; i <= nonceLRUSize+1; i++ {
		l.add(n(i), now)
	}
	if l.has(n(1), now) || !l.has(n(2), now) || len(l.order) != nonceLRUSize || len(l.at) != nonceLRUSize {
		t.Errorf("size %d %d", len(l.order), len(l.at))
	}
}

// Only authenticated REST answers move the clock; a NATS message never does.
func TestClockOffsetOnlyFromREST(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	local := vecNow(v).Add(-time.Hour)
	far := srvEnvelope(cmd, a.AgentID, "hs1", nil, 0, 0, v.T, bytes.Repeat([]byte{6}, 16), unhex(t, v.Hs1.Body))
	if _, why := openBytes(a, far, local, vecHs(t, v)); why != "clock" || a.sec2.offset.Load() != 0 {
		t.Fatal("clock:", why, a.sec2.offset.Load())
	}
	a.learnClock(time.Now().Add(time.Hour).UnixMilli())
	if off := a.sec2.offset.Load(); off < 3599_000 || off > 3601_000 {
		t.Fatal("offset", off)
	}
	a.sec2.offset.Store(time.Hour.Milliseconds())
	if _, why := openBytes(a, far, local, vecHs(t, v)); why != "" {
		t.Fatal("with the learned offset:", why)
	}
	if a.sec2.offset.Load() != time.Hour.Milliseconds() {
		t.Error("the handshake moved the clock")
	}
}

func TestArmedRefusesPlaintext(t *testing.T) {
	v := loadVectors(t)
	a, _ := sec2Agent(t, v)
	// the pin refresh a refusal starts would outlive the test and race with
	// the build key of the next one; TestUnsignedRefusalRefreshesPins covers it
	a.sec2.refusedNow("pins", time.Now())
	plain, _ := encodeMsgpack(map[string]string{"func": "ping"})
	if _, _, ok := a.openRequest(&nats.Msg{Data: plain}); ok {
		t.Fatal("an armed agent ran a plaintext command")
	}
	if len(a.events) != 1 || a.events[0].Kind != "unsigned_command" {
		t.Fatalf("events %+v", a.events)
	}
	a.openRequest(&nats.Msg{Data: plain})
	if len(a.events) != 1 {
		t.Error("one event per reason in 10 minutes")
	}
	// a forged envelope is refused too, with its own event
	bad := srvEnvelope(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), a.AgentID, "cmd", nil, 0, 1, time.Now().UnixMilli(), bytes.Repeat([]byte{1}, 16), []byte("x"))
	if _, _, ok := a.openRequest(&nats.Msg{Data: bad}); ok || len(a.events) != 2 || a.events[1].Kind != "envelope_refused" {
		t.Fatalf("forged envelope: %+v", a.events)
	}
}

func TestNotArmedAcceptsPlaintext(t *testing.T) {
	v := loadVectors(t)
	plain, _ := encodeMsgpack(map[string]string{"func": "ping"})
	for name, set := range map[string]func(a *Agent){
		"pin document says off": func(a *Agent) { a.pins.Load().Sec2 = "off" },
		"no sec2 claim":         func(a *Agent) { a.pins.Load().Sec2 = "" },
		"not registered":        func(a *Agent) { a.sec2.kid.Store(nil) },
		"other kid registered":  func(a *Agent) { k := "0000000000000000"; a.sec2.kid.Store(&k) },
	} {
		a, _ := sec2Agent(t, v)
		set(a)
		data, ctx, ok := a.openRequest(&nats.Msg{Data: plain})
		if !ok || ctx != nil || !bytes.Equal(data, plain) {
			t.Errorf("%s: plaintext refused", name)
		}
	}
}

func openReply(t *testing.T, a *Agent, rep []byte, a2s []byte, reqQ uint64) ([]byte, error) {
	t.Helper()
	var r struct {
		S []byte `codec:"s"`
		E uint32 `codec:"e"`
		Q uint64 `codec:"q"`
		C []byte `codec:"c"`
		G []byte `codec:"g"`
	}
	if err := codec.NewDecoderBytes(rep, &codec.MsgpackHandle{}).Decode(&r); err != nil {
		t.Fatal(err)
	}
	h := replyHeader(a.AgentID, r.S, r.E, r.Q, reqQ)
	if !ed25519.Verify(a.sec2.ident.Load().edPub(), signedBytes(h, r.C), r.G) {
		return nil, io.ErrUnexpectedEOF
	}
	return unseal(ratchetKeyN(a2s, r.E), aeadNonce(r.E, r.Q), r.C, h)
}

func ratchetKeyN(k []byte, e uint32) []byte {
	for i := uint32(1); i <= e; i++ {
		k = ratchetKey(k, i)
	}
	return k
}

func TestReplyBindsRequestSeq(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	s2a, a2s := handshake(t, a, cmd, sid, now, 3)
	o, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 7, now.UnixMilli(), bytes.Repeat([]byte{8}, 16), []byte{0xc0}), now, nil)
	if why != "" {
		t.Fatal(why)
	}
	rep, _ := a.sec2.sealReply(a.AgentID, o.ctx, []byte("pong"), now)
	if p, err := openReply(t, a, rep, a2s, 7); err != nil || string(p) != "pong" {
		t.Fatal("reply:", err)
	}
	if _, err := openReply(t, a, rep, a2s, 6); err == nil {
		t.Error("the answer verifies for another request")
	}
}

func TestFrameAEAD(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	_, a2s := handshake(t, a, cmd, sid, now, 3)
	subj := a.AgentID + ".cmdoutput.7"
	fr, ok := a.sec2.sealFrame(nil, subj, []byte("line"), now)
	if !ok {
		t.Fatal("no frame")
	}
	var r struct {
		S []byte `codec:"s"`
		E uint32 `codec:"e"`
		Q uint64 `codec:"q"`
		C []byte `codec:"c"`
	}
	_ = codec.NewDecoderBytes(fr, &codec.MsgpackHandle{}).Decode(&r)
	if p, err := unseal(a2s, aeadNonce(r.E, r.Q), r.C, frameHeader(subj, r.S, r.E, r.Q)); err != nil || string(p) != "line" {
		t.Fatal("frame:", err)
	}
	if _, err := unseal(a2s, aeadNonce(r.E, r.Q), r.C, frameHeader(a.AgentID+".terminal.7", r.S, r.E, r.Q)); err == nil {
		t.Error("a frame opens under another subject")
	}
	// without a session an armed agent sends nothing
	b := &Agent{Logger: a.Logger}
	if _, ok := b.sec2.sealFrame(nil, subj, []byte("x"), now); ok {
		t.Error("frame without session")
	}
}

func TestHandshakeAnswer(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	handshake(t, a, cmd, sid, now, 3)
	if len(a.sec2.sessions) != 1 {
		t.Fatal("no session")
	}
	// hs1 for an agent without identity
	b := &Agent{AgentID: a.AgentID, Logger: a.Logger}
	b.pins.Store(a.pins.Load())
	body := encodeBin(map[string]interface{}{"sid": bytes.Repeat([]byte{8}, 16), "es": unhex(t, v.Hs1.Es), "ts": v.T})
	if _, why := openBytes(b, srvEnvelope(cmd, a.AgentID, "hs1", nil, 0, 0, v.T, bytes.Repeat([]byte{9}, 16), body), now, b.hsInput); why != "session" {
		t.Error("hs1 without identity:", why)
	}
	// a low-order server key
	body = encodeBin(map[string]interface{}{"sid": bytes.Repeat([]byte{8}, 16), "es": make([]byte, 32), "ts": v.T})
	if _, why := openBytes(a, srvEnvelope(cmd, a.AgentID, "hs1", nil, 0, 0, v.T, bytes.Repeat([]byte{10}, 16), body), now, a.hsInput); why != "session" {
		t.Error("all-zero es:", why)
	}
}

func TestHandshakeReplayedSid(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	env := unhex(t, v.Hs1.Envelope)
	if _, why := openBytes(a, env, now, vecHs(t, v)); why != "" {
		t.Fatal(why)
	}
	if _, why := openBytes(a, env, now, vecHs(t, v)); why != "replay" {
		t.Error("the same hs1:", why)
	}
	// the same sid with a fresh nonce
	again := srvEnvelope(cmd, a.AgentID, "hs1", nil, 0, 0, v.T, bytes.Repeat([]byte{0x33}, 16), unhex(t, v.Hs1.Body))
	if _, why := openBytes(a, again, now, vecHs(t, v)); why != "replay" {
		t.Error("a used sid:", why)
	}
}

func TestRatchetAcceptsNextEpoch(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	s2a, _ := handshake(t, a, cmd, sid, now, 3)
	n := func(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }
	at := func(e uint32, q uint64, nb byte, when time.Time) string {
		_, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, ratchetKeyN(s2a, e), e, q, when.UnixMilli(), n(nb), []byte{0xc0}), when, nil)
		return why
	}
	if why := at(2, 1, 0x20, now); why != "session" {
		t.Error("epoch 2 before 1:", why)
	}
	if why := at(1, 1, 0x21, now); why != "" {
		t.Fatal("epoch 1:", why)
	}
	if why := at(0, 1, 0x22, now.Add(time.Minute)); why != "" {
		t.Error("epoch 0 within the overlap:", why)
	}
	if why := at(0, 2, 0x23, now.Add(3*time.Minute)); why != "session" {
		t.Error("epoch 0 after the overlap:", why)
	}
	if why := at(2, 1, 0x24, now.Add(3*time.Minute)); why != "" {
		t.Error("epoch 2:", why)
	}
}

func TestHardCapsRefuse(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	s2a, _ := handshake(t, a, cmd, sid, now, 3)
	a.sec2.sessions[0].epochs[0].inMsgs = e2eCapMessages
	if _, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 1, now.UnixMilli(), bytes.Repeat([]byte{1}, 16), []byte{0xc0}), now, nil); why != "session" {
		t.Error("beyond the message cap:", why)
	}
	a.sec2.sessions[0].epochs[0].inMsgs = 0
	a.sec2.sessions[0].epochs[0].inBytes = e2eCapBytes
	if _, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 1, now.UnixMilli(), bytes.Repeat([]byte{2}, 16), []byte{0xc0}), now, nil); why != "session" {
		t.Error("beyond the byte cap:", why)
	}
	a.sec2.sessions[0].epochs[0].inBytes = 0
	late := now.Add(e2eCapAge)
	if _, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 1, late.UnixMilli(), bytes.Repeat([]byte{3}, 16), []byte{0xc0}), late, nil); why != "session" {
		t.Error("session older than twice the rekey time:", why)
	}
	// frames move to the next epoch at the server's limit
	b, cmdB := sec2Agent(t, v)
	handshake(t, b, cmdB, sid, now, 3)
	b.sec2.sessions[0].epochs[0].outQ = e2eRekeyMessages
	fr, _ := b.sec2.sealFrame(nil, "x", []byte("y"), now)
	var r struct {
		E uint32 `codec:"e"`
		Q uint64 `codec:"q"`
	}
	_ = codec.NewDecoderBytes(fr, &codec.MsgpackHandle{}).Decode(&r)
	if r.E != 1 || r.Q != 1 {
		t.Errorf("frame after the limit: e %d q %d", r.E, r.Q)
	}
}

func TestMaxThreeSessions(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	var keys [][]byte
	for i := byte(1); i <= 4; i++ {
		k, _ := handshake(t, a, cmd, bytes.Repeat([]byte{i}, 16), now, 0x40+i)
		keys = append(keys, k)
	}
	if len(a.sec2.sessions) != e2eMaxSessions {
		t.Fatalf("%d sessions", len(a.sec2.sessions))
	}
	try := func(i int, when time.Time, nb byte) string {
		_, why := openBytes(a, srvCmd(cmd, a.AgentID, bytes.Repeat([]byte{byte(i + 1)}, 16), keys[i], 0, 1, when.UnixMilli(), bytes.Repeat([]byte{nb}, 16), []byte{0xc0}), when, nil)
		return why
	}
	if why := try(0, now, 0x50); why != "session" {
		t.Error("the oldest session:", why)
	}
	if why := try(1, now.Add(time.Minute), 0x51); why != "" {
		t.Error("an older session within the overlap:", why)
	}
	if why := try(2, now.Add(3*time.Minute), 0x52); why != "session" {
		t.Error("an older session after the overlap:", why)
	}
	if why := try(3, now.Add(3*time.Minute), 0x53); why != "" {
		t.Error("the newest session:", why)
	}
}

func sealedHdr() http.Header {
	h := http.Header{}
	h.Set(sealMarker, "1")
	return h
}

type fakeRT struct {
	hdr   http.Header
	body  []byte
	asked string
}

func (f *fakeRT) RoundTrip(r *http.Request) (*http.Response, error) {
	f.asked = r.Header.Get(sealAsk)
	return &http.Response{StatusCode: 200, Header: f.hdr.Clone(), Body: io.NopCloser(bytes.NewReader(f.body)), Request: r}, nil
}

func sealedReq(t *testing.T, a *Agent, rt http.RoundTripper, method, path string) ([]byte, error) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://rmm"+path, nil)
	resp, err := (&sealTransport{base: rt, a: a}).RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func TestSealedBodyOpen(t *testing.T) {
	v := loadVectors(t)
	a, _ := sec2Agent(t, v)
	a.sec2.offset.Store(v.T - time.Now().UnixMilli())
	rt := &fakeRT{hdr: sealedHdr(), body: v.Sealed.Body}
	got, err := sealedReq(t, a, rt, "GET", v.Sealed.Path)
	if err != nil || string(got) != `{"ok":true}` || rt.asked != "1" {
		t.Fatalf("%s %v asked %q", got, err, rt.asked)
	}
}

func TestSealedBodyRefused(t *testing.T) {
	v := loadVectors(t)
	a, _ := sec2Agent(t, v)
	a.sec2.offset.Store(v.T - time.Now().UnixMilli())
	var body map[string]interface{}
	_ = json.Unmarshal(v.Sealed.Body, &body)
	c, _ := base64.StdEncoding.DecodeString(body["c"].(string))
	c[0] ^= 1
	body["c"] = base64.StdEncoding.EncodeToString(c)
	flipped, _ := json.Marshal(body)
	for name, c := range map[string]struct {
		path string
		body []byte
	}{
		"other path": {strings.Replace(v.Sealed.Path, "/7/", "/8/", 1), v.Sealed.Body},
		"bit flip":   {v.Sealed.Path, flipped},
	} {
		if _, err := sealedReq(t, a, &fakeRT{hdr: sealedHdr(), body: c.body}, "GET", c.path); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	a.sec2.offset.Store(0)
	if _, err := sealedReq(t, a, &fakeRT{hdr: sealedHdr(), body: v.Sealed.Body}, "GET", v.Sealed.Path); err == nil {
		t.Error("an old sealed answer opened")
	}
}

func TestUnsealedRefusedWhenArmed(t *testing.T) {
	v := loadVectors(t)
	a, _ := sec2Agent(t, v)
	plain := &fakeRT{body: []byte(`{"ok":true}`)}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v4/x/pkgjob/7/"}, {"GET", "/api/v3/x/selfheal/"}, {"POST", "/api/v3/x/cert/"},
	} {
		if _, err := sealedReq(t, a, plain, c.method, c.path); err == nil {
			t.Errorf("%s %s unsealed accepted", c.method, c.path)
		}
	}
	if _, err := sealedReq(t, a, plain, "POST", "/api/v3/x/selfheal/"); err != nil {
		t.Error("an answer that is not sealed by design:", err)
	}
	a.pins.Load().Sec2 = "off"
	if _, err := sealedReq(t, a, plain, "GET", "/api/v4/x/pkgjob/7/"); err != nil {
		t.Error("not armed:", err)
	}
	a.sec2.kid.Store(nil)
	if _, _ = sealedReq(t, a, plain, "GET", "/api/v4/x/pkgjob/7/"); plain.asked != "" {
		t.Error("an unregistered agent asks for sealing")
	}
}

func TestProtectWrapping(t *testing.T) {
	s, err := wrapSecret(confRefresh, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := unwrapSecret(confRefresh, s); err != nil || string(b) != "secret" {
		t.Fatal(s, err)
	}
	if b, err := unwrapSecret(confRefresh, ""); b != nil || err != nil {
		t.Error("empty")
	}
	for _, bad := range []string{"secret", "raw1:%%", "plain:abc", "kek1:AAAA"} {
		if _, err := unwrapSecret(confRefresh, bad); err == nil {
			t.Errorf("%q read", bad)
		}
	}
	// values stored as they are before the keystore
	if b, err := unwrapSecret("Token", "tok"); err != nil || string(b) != "tok" {
		t.Error("plain token", err)
	}
}

// The service makes the seed once; an unreadable one is replaced and
// reported, and the registration starts over.
func TestLoadIdentity(t *testing.T) {
	old := etcConfig
	t.Cleanup(func() { etcConfig = old })
	etcConfig = filepath.Join(t.TempDir(), "agent.json")
	createAgentConfig("https://api", "agent-s", "api", "token", "1", "", "", "", "", "")
	a := &Agent{Logger: logrus.New()}
	a.Logger.SetOutput(io.Discard)
	id := a.loadIdentity()
	if id == nil || a.registered() {
		t.Fatal("no identity")
	}
	raw, _ := confValue(confIdentityKey)
	if !strings.HasPrefix(raw, wrapRaw) {
		t.Fatal("stored as", raw)
	}
	_ = setConfValues(map[string]string{confIdentityKid: id.kid})
	b := &Agent{Logger: a.Logger}
	if again := b.loadIdentity(); again == nil || again.kid != id.kid || !b.registered() {
		t.Fatal("the stored seed is not used")
	}
	_ = setConfValues(map[string]string{confIdentityKey: wrapRaw + "AAAA"})
	c := &Agent{Logger: a.Logger}
	if n := c.loadIdentity(); n == nil || n.kid == id.kid || c.registered() || len(c.events) != 1 || c.events[0].Kind != "identity_unreadable" {
		t.Fatalf("unreadable seed: %+v", c.events)
	}
}

func TestPinDocCommandKeys(t *testing.T) {
	k := testEnrollKey(t)
	cmd := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	pub := base64.StdEncoding.EncodeToString(cmd.Public().(ed25519.PublicKey))
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	doc := func(extra map[string]interface{}) string {
		c := map[string]interface{}{"v": 1, "typ": pinsTyp, "iss": "https://rmm.example", "seq": 4, "primary": []string{pin}, "backup": []string{}, "iat": time.Now().Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return mintJWS(k, map[string]string{"alg": "EdDSA", "kid": testKid(k), "typ": pinsTyp}, c)
	}
	ps, err := verifyPinDoc(doc(map[string]interface{}{"cmd": []map[string]string{{"kid": "34750f98bd59fcfc", "ed": pub, "state": "current"}}, "sec2": "required"}), "rmm.example")
	if err != nil || ps.Sec2 != "required" || len(ps.cmdKey("34750f98bd59fcfc")) != 32 || ps.cmdKey("x") != nil {
		t.Fatal(ps, err)
	}
	if ps, err := verifyPinDoc(doc(nil), "rmm.example"); err != nil || ps.Sec2 != "" || len(ps.Cmd) != 0 {
		t.Fatal("a document without the claims:", err)
	}
	for name, extra := range map[string]map[string]interface{}{
		"wrong kid": {"cmd": []map[string]string{{"kid": "0000000000000000", "ed": pub, "state": "current"}}},
		"short key": {"cmd": []map[string]string{{"kid": "34750f98bd59fcfc", "ed": "AAAA", "state": "current"}}},
		"bad mode":  {"sec2": "maybe"},
	} {
		if _, err := verifyPinDoc(doc(extra), "rmm.example"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// stored pins without the claims keep their bytes
	b, _ := json.Marshal(&pinSet{Seq: 1, Primary: []string{pin}, Backup: []string{}})
	if strings.Contains(string(b), "cmd") || strings.Contains(string(b), "sec2") {
		t.Error(string(b))
	}
}

func TestRefreshTiming(t *testing.T) {
	for _, c := range []struct {
		issued, expires, now int64
		due                  bool
	}{
		{1000, 2000, 1600, false}, {1000, 2000, 1700, true}, {0, 2000, 1999, false}, {0, 2000, 2000, true}, {0, 0, 5, false},
	} {
		if got := refreshDue(c.issued, c.expires, c.now); got != c.due {
			t.Errorf("%+v: %v", c, got)
		}
	}
	for raw, want := range map[string]int64{
		`"2023-11-14T22:13:20Z"`: 1700000000000, `1700000000`: 1700000000000, `1700000000000`: 1700000000000, `null`: 0, `"x"`: 0,
	} {
		if got := expiry(json.RawMessage(raw)); got != want {
			t.Errorf("%s: %d", raw, got)
		}
	}
}

// The answer of a long command goes out in its own session, after a newer
// handshake and past the age limit of the session.
func TestReplyAfterSessionSuperseded(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := vecNow(v)
	sid := bytes.Repeat([]byte{5}, 16)
	s2a, a2s := handshake(t, a, cmd, sid, now, 3)
	o, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 4, now.UnixMilli(), bytes.Repeat([]byte{8}, 16), []byte{0xc0}), now, nil)
	if why != "" {
		t.Fatal(why)
	}
	later := now.Add(61 * time.Minute)
	handshake(t, a, cmd, bytes.Repeat([]byte{6}, 16), later, 4)
	for _, at := range []time.Time{later.Add(10 * time.Minute), now.Add(3 * time.Hour)} {
		rep, ok := a.sec2.sealReply(a.AgentID, o.ctx, []byte("done"), at)
		if !ok {
			t.Fatal("no answer at", at.Sub(now))
		}
		if p, err := openReply(t, a, rep, a2s, 4); err != nil || string(p) != "done" {
			t.Fatal("answer:", err)
		}
	}
}

// Output follows the command that started it: plaintext for a plaintext
// command, sealed for a sealed one, whatever sessions the agent holds.
func TestFramesFollowCommandMode(t *testing.T) {
	v := loadVectors(t)
	a, cmd := sec2Agent(t, v)
	now := time.Now()
	a.learnClock(now.UnixMilli())
	sid := bytes.Repeat([]byte{5}, 16)
	s2a, a2s := handshake(t, a, cmd, sid, now, 3)
	plainSubj, sealedSubj := a.AgentID+".terminal.p", a.AgentID+".cmdoutput.s"
	t.Cleanup(func() { frameModes.Delete(plainSubj); frameModes.Delete(sealedSubj) })
	(&rpcReq{}).framesOf(plainSubj)
	o, why := openBytes(a, srvCmd(cmd, a.AgentID, sid, s2a, 0, 1, now.UnixMilli(), bytes.Repeat([]byte{8}, 16), []byte{0xc0}), now, nil)
	if why != "" {
		t.Fatal(why)
	}
	(&rpcReq{ctx: o.ctx}).framesOf(sealedSubj)
	want, _ := encodeMsgpack("line")

	if _, err := frameBytes(a, plainSubj, "line", now); err == nil {
		t.Error("an armed agent sent plaintext output")
	}
	a.pins.Load().Sec2 = "off"
	for _, subj := range []string{plainSubj, a.AgentID + ".terminal.unknown"} {
		if b, err := frameBytes(a, subj, "line", now); err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s: not plaintext after sec2 off: %v", subj, err)
		}
	}
	b, err := frameBytes(a, sealedSubj, "line", now)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		S []byte `codec:"s"`
		E uint32 `codec:"e"`
		Q uint64 `codec:"q"`
		C []byte `codec:"c"`
	}
	_ = codec.NewDecoderBytes(b, &codec.MsgpackHandle{}).Decode(&r)
	if p, err := unseal(a2s, aeadNonce(r.E, r.Q), r.C, frameHeader(sealedSubj, r.S, r.E, r.Q)); err != nil || !bytes.Equal(p, want) {
		t.Fatal("output of the sealed command:", err)
	}
	// past the age limit the command's own session carries it
	if _, err := frameBytes(a, sealedSubj, "line", now.Add(3*time.Hour)); err != nil {
		t.Error("no output without a live session:", err)
	}
}

// sec2 lowered to off: the first plaintext command the armed agent refuses
// fetches the pin document, and the newer one disarms it.
func TestUnsignedRefusalRefreshesPins(t *testing.T) {
	key := testEnrollKey(t)
	ca := newTestCA(t, "rmm CA")
	now := time.Now()
	srv := newPinDocServer(t, testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour)))
	a := rmmTestAgent(t)
	a.BaseURL, a.Cert = srv.URL, ca.file(t)
	id, _ := deriveIdentity(bytes.Repeat([]byte{1}, 32))
	a.sec2.ident.Store(id)
	a.sec2.kid.Store(&id.kid)
	a.pins.Store(&pinSet{Seq: 1, Sec2: "optional", Primary: []string{spkiPin(ca.cert.Raw)}})
	srv.set(pinDoc(key, srv.URL, 2, spkiPin(ca.cert.Raw)))
	plain, _ := encodeMsgpack(map[string]string{"func": "ping"})
	if _, _, ok := a.openRequest(&nats.Msg{Data: plain}); ok {
		t.Fatal("armed agent ran a plaintext command")
	}
	for deadline := time.Now().Add(5 * time.Second); a.pins.Load().Seq != 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no pin refresh after the refusal")
		}
	}
	if _, _, ok := a.openRequest(&nats.Msg{Data: plain}); !ok {
		t.Error("still armed after the newer pin document")
	}
}

// A server without the identity endpoint: the heartbeat still fetches the
// pin document, which tells when to register.
func TestHeartbeatRefreshesPinsUnregistered(t *testing.T) {
	testEnrollKey(t)
	ca := newTestCA(t, "rmm CA")
	now := time.Now()
	srv := newPinDocServer(t, testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour)))
	a := rmmTestAgent(t)
	a.BaseURL, a.Cert = srv.URL, ca.file(t)
	id, _ := deriveIdentity(bytes.Repeat([]byte{1}, 32))
	a.sec2.ident.Store(id)
	a.sec2.noEndpoint.Store(true)
	a.pins.Store(&pinSet{Seq: 1, Primary: []string{spkiPin(ca.cert.Raw)}})
	a.sec2Heartbeat(now)
	if srv.asked.Load() != 1 {
		t.Fatal("pin document asked", srv.asked.Load())
	}
	a.sec2Heartbeat(now.Add(heartbeatEvery))
	if srv.asked.Load() != 1 {
		t.Error("more than once an hour")
	}
}

func TestConfWriteOrder(t *testing.T) {
	got := strings.Join(confWriteOrder(map[string]string{
		"Token": "a", confAccessExpires: "1", confRefresh: "r", confIdentityNext: "", confAccessIssued: "2",
	}), " ")
	if want := confRefresh + " " + confAccessExpires + " " + confAccessIssued + " Token " + confIdentityNext; got != want {
		t.Errorf("order %q, want %q", got, want)
	}
}

func TestRestartForLoginExitsOnWindows(t *testing.T) {
	oldBy, oldExit, oldDir := restartByExit, exitProcess, nixAgentDir
	t.Cleanup(func() { restartByExit, exitProcess, nixAgentDir = oldBy, oldExit, oldDir })
	nixAgentDir = t.TempDir()
	code := -1
	restartByExit, exitProcess = true, func(c int) { code = c }
	a := &Agent{Logger: logrus.New(), ProgramDir: nixAgentDir}
	a.Logger.SetOutput(io.Discard)
	a.restartForLogin()
	if code <= 0 {
		t.Fatal("no unclean exit for the recovery actions, code", code)
	}
	if _, err := os.Stat(filepath.Join(a.dataDir(), stopExpectedFile)); err != nil {
		t.Error("the stop is not marked as expected:", err)
	}
}

// An agent updated from 2.25 keeps the pin document its older build stored
// without cmd and sec2; the same seq, signed with them, replaces it once.
func TestSameSeqPinDocAfterUpdate(t *testing.T) {
	key := testEnrollKey(t)
	ca := newTestCA(t, "rmm CA")
	now := time.Now()
	srv := newPinDocServer(t, testLeaf(t, ca, now.Add(-time.Hour), now.Add(time.Hour)))
	a := rmmTestAgent(t)
	a.BaseURL, a.Cert = srv.URL, ca.file(t)
	pin := spkiPin(ca.cert.Raw)
	old, err := loadPins(`{"seq":1,"primary":["` + pin + `"],"backup":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	a.pins.Store(old)
	pub, _, _ := ed25519.GenerateKey(nil)
	sum := sha256.Sum256(pub)
	doc := func(sec2 string) string {
		return mintJWS(key, map[string]string{"alg": "EdDSA", "kid": testKid(key), "typ": pinsTyp},
			map[string]interface{}{"v": 1, "typ": pinsTyp, "iss": srv.URL, "seq": 1, "primary": []string{pin}, "backup": []string{}, "sec2": sec2,
				"cmd": []cmdKey{{Kid: hex.EncodeToString(sum[:])[:16], Ed: base64.StdEncoding.EncodeToString(pub), State: "active"}}, "iat": now.Unix()})
	}
	srv.set(doc(""))
	a.RefreshPins()
	if a.pins.Load() != old {
		t.Fatal("same seq without a sec2 claim replaced the stored set")
	}
	srv.set(doc("optional"))
	a.RefreshPins()
	ps := a.pins.Load()
	if ps.Seq != 1 || ps.Sec2 != "optional" || ps.cmdKey(hex.EncodeToString(sum[:])[:16]) == nil {
		t.Fatalf("pins %+v", ps)
	}
	srv.set(doc("off"))
	a.RefreshPins()
	if a.pins.Load() != ps {
		t.Error("same seq replaced a set that has the sec2 claim")
	}
}
