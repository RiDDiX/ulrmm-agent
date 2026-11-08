// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Sessions of the command channel. The server starts each one with hs1
// (both sides send an ephemeral X25519 key, both handshake messages are
// signed); the agent only answers. Keys move to the next epoch by a hash
// ratchet when a direction carried too much, without a new handshake.

const (
	e2eClockWindow   = 30 * time.Second
	e2eRekeySeconds  = 3600
	e2eRekeyBytes    = 64 << 20
	e2eRekeyMessages = 100_000
	// the agent's hard caps are twice the server's limits
	e2eCapBytes    = 2 * e2eRekeyBytes
	e2eCapMessages = 2 * e2eRekeyMessages
	e2eCapAge      = 2 * e2eRekeySeconds * time.Second
	// an older session or epoch stays usable this long for answers in flight
	e2eOverlap     = 2 * time.Minute
	e2eMaxSessions = 3
	replayWindow   = 1024
	nonceLRUSize   = 4096
)

type epochKeys struct {
	s2a, a2s []byte
	win      replayWin
	// server to agent within this epoch
	inMsgs, inBytes int64
	// agent to server: the last sequence number used and the bytes sent
	outQ     uint64
	outBytes int64
}

type session struct {
	sid     [16]byte
	created time.Time
	// zero while it is the newest session
	until time.Time
	cur   uint32
	// the epoch before cur is accepted until then
	prevUntil time.Time
	epochs    map[uint32]*epochKeys
}

func sessionKeys(shared []byte, sid []byte, agentID string, es, ea []byte) (s2a, a2s []byte, err error) {
	info := append(append(append([]byte("ulrmm e2e v1\x00"), agentID...), es...), ea...)
	okm, err := hkdf.Key(sha256.New, shared, sid, string(info), 64)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}

// ratchetKey is the key of epoch e derived from the key of epoch e-1.
func ratchetKey(k []byte, e uint32) []byte {
	info := binary.BigEndian.AppendUint32([]byte("ulrmm e2e rekey v1"), e)
	out, _ := hkdf.Key(sha256.New, k, nil, string(info), 32)
	return out
}

// epoch returns the keys of e (cur-1, cur or cur+1), deriving cur+1 on demand.
func (s *session) epoch(e uint32) *epochKeys {
	if k := s.epochs[e]; k != nil {
		return k
	}
	if e == 0 || s.epochs[e-1] == nil {
		return nil
	}
	p := s.epochs[e-1]
	k := &epochKeys{s2a: ratchetKey(p.s2a, e), a2s: ratchetKey(p.a2s, e)}
	s.epochs[e] = k
	return k
}

// usable says whether a command in epoch e is taken now.
func (s *session) usable(e uint32, now time.Time) bool {
	switch {
	case e == s.cur || e == s.cur+1:
		return true
	case e+1 == s.cur:
		return now.Before(s.prevUntil)
	}
	return false
}

// advance moves to epoch e (cur+1) and drops what is older than cur-1.
func (s *session) advance(e uint32, now time.Time) {
	if e != s.cur+1 {
		return
	}
	s.cur = e
	s.prevUntil = now.Add(e2eOverlap)
	for k := range s.epochs {
		if k+1 < e {
			delete(s.epochs, k)
		}
	}
}

func (s *session) alive(now time.Time) bool {
	return now.Sub(s.created) < e2eCapAge && (s.until.IsZero() || now.Before(s.until))
}

// replayWin is a sliding window (as in DTLS) over the sequence numbers of
// one direction and epoch: the highest seen and which of the 1024 below it.
type replayWin struct {
	top  uint64
	seen [replayWindow]bool
}

func (w *replayWin) ok(q uint64) bool {
	switch {
	case q == 0:
		return false
	case q > w.top:
		return true
	case w.top-q >= replayWindow:
		return false
	}
	return !w.seen[q%replayWindow]
}

func (w *replayWin) mark(q uint64) {
	if q > w.top {
		n := q - w.top
		if n > replayWindow {
			n = replayWindow
		}
		for i := uint64(1); i <= n; i++ {
			w.seen[(w.top+i)%replayWindow] = false
		}
		w.top = q
	}
	w.seen[q%replayWindow] = true
}

// nonceLRU remembers command nonces for twice the clock window.
type nonceLRU struct {
	at    map[[16]byte]time.Time
	order [][16]byte
}

func (l *nonceLRU) has(n [16]byte, now time.Time) bool {
	t, ok := l.at[n]
	return ok && now.Sub(t) < 2*e2eClockWindow
}

func (l *nonceLRU) add(n [16]byte, now time.Time) {
	if l.at == nil {
		l.at = map[[16]byte]time.Time{}
	}
	if _, ok := l.at[n]; !ok {
		l.order = append(l.order, n)
	}
	l.at[n] = now
	for len(l.order) > 0 {
		old := l.order[0]
		if len(l.order) <= nonceLRUSize && now.Sub(l.at[old]) < 2*e2eClockWindow {
			break
		}
		delete(l.at, old)
		l.order = l.order[1:]
	}
}

type hs1Body struct {
	Sid    []byte   `codec:"sid"`
	Es     []byte   `codec:"es"`
	Rotate []string `codec:"rotate"`
}

func hs2Signed(agentID string, sid, es, ea []byte, cfp string, pinSeq int64, ts int64) []byte {
	b := append([]byte("ulrmm-hs2-v1\x00"), agentID...)
	b = append(b, 0)
	b = append(append(append(append(b, sid...), es...), ea...), cfp...)
	b = binary.BigEndian.AppendUint64(b, uint64(pinSeq))
	return binary.BigEndian.AppendUint64(b, uint64(ts))
}

// answerHandshake makes the session of a verified hs1 and the hs2 answer.
// ephemeral is the agent's private key (random outside tests).
func (st *sec2State) answerHandshake(id *identity, agentID string, body *hs1Body, cfp, version string, pinSeq, ts int64, ephemeral []byte, now time.Time) (map[string]interface{}, string) {
	if len(body.Sid) != 16 || len(body.Es) != 32 {
		return nil, "session"
	}
	var sid [16]byte
	copy(sid[:], body.Sid)
	if _, seen := st.sids[sid]; seen {
		return nil, "replay"
	}
	es, err := ecdh.X25519().NewPublicKey(body.Es)
	if err != nil {
		return nil, "session"
	}
	if ephemeral == nil {
		ephemeral = make([]byte, 32)
		_, _ = rand.Read(ephemeral)
	}
	ea, err := ecdh.X25519().NewPrivateKey(ephemeral)
	if err != nil {
		return nil, "session"
	}
	shared, err := ea.ECDH(es)
	if err != nil {
		return nil, "session"
	}
	eaPub := ea.PublicKey().Bytes()
	s2a, a2s, err := sessionKeys(shared, body.Sid, agentID, body.Es, eaPub)
	if err != nil {
		return nil, "session"
	}
	if st.sids == nil {
		st.sids = map[[16]byte]time.Time{}
	}
	for k, t := range st.sids {
		if now.Sub(t) > e2eCapAge {
			delete(st.sids, k)
		}
	}
	st.sids[sid] = now
	for _, old := range st.sessions {
		if old.until.IsZero() {
			old.until = now.Add(e2eOverlap)
		}
	}
	st.sessions = append(st.sessions, &session{sid: sid, created: now, epochs: map[uint32]*epochKeys{0: {s2a: s2a, a2s: a2s}}})
	if len(st.sessions) > e2eMaxSessions {
		st.sessions = st.sessions[len(st.sessions)-e2eMaxSessions:]
	}
	g := id.sign(hs2Signed(agentID, body.Sid, body.Es, eaPub, cfp, pinSeq, ts))
	return map[string]interface{}{
		"v": 2, "y": "hs2", "sid": body.Sid, "ea": eaPub, "cfp": cfp,
		"pin_seq": pinSeq, "ver": version, "ts": ts, "g": g,
	}, ""
}

// session is the live session sid, nil when there is none.
func (st *sec2State) session(sid []byte, now time.Time) *session {
	var live []*session
	var found *session
	for _, s := range st.sessions {
		if !s.alive(now) {
			continue
		}
		live = append(live, s)
		if string(s.sid[:]) == string(sid) {
			found = s
		}
	}
	st.sessions = live
	return found
}

// newest is the session frames go out in.
func (st *sec2State) newest(now time.Time) *session {
	for i := len(st.sessions) - 1; i >= 0; i-- {
		if s := st.sessions[i]; s.alive(now) {
			return s
		}
	}
	return nil
}
