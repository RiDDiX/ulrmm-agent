// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"strings"
	"sync"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

// Config MAC: the values that decide which server the agent trusts are kept
// as TrustSnapshot with an HMAC (key from the identity seed) in ConfigMAC.
// The service refreshes both whenever it writes one of them or the seed.
// At start a config whose values differ from a valid snapshot is reported
// and the snapshot values are used instead.

const (
	confConfigMAC     = "ConfigMAC"
	confTrustSnapshot = "TrustSnapshot"
)

// macFields in snapshot order
var macFields = [...]string{"ApiURL", "BaseURL", "AgentID", "Cert", confPins, "NatsProxyPath", "NatsStandardPort", "Proxy"}

type trustVals [len(macFields)]string

func trustOf(c *rmm.LocalConfig) trustVals {
	return trustVals{c.APIHost, c.ServerBase, c.ID, c.CACert, c.PinsJSON, c.NATSProxyPath, c.NATSPort, c.ProxyURL}
}

func (v trustVals) apply(c *rmm.LocalConfig) {
	c.APIHost, c.ServerBase, c.ID, c.CACert, c.PinsJSON, c.NATSProxyPath, c.NATSPort, c.ProxyURL = v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
}

func (v trustVals) encode() string {
	b, _ := json.Marshal(v)
	return string(b)
}

func configMAC(seed []byte, snapshot string) string {
	k, _ := hkdf.Key(sha256.New, seed, nil, "ulrmm config mac v1", 32)
	m := hmac.New(sha256.New, k)
	m.Write([]byte(snapshot))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// confTrust holds the values this process trusts; set by checkConfigMAC.
// Only the service writes the snapshot and the MAC (service, from
// startConfigMAC): the other modes run next to it, and a config write of
// theirs could undo one of the service, a refresh token just rotated.
var confTrust struct {
	sync.Mutex
	on      bool
	service bool
	// the stored MAC is missing or does not match: the service makes it
	renew bool
	vals  trustVals
}

// confWrite is writeConfValues; a variable for the tests
var confWrite = writeConfValues

func macSeed() []byte {
	s, err := confValue(confIdentityKey)
	if err != nil {
		return nil
	}
	return seedOf(s)
}

func seedOf(s string) []byte {
	m, err := unwrapSecret(confIdentityKey, s)
	if err != nil || len(m) != 32 {
		return nil
	}
	return m
}

func sealTrust(kv map[string]string, seed []byte, v trustVals) {
	s := v.encode()
	kv[confTrustSnapshot], kv[confConfigMAC] = s, configMAC(seed, s)
}

// checkConfigMAC runs in New(). It returns why the config was refused, ""
// when it was not; cfg then carries the snapshot values. Without a seed
// (first start, unreadable keystore) nothing is checked and the MAC is made
// once the identity is stored.
func checkConfigMAC(cfg *rmm.LocalConfig) string {
	confTrust.Lock()
	defer confTrust.Unlock()
	cur := trustOf(cfg)
	confTrust.on, confTrust.renew, confTrust.vals = true, false, cur
	seed := macSeed()
	if seed == nil {
		return ""
	}
	snap, _ := confValue(confTrustSnapshot)
	mac, _ := confValue(confConfigMAC)
	var old trustVals
	switch {
	case mac == "" && snap == "":
		confTrust.renew = true
		return ""
	case !hmac.Equal([]byte(mac), []byte(configMAC(seed, snap))) || json.Unmarshal([]byte(snap), &old) != nil:
		// nothing left to fall back to; the current values become the
		// trusted ones so the service reports it once
		confTrust.renew = true
		return "the config MAC does not match"
	case old == cur:
		return ""
	}
	var changed []string
	for i := range macFields {
		if old[i] != cur[i] {
			changed = append(changed, macFields[i])
		}
	}
	old.apply(cfg)
	confTrust.vals = old
	return "changed outside the agent, ignored: " + strings.Join(changed, ", ")
}

// startConfigMAC runs at service start, after the keystore: from here on
// this process keeps the snapshot and the MAC.
func startConfigMAC() {
	confTrust.Lock()
	defer confTrust.Unlock()
	if !confTrust.on {
		return
	}
	confTrust.service = true
	if !confTrust.renew {
		return
	}
	if seed := macSeed(); seed != nil {
		kv := map[string]string{}
		sealTrust(kv, seed, confTrust.vals)
		if confWrite(kv) == nil {
			confTrust.renew = false
		}
	}
}

// setConfValues merges kv into the config. In the service a write of a
// trusted value or of the identity seed carries the renewed snapshot and
// its MAC in the same write, so no interruption leaves them apart.
func setConfValues(kv map[string]string) error {
	confTrust.Lock()
	defer confTrust.Unlock()
	if !confTrust.on || !confTrust.service {
		return confWrite(kv)
	}
	vals, touched, seedSet := confTrust.vals, false, false
	var seed []byte
	for k, v := range kv {
		if strings.EqualFold(k, confIdentityKey) {
			touched, seedSet, seed = true, true, seedOf(v)
		}
		for i, f := range macFields {
			if strings.EqualFold(k, f) {
				vals[i], touched = v, true
			}
		}
	}
	if !touched {
		return confWrite(kv)
	}
	if !seedSet {
		seed = macSeed()
	}
	if seed != nil {
		kv = maps.Clone(kv)
		sealTrust(kv, seed, vals)
	}
	if err := confWrite(kv); err != nil {
		return err
	}
	confTrust.vals = vals
	return nil
}
