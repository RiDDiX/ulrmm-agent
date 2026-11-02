// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// Enrollment data is a compact JWS (Ed25519) the server signs for one
// deployment. A setup file carries it as a block at its end, in front of the
// Authenticode certificate table when the file is signed:
// [0-7 zero bytes][JWS][uint64 LE length of the JWS]["ULRMMENR"].
// A text file holding only the JWS works too.

const (
	enrollMagic    = "ULRMMENR"
	enrollMaxBlock = 16384
	enrollMaxJWS   = 4096
	// the clock of a freshly installed machine is often off
	enrollLeeway = 24 * time.Hour
)

// Config values of the client certificate; the unix file keeps them lower case.
const (
	confClientCert = "ClientCert"
	confClientKey  = "ClientKey"
)

// ErrNoEnrollment: a generic installer, nothing to enroll with.
var ErrNoEnrollment = errors.New("the file carries no enrollment data")

type enrollClaims struct {
	V    int    `json:"v"`
	Iss  string `json:"iss"`
	Dep  string `json:"dep"`
	Cli  int    `json:"cli"`
	Site int    `json:"site"`
	Mon  string `json:"mon"`
	Flg  struct {
		Power bool `json:"power"`
		Ping  bool `json:"ping"`
		RDP   bool `json:"rdp"`
	} `json:"flg"`
	Pins []string `json:"pins"`
	Iat  int64    `json:"iat"`
	Exp  int64    `json:"exp"`
}

// applyEnrollment sets the installer fields the enrollment data in
// i.EnrollFile covers. Flags given for them are replaced.
func applyEnrollment(i *Installer, now time.Time) error {
	jws, err := readEnrollment(i.EnrollFile)
	if err != nil {
		return err
	}
	c, err := verifyEnrollment(jws, now)
	if err != nil {
		return err
	}
	i.RMM, i.ClientID, i.SiteID, i.AgentType = c.Iss, c.Cli, c.Site, c.Mon
	i.Power, i.Ping, i.RDP = c.Flg.Power, c.Flg.Ping, c.Flg.RDP
	i.Token, i.Enroll, i.Pins = "", jws, c.Pins
	return nil
}

// readEnrollment returns the JWS in path, ErrNoEnrollment when there is none.
func readEnrollment(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	end := st.Size()
	if off := certTableOffset(f); off > 0 && off <= end {
		end = off
	}
	n := int64(7 + 16 + enrollMaxBlock)
	if end < n {
		n = end
	}
	tail := make([]byte, n)
	if _, err := f.ReadAt(tail, end-n); err != nil {
		return "", err
	}
	if jws, err := footerJWS(tail); !errors.Is(err, ErrNoEnrollment) {
		return jws, err
	}
	// a text file fits into tail as a whole
	if s := strings.TrimSpace(string(tail)); int64(len(tail)) == st.Size() && looksLikeJWS(s) {
		return s, nil
	}
	return "", ErrNoEnrollment
}

// certTableOffset is the file offset of a PE file's certificate table, 0
// when the file is no PE or is not signed.
func certTableOffset(r io.ReaderAt) int64 {
	f, err := pe.NewFile(r)
	if err != nil {
		return 0
	}
	var d pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		d = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	case *pe.OptionalHeader64:
		d = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	}
	if d.Size == 0 {
		return 0
	}
	return int64(d.VirtualAddress)
}

// footerJWS takes the block off the end of tail; signers may have padded
// the file with up to 7 zero bytes after it.
func footerJWS(tail []byte) (string, error) {
	for i := 0; i < 7 && len(tail) > 0 && tail[len(tail)-1] == 0; i++ {
		tail = tail[:len(tail)-1]
	}
	if len(tail) < 16 || string(tail[len(tail)-8:]) != enrollMagic {
		return "", ErrNoEnrollment
	}
	n := binary.LittleEndian.Uint64(tail[len(tail)-16:])
	tail = tail[:len(tail)-16]
	if n < 1 || n > enrollMaxBlock || n > uint64(len(tail)) {
		return "", errors.New("enrollment data invalid: bad block length")
	}
	return string(tail[uint64(len(tail))-n:]), nil
}

func looksLikeJWS(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

// verifyEnrollment checks the JWS against BrandEnrollPubKey and returns its
// claims.
func verifyEnrollment(jws string, now time.Time) (*enrollClaims, error) {
	pub, err := enrollPubKey()
	if err != nil {
		return nil, err
	}
	bad := func(why string) error { return fmt.Errorf("enrollment data invalid: %s", why) }
	var c enrollClaims
	if err := verifyJWS(pub, jws, "", enrollMaxJWS, &c); err != nil {
		return nil, bad(err.Error())
	}
	switch {
	case c.V != 1:
		return nil, bad(fmt.Sprintf("version %d", c.V))
	case c.Exp <= 0 || c.Iat <= 0 || c.Iat > c.Exp:
		return nil, bad("validity period")
	case now.After(time.Unix(c.Exp, 0).Add(enrollLeeway)):
		return nil, bad("expired")
	case time.Unix(c.Iat, 0).After(now.Add(enrollLeeway)):
		return nil, bad("issued in the future, check the clock")
	case c.Dep == "" || c.Cli <= 0 || c.Site <= 0:
		return nil, bad("deployment, client or site missing")
	case c.Mon != "server" && c.Mon != "workstation":
		return nil, bad("agent type " + c.Mon)
	}
	if u, err := url.Parse(c.Iss); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, bad("server URL")
	}
	return &c, nil
}

// enrollPubKey is BrandEnrollPubKey; it also checks pin documents and
// update signatures.
func enrollPubKey() (ed25519.PublicKey, error) {
	if BrandEnrollPubKey == "" {
		return nil, errors.New("this build has no enrollment key")
	}
	pub, err := base64.StdEncoding.DecodeString(BrandEnrollPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("the enrollment key of this build is not an Ed25519 key")
	}
	return pub, nil
}

// verifyJWS checks a compact JWS (EdDSA, key id of pub) and decodes its
// claims into v. A typ given must be the header's.
func verifyJWS(pub ed25519.PublicKey, jws, typ string, max int, v interface{}) error {
	if len(jws) > max {
		return errors.New("too long")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("not a signed token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := decodeJWSPart(parts[0], &hdr); err != nil {
		return errors.New("header: " + err.Error())
	}
	if hdr.Alg != "EdDSA" {
		return errors.New("algorithm " + hdr.Alg)
	}
	sum := sha256.Sum256(pub)
	if hdr.Kid != hex.EncodeToString(sum[:])[:16] {
		return errors.New("signed with another key (key id does not match)")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("signature does not match")
	}
	if typ != "" && hdr.Typ != typ {
		return errors.New("type " + hdr.Typ)
	}
	if err := decodeJWSPart(parts[1], v); err != nil {
		return errors.New("payload: " + err.Error())
	}
	return nil
}

func decodeJWSPart(s string, v interface{}) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// newCSR makes a fresh ECDSA P-256 key and a certificate request with the
// agent id as common name, both PEM.
func newCSR(agentID string) (csrPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		return "", "", err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})), nil
}
