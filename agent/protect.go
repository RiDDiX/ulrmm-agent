// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Agent protection: an uninstall code the server keeps per agent, and a marker
// for service stops the agent did not cause itself.

const (
	uninstallCodeLen = 32
	confUninstallKey = "UninstallCode"
	confUninstallAck = "UninstallCodeSent"
	stopManualFile   = "stop.manual"
	stopExpectedFile = "stop.expected"
	stopExpectedFor  = 15 * time.Minute
)

func newUninstallCode() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, uninstallCodeLen)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			panic(err)
		}
		b[i] = chars[n.Int64()]
	}
	return string(b)
}

// ensureUninstallCode returns the stored code and whether the server has it.
// The ack holds the sum of the code the server took (the code itself up to
// 3.25.10.2026), so an ack left over from an earlier install does not cover
// a new code. Agents installed before the code existed get one here.
func ensureUninstallCode() (code string, sent bool, err error) {
	code, err = storedUninstallCode()
	if err != nil {
		return "", false, err
	}
	if len(code) == uninstallCodeLen {
		ack, _ := confValue(confUninstallAck)
		return code, ack == codeSum(code) || ack == code, nil
	}
	code = newUninstallCode()
	s, err := wrapSecret(confUninstallKey, []byte(code))
	if err != nil {
		return "", false, err
	}
	return code, false, setConfValues(map[string]string{confUninstallSum: codeSum(code), confUninstallKey: s, confUninstallAck: ""})
}

// storedUninstallCode is the code in the clear, "" without one.
func storedUninstallCode() (string, error) {
	b, err := unprotect(confUninstallKey)
	return string(b), err
}

// checkUninstallCode accepts the stored code only. An agent without a stored
// code (never started since the code was introduced) has nothing to check.
func checkUninstallCode(given string) error {
	stored, err := storedUninstallCode()
	if err != nil {
		return err
	}
	if stored != "" && subtle.ConstantTimeCompare([]byte(stored), []byte(given)) != 1 {
		return errors.New("wrong or missing uninstall code")
	}
	return nil
}

// UninstallWithCode is -m uninstall: the local way to remove the agent.
func (a *Agent) UninstallWithCode(code string) error {
	if err := checkUninstallCode(code); err != nil {
		return err
	}
	expectStop(a.dataDir())
	return a.uninstallLocal()
}

func (a *Agent) dataDir() string { return newHealPlatform(a).dataDir() }

// expectStop marks the next stop as one the agent caused: update, uninstall,
// self-healing restart.
func expectStop(dir string) {
	_ = os.WriteFile(filepath.Join(dir, stopExpectedFile), nil, 0o600)
}

func clearExpectedStop(dir string) {
	_ = os.Remove(filepath.Join(dir, stopExpectedFile))
}

// recordStop runs when the service is told to stop.
func recordStop(dir string, now time.Time) {
	exp := filepath.Join(dir, stopExpectedFile)
	st, err := os.Stat(exp)
	_ = os.Remove(exp)
	if err == nil && now.Sub(st.ModTime()) < stopExpectedFor {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, stopManualFile), nil, 0o600)
}

// stopReason is "manual" when the service was stopped from outside since the
// last boot. A marker older than the boot is a shutdown and is dropped.
func stopReason(dir string, boot time.Time) string {
	m := filepath.Join(dir, stopManualFile)
	st, err := os.Stat(m)
	if err != nil {
		return ""
	}
	if st.ModTime().Before(boot) {
		_ = os.Remove(m)
		return ""
	}
	return "manual"
}

func ackStop(dir string) {
	_ = os.Remove(filepath.Join(dir, stopManualFile))
}

// startupReport is what the checkin at service start carries besides the id.
func (a *Agent) startupReport() map[string]interface{} {
	r := map[string]interface{}{}
	if s := stopReason(a.dataDir(), time.Unix(a.BootTime(), 0)); s != "" {
		r["stop_reason"] = s
	}
	code, sent, err := ensureUninstallCode()
	if err != nil {
		a.Logger.Errorln("uninstall code:", err)
	} else if !sent {
		r["uninstall_code"] = code
	}
	return r
}

// startupReported runs after the server took the report.
func (a *Agent) startupReported(r map[string]interface{}) {
	if _, ok := r["stop_reason"]; ok {
		ackStop(a.dataDir())
	}
	if code, ok := r["uninstall_code"].(string); ok {
		if err := setConfValues(map[string]string{confUninstallAck: codeSum(code)}); err != nil {
			a.Logger.Errorln("uninstall code:", err)
		}
	}
}

// Secrets in the config carry a prefix naming how they are wrapped: "kek1:"
// is under the host KEK (keystore.go). Before the keystore "raw1:" was plain
// base64 (Unix config file, mode 0600) and "dpapi1:" a DPAPI blob of the
// service account (Windows); both are still read.
const (
	wrapRaw   = "raw1:"
	wrapDPAPI = "dpapi1:"
)

var errUnwrap = errors.New("the stored secret cannot be read")

func protect(name string, b []byte) error {
	s, err := wrapSecret(name, b)
	if err != nil {
		return err
	}
	return setConfValues(map[string]string{name: s})
}

// unprotect is nil, nil when nothing is stored under name.
func unprotect(name string) ([]byte, error) {
	s, err := confValue(name)
	if err != nil {
		return nil, err
	}
	return unwrapSecret(name, s)
}
