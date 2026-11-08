// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// KEK stores on Unix: systemd-creds (Linux, v250 and later; bound to the
// TPM2 when the host has one), the System keychain (macOS), else a file
// next to the config that only root reads. TrueNAS keeps only /root across
// updates and loses the systemd host key: the file there.

var (
	keystoreOS  = runtime.GOOS
	credsBins   = []string{"/usr/bin/systemd-creds", "/bin/systemd-creds"}
	securityBin = "/usr/bin/security"
	// runTool runs an OS tool with a fixed argv and returns its stdout
	runTool = func(stdin []byte, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("%s %s: %v %s", filepath.Base(name), args[0], err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
)

const (
	systemKeychain = "/Library/Keychains/System.keychain"
	credsMinVer    = 250
)

func kekFile() string     { return etcConfig + ".kek" }
func kekCred() string     { return etcConfig + ".kek.cred" }
func kekCredHost() string { return etcConfig + ".kek.host.cred" }
func credName() string    { return IdentNixBin + "-kek" }

func kekSchemes() []string {
	switch {
	case keystoreOS == "linux" && !onTrueNAS:
		return []string{"creds", "file"}
	case keystoreOS == "darwin":
		return []string{"keychain", "file"}
	}
	return []string{"file"}
}

func credsBin() (string, error) {
	for _, p := range credsBins {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("systemd-creds not found")
}

// kekPut stores k in the store s and returns the scheme it is under.
func kekPut(s string, k []byte) (string, error) {
	switch s {
	case "file":
		return "file", writeRootFile(kekFile(), k)
	case "creds", "creds-tpm", "creds-host":
		bin, err := credsBin()
		if err != nil {
			return "", err
		}
		out, err := runTool(nil, bin, "--version")
		if err != nil {
			return "", err
		}
		// "systemd 252 (252.19-1~deb12u1)"
		if f := strings.Fields(string(out)); len(f) < 2 {
			return "", errors.New("systemd-creds: no version")
		} else if v, _ := strconv.Atoi(f[1]); v < credsMinVer {
			return "", fmt.Errorf("systemd-creds %s is older than %d", f[1], credsMinVer)
		}
		scheme := "creds-host"
		if _, err := runTool(nil, bin, "has-tpm2"); err == nil {
			scheme = "creds-tpm"
		}
		// no PCR binding: PCR 7, the default, changes with a Secure Boot db
		// or dbx update and the key would not open after the next boot
		if err := credsEncrypt(bin, k, kekCred(), "--with-key=auto", "--tpm2-pcrs="); err != nil {
			return "", err
		}
		if scheme == "creds-host" {
			_ = os.Remove(kekCredHost())
			return scheme, nil
		}
		// a cleared TPM or a VM moved without its vTPM state loses the
		// credential above: a copy under the host key alone
		return scheme, credsEncrypt(bin, k, kekCredHost(), "--with-key=host")
	case "keychain":
		// the command goes in on stdin: as an argument the key would show in
		// ps. security -i does not fail on a refused command; the read-back
		// in newKeyStore catches that.
		cmd := "add-generic-password -U -s " + macPlistName + " -a kek -w " +
			base64.StdEncoding.EncodeToString(k) + " " + systemKeychain + "\n"
		_, err := runTool([]byte(cmd), securityBin, "-i")
		return "keychain", err
	}
	return "", fmt.Errorf("no store %q here", s)
}

func credsEncrypt(bin string, k []byte, path, with string, more ...string) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)
	args := append([]string{"encrypt", "--name=" + credName(), with}, more...)
	if _, err := runTool(k, bin, append(args, "-", tmp)...); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// kekCopy opens the copy of the KEK kept next to the store of scheme, and
// names where it is.
func kekCopy(scheme string) ([]byte, string, error) {
	if scheme != "creds-tpm" {
		return nil, "", errNoKEKCopy
	}
	bin, err := credsBin()
	if err != nil {
		return nil, "", err
	}
	k, err := runTool(nil, bin, "decrypt", "--name="+credName(), kekCredHost(), "-")
	return k, "creds-host", err
}

func kekGet(scheme string) ([]byte, error) {
	switch scheme {
	case "file":
		return os.ReadFile(kekFile())
	case "creds-tpm", "creds-host":
		bin, err := credsBin()
		if err != nil {
			return nil, err
		}
		return runTool(nil, bin, "decrypt", "--name="+credName(), kekCred(), "-")
	case "keychain":
		out, err := runTool(nil, securityBin, "find-generic-password", "-s", macPlistName, "-a", "kek", "-w", systemKeychain)
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	}
	return nil, fmt.Errorf("unknown keystore %q", scheme)
}

// writeRootFile writes b with mode 0600 through a temp file in the same
// directory.
func writeRootFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".kek*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}
