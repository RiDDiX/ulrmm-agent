// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/go-resty/resty/v2"
)

// Script runtimes. The release URLs are variables for the tests.
var (
	nuReleaseURL        = "https://github.com/nushell/nushell/releases/download"
	denoReleaseURL      = "https://github.com/denoland/deno/releases/download"
	runtimeInstallDelay = func() { sleepSeconds(randRange(1, 10)) }
)

type scriptRuntime struct {
	name      string
	bin       string
	customURL string
	version   string
	// release URL for this OS and arch, "" when there is none
	releaseURL string
	// sha256 of the download as the server pins it, "" when it has none
	sha256 string
	// unpack extracts the release archive into dir and names the binary
	unpack func(archive, dir string) (string, error)
	// prepare runs before the download
	prepare func() error
	// tmpBase holds the download directory, "" is the system temp dir
	tmpBase string
}

// customRuntimeURL fills the placeholders of a download URL from the
// server settings.
func customRuntimeURL(tmpl, goos, goarch, ver string) string {
	return strings.NewReplacer("{OS}", goos, "{ARCH}", goarch, "{VERSION}", ver).Replace(tmpl)
}

// installRuntime downloads first and replaces an existing binary only with
// a complete new one, so a failed download keeps the old runtime.
func (a *Agent) installRuntime(rt scriptRuntime, force bool) error {
	if rmm.FileExists(rt.bin) && !force {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(rt.bin), 0o755); err != nil {
		return err
	}
	if rt.prepare != nil {
		if err := rt.prepare(); err != nil {
			return err
		}
	}
	url, bare := rt.releaseURL, false
	if rt.customURL != "" {
		url, bare = customRuntimeURL(rt.customURL, runtime.GOOS, runtime.GOARCH, rt.version), true
	}
	if url == "" {
		a.Logger.Debugln(rt.name, "has no release for", runtime.GOOS, runtime.GOARCH)
		return nil
	}

	tmp, err := os.MkdirTemp(rt.tmpBase, strings.TrimSuffix(rt.name, "shell")+"temp")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	archive := filepath.Join(tmp, "download")
	a.Logger.Infoln("Downloading", rt.name, "from", url)
	if err := a.runtimeDownload(url, archive); err != nil {
		return err
	}
	if rt.sha256 != "" {
		got, err := fileSHA256(archive)
		if err != nil {
			return err
		}
		if !strings.EqualFold(got, rt.sha256) {
			return fmt.Errorf("sha256 of the %s download is %s, the server expects %s", rt.name, got, rt.sha256)
		}
	} else {
		a.Logger.Debugln(rt.name, "download not verified: the server sent no sha256")
	}
	src := archive
	if !bare {
		dir := filepath.Join(tmp, "unpacked")
		if src, err = rt.unpack(archive, dir); err != nil {
			return err
		}
	}
	if err := copyFileAtomic(src, rt.bin, 0o755); err != nil {
		return err
	}
	a.Logger.Infoln(rt.name, "installed at", rt.bin)
	return nil
}

// runtimeDownload uses the agent's proxy and TLS settings but never the
// agent token: the file host is not the RMM.
func (a *Agent) runtimeDownload(link, dest string) error {
	hc, err := a.httpClient(link, 20*time.Minute)
	if err != nil {
		return err
	}
	c := resty.NewWithClient(hc).
		SetRetryCount(10).
		SetRetryWaitTime(time.Minute).
		SetRetryMaxWaitTime(15 * time.Minute)
	r, err := c.R().SetOutput(dest).Get(link)
	if err != nil {
		return err
	}
	if r.IsError() {
		return fmt.Errorf("download answered %d", r.StatusCode())
	}
	return nil
}

// denoPermissions takes the permission flags from the first
// DENO_PERMISSIONS entry (removed from env) or else from the default.
func denoPermissions(env []string, defaults string) ([]string, []string) {
	const key = "DENO_PERMISSIONS="
	for i, v := range env {
		if strings.HasPrefix(v, key) {
			rest := append(append([]string{}, env[:i]...), env[i+1:]...)
			return rest, strings.Fields(strings.TrimPrefix(v, key))
		}
	}
	return env, strings.Fields(defaults)
}
