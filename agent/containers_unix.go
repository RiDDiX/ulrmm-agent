// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

func unixHTTP(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
}

// only engines present on the host show up in sources
func collectContainers(ctx context.Context, stats bool) *SContainers {
	ct := newContainers()
	for _, e := range []struct{ kind, sock string }{
		{"docker", "/var/run/docker.sock"},
		{"podman", "/run/podman/podman.sock"},
	} {
		if !rmm.FileExists(e.sock) {
			continue
		}
		items, err := dockerItems(ctx, unixHTTP(e.sock), "http://engine", e.kind, stats)
		ct.source(e.kind, err)
		ct.Items = append(ct.Items, items...)
	}
	for _, e := range []struct {
		kind, bin string
		socks     []string
	}{
		{"lxd", "lxc", []string{"/var/snap/lxd/common/lxd/unix.socket", "/var/lib/lxd/unix.socket"}},
		{"incus", "incus", []string{"/var/lib/incus/unix.socket"}},
	} {
		if !rmm.FileExists(e.socks[0]) && (len(e.socks) < 2 || !rmm.FileExists(e.socks[1])) {
			continue
		}
		out, err := runOut(ctx, e.bin, "list", "--format", "json")
		if err == nil {
			var items []SContainer
			items, err = parseLxdList([]byte(out), e.kind, time.Now())
			ct.Items = append(ct.Items, items...)
		}
		ct.source(e.kind, err)
	}
	pve := rmm.FileExists("/etc/pve")
	if _, err := exec.LookPath("pvesh"); err == nil && pve {
		pveGuests(ctx, ct)
	} else if _, err := exec.LookPath("lxc-ls"); err == nil && !pve {
		out, err := runOut(ctx, "lxc-ls", "-f", "-F", "NAME,STATE")
		if err == nil {
			ct.Items = append(ct.Items, parseLxcLs(out)...)
		}
		ct.source("lxc", err)
	}
	ct.Items = capList(ct.Items, ctrMax)
	return ct
}

func pveGuests(ctx context.Context, ct *SContainers) {
	node, _ := os.Hostname()
	node, _, _ = strings.Cut(node, ".")
	out, err := runOut(ctx, "pvesh", "get", "/cluster/status", "--output-format", "json")
	if err == nil {
		var local string
		if local, ct.Cluster, err = parsePveStatus([]byte(out)); local != "" {
			node = local
		}
	}
	if err == nil {
		out, err = runOut(ctx, "pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json")
	}
	if err == nil {
		var items []SContainer
		items, err = parsePveResources([]byte(out), node)
		ct.Items = append(ct.Items, items...)
	}
	ct.source("pve-qemu", err)
	ct.source("pve-lxc", err)
}
