// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var imagingInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func imagingDialContext(iface string) (func(context.Context, string, string) (net.Conn, error), error) {
	if !imagingInterfaceName.MatchString(iface) {
		return nil, fmt.Errorf("waiting for a configured WireGuard interface")
	}
	dialer := net.Dialer{
		Timeout: 30 * time.Second,
		ControlContext: func(ctx context.Context, _, _ string, raw syscall.RawConn) error {
			index, err := imagingWireGuardIndex(ctx, iface)
			if err != nil {
				return err
			}
			var bindError error
			if err := raw.Control(func(fd uintptr) {
				bindError = unix.BindToDevice(int(fd), iface)
			}); err != nil {
				return err
			}
			if bindError != nil {
				return fmt.Errorf("bind transfer socket to WireGuard: %w", bindError)
			}
			current, err := net.InterfaceByName(iface)
			if err != nil || current.Index != index {
				return fmt.Errorf("WireGuard interface changed during socket setup")
			}
			return nil
		},
	}
	return dialer.DialContext, nil
}

func imagingWireGuardIndex(ctx context.Context, iface string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-json", "-details", "link", "show", "dev", iface).Output()
	var links []struct {
		Index int `json:"ifindex"`
		Flags []string
		Info  struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err != nil || json.Unmarshal(out, &links) != nil || len(links) != 1 ||
		links[0].Index <= 0 || links[0].Info.Kind != "wireguard" || !slices.Contains(links[0].Flags, "UP") {
		return 0, fmt.Errorf("waiting for WireGuard interface %s", iface)
	}
	return links[0].Index, nil
}
