// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const macImagingTunnelPath = "/etc/ulrmm-imaging-wireguard.json"

var macTunnelInterface = regexp.MustCompile(`^utun[0-9]{1,5}$`)

type macImagingTunnel struct {
	Interface string `json:"interface"`
	SourceIP  string `json:"source_ip"`
	PeerKey   string `json:"peer_public_key"`
	WGPath    string `json:"wg_path"`
}

func imagingDialContext(iface string) (func(context.Context, string, string) (net.Conn, error), error) {
	config, source, err := macReadImagingTunnel(iface)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("internal imaging requires TCP")
		}
		device, socket, err := config.verify(ctx, source)
		if err != nil {
			return nil, err
		}
		protocol, option, family := unix.IPPROTO_IP, unix.IP_BOUND_IF, "tcp4"
		if source.Is6() {
			protocol, option, family = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, "tcp6"
		}
		dialer := net.Dialer{
			Timeout:   30 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.IP(source.AsSlice())},
			Control: func(_, _ string, connection syscall.RawConn) error {
				var bindErr error
				err := connection.Control(func(fd uintptr) {
					bindErr = unix.SetsockoptInt(int(fd), protocol, option, device.Index)
				})
				return errors.Join(err, bindErr)
			},
		}
		connection, err := dialer.DialContext(ctx, family, address)
		if err != nil {
			return nil, err
		}
		verified, currentSocket, err := config.verify(ctx, source)
		if err != nil || verified.Index != device.Index || !os.SameFile(socket, currentSocket) {
			connection.Close()
			return nil, errors.New("WireGuard interface changed before imaging transfer")
		}
		return connection, nil
	}, nil
}

func macReadImagingTunnel(iface string) (macImagingTunnel, netip.Addr, error) {
	var config macImagingTunnel
	var source netip.Addr
	if os.Geteuid() != 0 || (iface != "" && !macTunnelInterface.MatchString(iface)) {
		return config, source, errors.New("waiting for a configured root-operated WireGuard utun interface")
	}
	fd, err := syscall.Open(macImagingTunnelPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return config, source, errors.New("waiting for " + macImagingTunnelPath)
	}
	f := os.NewFile(uintptr(fd), macImagingTunnelPath)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return config, source, err
	}
	if !macRootOwned(info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return config, source, errors.New("WireGuard imaging configuration must be a regular root-owned 0600 file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return config, source, err
	}
	if len(raw) > 4096 || json.Unmarshal(raw, &config) != nil || !macTunnelInterface.MatchString(config.Interface) ||
		(iface != "" && config.Interface != iface) {
		return config, source, errors.New("invalid or mismatched local WireGuard imaging configuration")
	}
	source, err = netip.ParseAddr(config.SourceIP)
	key, keyErr := base64.StdEncoding.DecodeString(config.PeerKey)
	if err != nil || !source.IsGlobalUnicast() || source.Is4In6() || source.Zone() != "" ||
		keyErr != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != config.PeerKey ||
		!filepath.IsAbs(config.WGPath) || filepath.Clean(config.WGPath) != config.WGPath {
		return config, source, errors.New("configure a WireGuard tunnel IP, public peer key and absolute wg executable path")
	}
	return config, source, nil
}

func macRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func macProtectedTunnelPath(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !macRootOwned(info) || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("WireGuard path ownership or permissions are unsafe")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		dir, err := os.Lstat(parent)
		if err != nil {
			return nil, err
		}
		if !dir.IsDir() || !macRootOwned(dir) || dir.Mode().Perm()&0022 != 0 {
			return nil, errors.New("WireGuard parent directory ownership or permissions are unsafe")
		}
		if parent == "/" {
			return info, nil
		}
	}
}

func (config macImagingTunnel) verify(ctx context.Context, source netip.Addr) (*net.Interface, os.FileInfo, error) {
	device, err := net.InterfaceByName(config.Interface)
	if err != nil || device.Index < 1 || device.Flags&(net.FlagUp|net.FlagPointToPoint) != (net.FlagUp|net.FlagPointToPoint) {
		return nil, nil, errors.New("configured WireGuard interface is unavailable")
	}
	addrs, err := device.Addrs()
	if err != nil {
		return nil, nil, err
	}
	found := false
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok && ip.IP.Equal(net.IP(source.AsSlice())) {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, errors.New("configured WireGuard tunnel IP is not assigned to the interface")
	}
	executable, err := macProtectedTunnelPath(config.WGPath)
	if err != nil || !executable.Mode().IsRegular() || executable.Mode().Perm()&0100 == 0 {
		return nil, nil, errors.New("configure a protected root-owned wg executable")
	}
	uapi := filepath.Join("/private/var/run/wireguard", config.Interface+".sock")
	socket, err := macProtectedTunnelPath(uapi)
	if err != nil || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("waiting for a protected wireguard-go UAPI socket")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, config.WGPath, "show", config.Interface, "peers")
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := command.Output()
	if err != nil || strings.TrimSpace(string(out)) != config.PeerKey {
		return nil, nil, errors.New("WireGuard does not report the single locally approved public peer")
	}
	socketAfter, err := macProtectedTunnelPath(uapi)
	if err != nil || !os.SameFile(socket, socketAfter) {
		return nil, nil, errors.New("WireGuard UAPI socket changed during verification")
	}
	return device, socket, nil
}
