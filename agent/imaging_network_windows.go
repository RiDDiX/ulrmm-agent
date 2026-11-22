// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"math/bits"
	"net"
	"regexp"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var windowsWireGuardDescription = regexp.MustCompile(`^WireGuard Tunnel( #[0-9]+)?$`)

func windowsImagingTunnel(name string) (ipv4, ipv6 uint32, luid uint64, err error) {
	state, err := GetServiceStatus("WireGuardTunnel$" + name)
	if name == "" || err != nil || state != "running" {
		return 0, 0, 0, errors.New("the configured WireGuard tunnel service is not running")
	}
	size := uint32(15000)
	for attempt := 0; attempt < 3; attempt++ {
		if size > 4<<20 {
			break
		}
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return 0, 0, 0, err
		}
		for adapter := first; adapter != nil; adapter = adapter.Next {
			if windows.UTF16PtrToString(adapter.FriendlyName) == name &&
				windowsWireGuardDescription.MatchString(windows.UTF16PtrToString(adapter.Description)) &&
				adapter.OperStatus == windows.IfOperStatusUp && adapter.Luid != 0 {
				return adapter.IfIndex, adapter.Ipv6IfIndex, adapter.Luid, nil
			}
		}
		break
	}
	return 0, 0, 0, errors.New("the configured Windows network interface is not an active WireGuardNT adapter")
}

func imagingDialContext(iface string) (func(context.Context, string, string) (net.Conn, error), error) {
	if _, _, _, err := windowsImagingTunnel(iface); err != nil {
		return nil, err
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ipv4, ipv6, luid, err := windowsImagingTunnel(iface)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{
			Timeout: 15 * time.Second,
			Control: func(network, _ string, socket syscall.RawConn) error {
				// Winsock uses option 31 for IP_UNICAST_IF and IPV6_UNICAST_IF.
				level, index := windows.IPPROTO_IP, int(bits.ReverseBytes32(ipv4))
				switch network {
				case "tcp4":
				case "tcp6":
					level, index = windows.IPPROTO_IPV6, int(ipv6)
				default:
					return errors.New("unexpected internal transfer socket family")
				}
				if index == 0 {
					return errors.New("WireGuard tunnel has no interface index for the destination address family")
				}
				var optionErr error
				if err := socket.Control(func(fd uintptr) {
					optionErr = windows.SetsockoptInt(windows.Handle(fd), level, 31, index)
				}); err != nil {
					return err
				}
				return optionErr
			},
		}
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		check4, check6, checkLUID, err := windowsImagingTunnel(iface)
		if err != nil || checkLUID != luid || check4 != ipv4 || check6 != ipv6 {
			conn.Close()
			return nil, errors.New("WireGuard adapter changed during connection setup")
		}
		return conn, nil
	}, nil
}
