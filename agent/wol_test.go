// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"net"
	"testing"
)

func TestMagicPacket(t *testing.T) {
	p, err := magicPacket("00:11:22:AA:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Fatalf("bad header or length %d: %x", len(p), p)
	}
	mac := []byte{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc}
	for i := 6; i < len(p); i += 6 {
		if !bytes.Equal(p[i:i+6], mac) {
			t.Fatalf("mac repeat at %d: %x", i, p[i:i+6])
		}
	}
	for _, bad := range []string{"", "zz:11:22:33:44:55", "00:11:22:33:44:55:66:77"} {
		if _, err := magicPacket(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestBroadcastAddr(t *testing.T) {
	for cidr, want := range map[string]string{
		"192.168.178.20/24": "192.168.178.255",
		"10.1.2.3/8":        "10.255.255.255",
		"172.16.5.9/22":     "172.16.7.255",
	} {
		if got, ok := broadcastAddr(cidr); !ok || got != want {
			t.Fatalf("%s: got %q %v, want %q", cidr, got, ok, want)
		}
	}
	for _, cidr := range []string{"10.0.0.1/32", "10.0.0.1/31", "fe80::1/64", "nope"} {
		if got, ok := broadcastAddr(cidr); ok {
			t.Fatalf("%s: got %q", cidr, got)
		}
	}
}

func TestToNIC(t *testing.T) {
	eth := net.Interface{
		Name:         "eth0",
		Flags:        net.FlagUp | net.FlagBroadcast,
		HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc},
	}
	v4 := &net.IPNet{IP: net.IPv4(192, 168, 178, 20), Mask: net.CIDRMask(24, 32)}
	v6 := &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}

	n, ok := toNIC(eth, []net.Addr{v6, v4})
	if !ok || n.Name != "eth0" || n.MAC != "00:11:22:aa:bb:cc" ||
		len(n.IPs) != 1 || n.IPs[0] != "192.168.178.20/24" {
		t.Fatalf("got %+v %v", n, ok)
	}

	if _, ok := toNIC(eth, []net.Addr{v6}); ok {
		t.Fatal("card without IPv4 was kept")
	}
	lo := eth
	lo.Flags |= net.FlagLoopback
	if _, ok := toNIC(lo, []net.Addr{v4}); ok {
		t.Fatal("loopback was kept")
	}
	tun := net.Interface{Name: "tun0", Flags: net.FlagUp}
	if _, ok := toNIC(tun, []net.Addr{v4}); ok {
		t.Fatal("card without mac was kept")
	}
}
