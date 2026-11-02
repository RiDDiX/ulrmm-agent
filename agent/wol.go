// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
)

// One wmi_detail["nics"] entry. Server uses the MAC for WoL.
// wol: on|off|unsupported (omitted if OS silent)
type NIC struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
	WoL  string   `json:"wol,omitempty"`
}

func nics() []NIC {
	ret := make([]NIC, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ret
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		if n, ok := toNIC(i, addrs); ok {
			ret = append(ret, n)
		}
	}
	return ret
}

// read only; Suspend() arms the nics
func withWoL(ns []NIC) []NIC {
	names := make([]string, len(ns))
	for i, n := range ns {
		names[i] = n.Name
	}
	st := wolStates(names)
	for i := range ns {
		ns[i].WoL = st[ns[i].Name]
	}
	return ns
}

// ethernet MAC and at least one ipv4, else skip
func toNIC(i net.Interface, addrs []net.Addr) (NIC, bool) {
	if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
		return NIC{}, false
	}
	ips := make([]string, 0)
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ips = append(ips, ipn.String())
		}
	}
	if len(ips) == 0 {
		return NIC{}, false
	}
	return NIC{Name: i.Name, MAC: i.HardwareAddr.String(), IPs: ips}, true
}

// 6 bytes of 0xff, then the mac 16 times
func magicPacket(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil, err
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("not an ethernet mac: %s", mac)
	}
	return append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(hw, 16)...), nil
}

// directed broadcast of an ipv4 cidr
func broadcastAddr(cidr string) (string, bool) {
	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil || ipn.IP.To4() == nil {
		return "", false
	}
	ones, bits := ipn.Mask.Size()
	if bits != 32 || ones > 30 {
		return "", false
	}
	b := make(net.IP, 4)
	for i := range b {
		b[i] = ipn.IP[i] | ^ipn.Mask[i]
	}
	return b.String(), true
}

// udp/9 to 255.255.255.255 and each local subnet broadcast.
// net.Dial udp4 sets SO_BROADCAST. error only when nothing went out.
func sendMagicPackets(macs []string) error {
	targets := []string{"255.255.255.255"}
	for _, n := range nics() {
		for _, ip := range n.IPs {
			if b, ok := broadcastAddr(ip); ok {
				targets = append(targets, b)
			}
		}
	}

	sent := 0
	err := errors.New("no mac address given")
	for _, mac := range macs {
		p, perr := magicPacket(mac)
		if perr != nil {
			err = perr
			continue
		}
		for _, t := range targets {
			c, derr := net.Dial("udp4", net.JoinHostPort(t, "9"))
			if derr != nil {
				err = derr
				continue
			}
			if _, werr := c.Write(p); werr != nil {
				err = werr
			} else {
				sent++
			}
			c.Close()
		}
	}
	if sent == 0 {
		return err
	}
	return nil
}
