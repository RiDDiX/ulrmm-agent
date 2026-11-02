// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string, links map[string]string) {
	t.Helper()
	for p, v := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if v == "<dir>" {
			os.MkdirAll(full, 0o755)
			continue
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for p, target := range links {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHwmonSensors(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"hwmon0/name": "coretemp\n", "hwmon0/temp1_input": "45000\n", "hwmon0/temp1_label": "Package id 0\n",
		"hwmon0/temp1_max": "80000\n", "hwmon0/temp1_crit": "100000\n",
		"hwmon0/temp2_input": "44000\n", "hwmon0/temp2_label": "Core 0\n",
		"hwmon1/name": "acpitz\n", "hwmon1/temp1_input": "27800\n",
		"hwmon2/name": "nvme\n", "hwmon2/temp1_input": "38850\n",
		"hwmon3/name": "nct6775\n", "hwmon3/temp1_input": "91000\n", "hwmon3/temp1_max": "90000\n",
		"hwmon3/temp2_input": "200000\n",
		"hwmon3/fan1_input":  "1210\n", "hwmon3/fan1_label": "CPU fan\n", "hwmon3/fan2_input": "0\n", "hwmon3/fan2_alarm": "1\n",
		"hwmon3/in0_input": "1104\n", "hwmon3/in1_input": "garbage\n",
	}, nil)

	var names []string
	for _, in := range hwmonInputs(root, "temp") {
		names = append(names, in.name)
	}
	sort.Strings(names)
	// the filters health has always used: no acpitz, no nvme, no per-core coretemp
	if want := []string{"coretemp Package id 0", "nct6775 temp1", "nct6775 temp2"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("hwmon temps %q", names)
	}

	got := map[string]SSensor{}
	for _, s := range hwmonSensors(root) {
		got[s.Name] = s
	}
	pkg := got["coretemp Package id 0"]
	if pkg.Kind != "temp" || pkg.Value != 45 || *pkg.Warn != 80 || *pkg.Crit != 100 || pkg.Status != "ok" || pkg.Unit != "C" || pkg.Source != "hwmon" {
		t.Fatalf("package %+v", pkg)
	}
	if hot := got["nct6775 temp1"]; hot.Status != "warn" || hot.Crit != nil {
		t.Fatalf("hot %+v", hot)
	}
	if _, ok := got["nct6775 temp2"]; ok {
		t.Fatal("200 C must be dropped")
	}
	if f := got["nct6775 CPU fan"]; f.Kind != "fan" || f.Value != 1210 || f.Unit != "rpm" || f.Status != "ok" {
		t.Fatalf("fan %+v", f)
	}
	if f := got["nct6775 fan2"]; f.Status != "alarm" {
		t.Fatalf("fan alarm %+v", f)
	}
	if v := got["nct6775 in0"]; v.Kind != "volt" || v.Value != 1.104 || v.Unit != "V" {
		t.Fatalf("volt %+v", v)
	}
	if len(got) != 5 {
		t.Fatalf("sensors %+v", got)
	}
}

func TestSysIfaces(t *testing.T) {
	root := t.TempDir()
	stats := func(prefix string, v string) map[string]string {
		m := map[string]string{}
		for _, k := range []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"} {
			m[prefix+"/statistics/"+k] = v
		}
		return m
	}
	files := map[string]string{
		"eth0/device": "<dir>", "eth0/operstate": "up\n", "eth0/speed": "1000\n", "eth0/duplex": "full\n",
		"eth0/address": "52:54:00:aa:bb:01\n", "eth0/mtu": "1500\n",
		"eth1/device": "<dir>", "eth1/operstate": "down\n", "eth1/speed": "-1\n", "eth1/duplex": "unknown\n", "eth1/address": "52:54:00:aa:bb:02\n",
		"bond0/bonding/slaves": "eth0 eth1\n", "bond0/operstate": "up\n", "bond0/address": "52:54:00:aa:bb:01\n",
		"br0/bridge": "<dir>", "br0/brif/bond0": "", "br0/operstate": "up\n",
		"vlan10/uevent": "DEVTYPE=vlan\nINTERFACE=vlan10\n", "vlan10/operstate": "lowerlayerdown\n",
		"wlan0/device": "<dir>", "wlan0/wireless": "<dir>", "wlan0/operstate": "dormant\n",
		"lo/operstate": "unknown\n", "veth1234/device": "<dir>", "fwbr100i0/bridge": "<dir>", "tap100i0/device": "<dir>",
		"wg0/operstate": "unknown\n",
	}
	for k, v := range stats("eth0", "7\n") {
		files[k] = v
	}
	writeTree(t, root, files, map[string]string{"eth0/master": "../bond0", "eth1/master": "../bond0", "bond0/master": "../br0"})

	got := map[string]SIface{}
	for _, f := range sysIfaces(root, func(n string) []string { return []string{"addr-of-" + n} }) {
		got[f.Name] = f
	}
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	if want := []string{"bond0", "br0", "eth0", "eth1", "vlan10", "wlan0"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("interfaces %q", names)
	}
	e := got["eth0"]
	if e.Kind != "ether" || e.State != "up" || *e.SpeedMbps != 1000 || *e.Duplex != "full" || e.MAC != "52:54:00:aa:bb:01" || *e.MTU != 1500 ||
		*e.Master != "bond0" || e.RxBytes != 7 || e.TxDrops != 7 || e.Addrs[0] != "addr-of-eth0" {
		t.Fatalf("eth0 %+v", e)
	}
	if e := got["eth1"]; e.State != "down" || e.SpeedMbps != nil || e.Duplex != nil {
		t.Fatalf("eth1 %+v", e)
	}
	if b := got["bond0"]; b.Kind != "bond" || !reflect.DeepEqual(b.Members, []string{"eth0", "eth1"}) || *b.Master != "br0" {
		t.Fatalf("bond0 %+v", b)
	}
	if b := got["br0"]; b.Kind != "bridge" || !reflect.DeepEqual(b.Members, []string{"bond0"}) || b.Master != nil {
		t.Fatalf("br0 %+v", b)
	}
	if got["vlan10"].Kind != "vlan" || got["vlan10"].State != "down" || got["wlan0"].Kind != "wifi" || got["wlan0"].State != "unknown" {
		t.Fatalf("vlan/wifi %+v %+v", got["vlan10"], got["wlan0"])
	}
}

func TestPickUnits(t *testing.T) {
	svcs := mergeSystemd(parseSystemctlUnits(stateFixture(t, "systemctl_list_units.txt")), parseUnitFiles(stateFixture(t, "systemctl_list_unit_files.txt")))
	total, failed, units := pickUnits(svcs)
	var got []string
	for _, u := range units {
		got = append(got, u.Name+"|"+u.Active+"|"+u.Sub)
	}
	want := []string{
		"backup-sync.service|failed|failed",
		"db-migrate.service|activating|start-pre",
		"nginx.service|reloading|reload",
		"worker.service|deactivating|stop-sigterm",
		"mail-relay.service|inactive|dead",
		"unloaded-enabled.service|inactive|dead",
	}
	if total != 9 || failed != 1 || !reflect.DeepEqual(got, want) {
		t.Fatalf("total %d failed %d\n got %q\nwant %q", total, failed, got, want)
	}
	if units[0].Description != "Nightly backup sync" || units[0].Enabled == nil || !*units[0].Enabled {
		t.Fatalf("unit fields %+v", units[0])
	}
	// the services RPC keeps its mapping: activating stays unknown, reloading running
	for _, s := range svcs {
		if s.Unit == "db-migrate.service" && s.State != "unknown" || s.Unit == "nginx.service" && s.State != "running" {
			t.Fatalf("PosixServices status changed: %+v", s.UnixService)
		}
	}
}

func TestDoneOneshots(t *testing.T) {
	out := "Type=oneshot\nResult=success\nId=grub-common.service\n\nType=simple\nResult=success\nId=mail-relay.service\n\nType=oneshot\nResult=exit-code\nId=fsck.service\n"
	if got := doneOneshots(out); !reflect.DeepEqual(got, map[string]bool{"grub-common.service": true}) {
		t.Fatalf("%v", got)
	}
}

func TestUnixHTTP(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "engine.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `[]`) })}
	go srv.Serve(l)
	defer srv.Close()
	items, err := dockerItems(context.Background(), unixHTTP(sock), "http://engine", "docker", true)
	if err != nil || len(items) != 0 {
		t.Fatalf("%v %v", items, err)
	}
}
