// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

func TestDockerStats(t *testing.T) {
	var c SContainer
	var st dockerStats
	for name, check := range map[string]func(){
		// (2.5e9-2e9)/(4e11-3.96e11) x 4 x 100 = 50
		"docker_stats_v2.json": func() {
			if c.CPUPct == nil || math.Abs(*c.CPUPct-50) > 1e-9 || *c.MemUsed != 209715200-52428800 || *c.MemLimit != 1073741824 || *c.NetRx != 1500 || *c.NetTx != 2050 {
				t.Fatalf("v2 %+v", c)
			}
		},
		// no online_cpus: percpu length; v1 cache key wins
		"docker_stats_v1.json": func() {
			if c.CPUPct == nil || math.Abs(*c.CPUPct-10) > 1e-9 || *c.MemUsed != 104857600-20971520 {
				t.Fatalf("v1 %+v", c)
			}
		},
		// no previous sample yet: cpu unknown, nothing invented for memory
		"docker_stats_first.json": func() {
			if c.CPUPct != nil || c.MemUsed != nil || c.MemLimit != nil || c.NetRx != nil {
				t.Fatalf("first %+v", c)
			}
		},
	} {
		c, st = SContainer{}, dockerStats{}
		if err := jsonFixture(t, name, &st); err != nil {
			t.Fatal(err)
		}
		st.apply(&c)
		check()
	}
}

func jsonFixture(t *testing.T, name string, v interface{}) error {
	return json.Unmarshal([]byte(stateFixture(t, name)), v)
}

func TestDockerItems(t *testing.T) {
	var statsCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/containers/json" && r.URL.Query().Get("all") == "1":
			io.WriteString(w, stateFixture(t, "docker_containers.json"))
		case strings.HasSuffix(r.URL.Path, "/json"):
			io.WriteString(w, stateFixture(t, "docker_inspect.json"))
		case strings.HasSuffix(r.URL.Path, "/stats") && r.URL.Query().Get("stream") == "false":
			statsCalls.Add(1)
			io.WriteString(w, stateFixture(t, "docker_stats_v2.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	items, err := dockerItems(context.Background(), ts.Client(), ts.URL, "docker", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || statsCalls.Load() != 1 {
		t.Fatalf("%d items, %d stats calls", len(items), statsCalls.Load())
	}
	web, jobs, cache := items[0], items[1], items[2]
	if web.Name != "web" || web.Image != "nginx:1.27" || web.State != "running" || *web.Restarts != 2 || web.Uptime == nil || web.CPUPct == nil || web.Kind != "docker" {
		t.Fatalf("web %+v", web)
	}
	if jobs.State != "exited" || jobs.Status != "Exited (1) 5 minutes ago" || jobs.CPUPct != nil || jobs.Uptime != nil {
		t.Fatalf("jobs %+v", jobs)
	}
	if cache.State != "restarting" {
		t.Fatalf("cache %+v", cache)
	}

	statsCalls.Store(0)
	if _, err := dockerItems(context.Background(), ts.Client(), ts.URL, "docker", false); err != nil || statsCalls.Load() != 0 {
		t.Fatalf("stats off: %v, %d calls", err, statsCalls.Load())
	}
	if _, err := dockerItems(context.Background(), ts.Client(), ts.URL+"/nope", "docker", false); err == nil {
		t.Fatal("engine error not returned")
	}
}

// a check finds a container past the push cap; only pushed ones are inspected
func TestDockerItemsPastCap(t *testing.T) {
	var inspects atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			list := make([]string, ctrMax+2)
			for i := range list {
				list[i] = fmt.Sprintf(`{"Id":"%064x","Names":["/c%d"],"State":"running"}`, i, i)
			}
			io.WriteString(w, "["+strings.Join(list, ",")+"]")
			return
		}
		inspects.Add(1)
		io.WriteString(w, "{}")
	}))
	defer ts.Close()

	items, err := dockerItems(context.Background(), ts.Client(), ts.URL, "docker", false)
	if err != nil || len(items) != ctrMax+2 || inspects.Load() != ctrMax {
		t.Fatalf("%d items, %d inspects, %v", len(items), inspects.Load(), err)
	}
	ct := newContainers()
	ct.source("docker", nil)
	ct.Items = items
	if s, info := containerVerdict(rmm.CheckDef{Container: fmt.Sprintf("c%d", ctrMax+1)}, ct); s != "passing" {
		t.Fatal(s, info)
	}
}

func TestContainerSources(t *testing.T) {
	ct := newContainers()
	ct.source("docker", nil)
	ct.source("podman", fmt.Errorf("dial unix /run/podman/podman.sock: %w", os.ErrPermission))
	ct.source("lxd", errors.New("lxc: exit status 1"))
	if ct.Sources["docker"] != "ok" || ct.Sources["podman"] != "denied" || ct.Sources["lxd"] != "error" || ct.msgs["docker"] != "" || ct.msgs["lxd"] == "" {
		t.Fatalf("%+v %+v", ct.Sources, ct.msgs)
	}
}

func TestParseLxd(t *testing.T) {
	now := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	l, err := parseLxdList([]byte(stateFixture(t, "lxc_list.json")), "lxd", now)
	if err != nil {
		t.Fatal(err)
	}
	f, vm, held := l[0], l[1], l[2]
	if f.ID != "files" || f.State != "running" || f.Image != "Debian bookworm amd64" || *f.MemUsed != 268435456 || *f.NetRx != 4096 || *f.NetTx != 8192 || *f.Uptime != 7200 {
		t.Fatalf("files %+v", f)
	}
	if vm.State != "stopped" || vm.Status != "Stopped, virtual-machine" || vm.MemUsed != nil || vm.Uptime != nil {
		t.Fatalf("vm %+v", vm)
	}
	if held.State != "paused" {
		t.Fatalf("frozen %+v", held)
	}
	ls := parseLxcLs(stateFixture(t, "lxc_ls.txt"))
	if len(ls) != 3 || ls[0].Name != "build01" || ls[0].State != "running" || ls[1].State != "stopped" || ls[2].State != "paused" || ls[0].Kind != "lxc" {
		t.Fatalf("lxc-ls %+v", ls)
	}
}

func TestParsePve(t *testing.T) {
	local, cl, err := parsePveStatus([]byte(stateFixture(t, "pvesh_cluster_status.json")))
	if err != nil || local != "pve-a" || cl == nil || *cl != (SCluster{Name: "lab", Quorate: true, Nodes: 3, Online: 2}) {
		t.Fatalf("status %q %+v %v", local, cl, err)
	}
	local, cl, err = parsePveStatus([]byte(stateFixture(t, "pvesh_status_single.json")))
	if err != nil || local != "pve-solo" || cl != nil {
		t.Fatalf("single node %q %+v %v", local, cl, err)
	}
	l, err := parsePveResources([]byte(stateFixture(t, "pvesh_resources.json")), "pve-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 {
		t.Fatalf("other node, template or storage leaked in: %+v", l)
	}
	q, c := l[0], l[1]
	if q.Kind != "pve-qemu" || q.ID != "100" || q.Name != "dc01" || q.State != "running" || math.Abs(*q.CPUPct-5.25) > 1e-9 ||
		*q.MemUsed != 4294967296 || *q.MemLimit != 8589934592 || *q.Uptime != 86400 || *q.NetRx != 123456 || *q.Node != "pve-a" {
		t.Fatalf("qemu %+v", q)
	}
	if c.Kind != "pve-lxc" || c.State != "stopped" || c.CPUPct != nil || c.Uptime != nil {
		t.Fatalf("lxc %+v", c)
	}
}

func TestParseGetVM(t *testing.T) {
	l, err := parseGetVM([]byte(stateFixture(t, "getvm.json")))
	if err != nil || len(l) != 2 {
		t.Fatalf("%+v %v", l, err)
	}
	if l[0].ID != "6f1c2a9e-1111-4c2b-9a77-0d1e2f3a4b5c" || l[0].State != "running" || *l[0].CPUPct != 7 || *l[0].MemUsed != 4294967296 || *l[0].Uptime != 3600 || l[0].Kind != "hyperv" {
		t.Fatalf("running %+v", l[0])
	}
	if l[1].State != "stopped" || l[1].Status != "Off" || l[1].Uptime != nil {
		t.Fatalf("off %+v", l[1])
	}
	// a single VM is an object; enum number and TimeSpan from a plain Get-VM
	l, err = parseGetVM([]byte(stateFixture(t, "getvm_single_raw.json")))
	if err != nil || len(l) != 1 || l[0].ID != "7a7b7c7d-3333-4e5f-8a9b-c0d1e2f3a4b5" || l[0].Status != "Running" || *l[0].Uptime != 72900 {
		t.Fatalf("single %+v %v", l, err)
	}
	if l, err := parseGetVM([]byte("  \r\n")); err != nil || len(l) != 0 {
		t.Fatal("no VMs is an empty list")
	}
}

func TestContainerVerdict(t *testing.T) {
	ct := newContainers()
	ct.source("docker", nil)
	ct.Items = []SContainer{
		{Kind: "docker", ID: "3f4e8a1b2c3d4e5f6071", Name: "web", State: "running", Status: "Up 3 hours"},
		{Kind: "docker", ID: "9a8b7c6d5e4f30211234", Name: "jobs", State: "exited", Status: "Exited (1)"},
		{Kind: "pve-qemu", ID: "100", Name: "web2", State: "running"},
	}
	denied := newContainers()
	denied.source("docker", fmt.Errorf("dial: %w", os.ErrPermission))
	cases := []struct {
		name   string
		c      rmm.CheckDef
		ct     *SContainers
		status string
		info   string
	}{
		{"name", rmm.CheckDef{Container: "web"}, ct, "passing", "running: Up 3 hours"},
		{"id prefix", rmm.CheckDef{Container: "3f4e8a1b2c3d"}, ct, "passing", "running: Up 3 hours"},
		{"short prefix is no match", rmm.CheckDef{Container: "3f4e8a"}, ct, "failing", "Container 3f4e8a not found"},
		{"exact id", rmm.CheckDef{Container: "100", ContainerKind: "pve-qemu"}, ct, "passing", "running"},
		{"stopped", rmm.CheckDef{Container: "jobs"}, ct, "failing", "exited: Exited (1)"},
		{"kind filter", rmm.CheckDef{Container: "web", ContainerKind: "lxd"}, ct, "failing", "Container web not found"},
		{"not found may pass", rmm.CheckDef{Container: "gone", OKIfMissing: true}, ct, "passing", "Container gone not found"},
		{"denied", rmm.CheckDef{Container: "web", OKIfMissing: true}, denied, "failing", "docker: dial: permission denied"},
		{"no engine", rmm.CheckDef{Container: "web"}, newContainers(), "failing", "Container web not found"},
	}
	for _, c := range cases {
		if s, info := containerVerdict(c.c, c.ct); s != c.status || info != c.info {
			t.Fatalf("%s: got %s %q, want %s %q", c.name, s, info, c.status, c.info)
		}
	}
}
