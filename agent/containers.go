// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

const (
	ctrMax       = 128
	ctrStatsMax  = 32
	ctrParallel  = 8
	ctrAPIBudget = 20 * time.Second
	ctrBodyMax   = 4 << 20
)

func newContainers() *SContainers {
	return &SContainers{Sources: map[string]string{}, Items: []SContainer{}, msgs: map[string]string{}}
}

// ok, or denied when the engine refused us, else error; the text goes to errors
func (c *SContainers) source(kind string, err error) {
	switch {
	case err == nil:
		c.Sources[kind] = "ok"
	case errors.Is(err, os.ErrPermission):
		c.Sources[kind] = "denied"
		c.msgs[kind] = err.Error()
	default:
		c.Sources[kind] = "error"
		c.msgs[kind] = err.Error()
	}
}

func ctrState(s string) string {
	switch s = strings.ToLower(s); s {
	case "running", "paused", "restarting", "stopped", "exited", "created":
		return s
	case "frozen":
		return "paused"
	}
	return "unknown"
}

type dockerList []struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

type dockerInspect struct {
	RestartCount int `json:"RestartCount"`
	State        struct {
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
}

type dockerCPU struct {
	Usage struct {
		Total  uint64   `json:"total_usage"`
		PerCPU []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	System uint64 `json:"system_cpu_usage"`
	Online uint32 `json:"online_cpus"`
}

type dockerStats struct {
	CPU    dockerCPU `json:"cpu_stats"`
	PreCPU dockerCPU `json:"precpu_stats"`
	Memory struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		Rx uint64 `json:"rx_bytes"`
		Tx uint64 `json:"tx_bytes"`
	} `json:"networks"`
}

// cpu delta / system delta x online cpus x 100, as the engine API documents it;
// memory without the page cache (inactive_file on cgroup v2, total_inactive_file on v1)
func (s dockerStats) apply(c *SContainer) {
	n := float64(s.CPU.Online)
	if n == 0 {
		n = float64(len(s.CPU.Usage.PerCPU))
	}
	cd := float64(s.CPU.Usage.Total) - float64(s.PreCPU.Usage.Total)
	sd := float64(s.CPU.System) - float64(s.PreCPU.System)
	if s.PreCPU.System > 0 && sd > 0 && cd >= 0 && n > 0 {
		c.CPUPct = ptr(cd / sd * n * 100)
	}
	if s.Memory.Usage > 0 {
		cache := s.Memory.Stats["inactive_file"]
		if v, ok := s.Memory.Stats["total_inactive_file"]; ok {
			cache = v
		}
		used := s.Memory.Usage
		if cache < used {
			used -= cache
		}
		c.MemUsed = ptr(i64(used))
	}
	if s.Memory.Limit > 0 {
		c.MemLimit = ptr(i64(s.Memory.Limit))
	}
	if s.Networks != nil {
		var rx, tx uint64
		for _, v := range s.Networks {
			rx, tx = rx+v.Rx, tx+v.Tx
		}
		c.NetRx, c.NetTx = ptr(i64(rx)), ptr(i64(tx))
	}
}

func apiGet(ctx context.Context, hc *http.Client, url string, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	r, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("engine answered %d", r.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(r.Body, ctrBodyMax)).Decode(v)
}

// Docker engine API (podman speaks it too): list, inspect for the restart
// count, one-shot stats for running ones. 8 at a time, 20 s for all of it.
func dockerItems(ctx context.Context, hc *http.Client, base, kind string, stats bool) ([]SContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, ctrAPIBudget)
	defer cancel()
	var list dockerList
	if err := apiGet(ctx, hc, base+"/containers/json?all=1", &list); err != nil {
		return nil, err
	}
	ret := make([]SContainer, len(list))
	sem := make(chan struct{}, ctrParallel)
	var wg sync.WaitGroup
	nstats := 0
	now := time.Now()
	for i, d := range list {
		c := SContainer{Kind: kind, ID: d.ID, Image: d.Image, State: ctrState(d.State), Status: d.Status}
		if len(d.Names) > 0 {
			c.Name = strings.TrimPrefix(d.Names[0], "/")
		}
		ret[i] = c
		// checks get the whole list, the push only the first ctrMax
		if i >= ctrMax {
			continue
		}
		withStats := stats && c.State == "running" && nstats < ctrStatsMax
		if withStats {
			nstats++
		}
		wg.Add(1)
		go func(c *SContainer, withStats bool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var in dockerInspect
			if apiGet(ctx, hc, base+"/containers/"+c.ID+"/json", &in) == nil {
				c.Restarts = ptr(in.RestartCount)
				if t, err := time.Parse(time.RFC3339Nano, in.State.StartedAt); err == nil && c.State == "running" && t.Before(now) {
					c.Uptime = ptr(int64(now.Sub(t).Seconds()))
				}
			}
			if withStats {
				var st dockerStats
				if apiGet(ctx, hc, base+"/containers/"+c.ID+"/stats?stream=false", &st) == nil {
					st.apply(c)
				}
			}
		}(&ret[i], withStats)
	}
	wg.Wait()
	return ret, nil
}

// lxc|incus list --format json
func parseLxdList(out []byte, kind string, now time.Time) ([]SContainer, error) {
	var l []struct {
		Name       string            `json:"name"`
		Status     string            `json:"status"`
		Type       string            `json:"type"`
		Config     map[string]string `json:"config"`
		LastUsedAt string            `json:"last_used_at"`
		State      *struct {
			Memory struct {
				Usage int64 `json:"usage"`
			} `json:"memory"`
			Network map[string]struct {
				Counters struct {
					Rx int64 `json:"bytes_received"`
					Tx int64 `json:"bytes_sent"`
				} `json:"counters"`
				Type string `json:"type"`
			} `json:"network"`
		} `json:"state"`
	}
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, err
	}
	var ret []SContainer
	for _, x := range l {
		c := SContainer{Kind: kind, ID: x.Name, Name: x.Name, Image: x.Config["image.description"], State: ctrState(x.Status), Status: x.Status}
		if x.Type != "" {
			c.Status = x.Status + ", " + x.Type
		}
		if s := x.State; s != nil && c.State == "running" {
			c.MemUsed = ptr(s.Memory.Usage)
			var rx, tx int64
			for _, n := range s.Network {
				if n.Type != "loopback" {
					rx, tx = rx+n.Counters.Rx, tx+n.Counters.Tx
				}
			}
			c.NetRx, c.NetTx = ptr(rx), ptr(tx)
			if t, err := time.Parse(time.RFC3339Nano, x.LastUsedAt); err == nil && t.Before(now) && t.Year() > 2000 {
				c.Uptime = ptr(int64(now.Sub(t).Seconds()))
			}
		}
		ret = append(ret, c)
	}
	return ret, nil
}

// lxc-ls -f -F NAME,STATE
func parseLxcLs(out string) []SContainer {
	var ret []SContainer
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 2 {
			continue
		}
		ret = append(ret, SContainer{Kind: "lxc", ID: f[0], Name: f[0], State: ctrState(f[1]), Status: f[1]})
	}
	return ret
}

type pveStatus []struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Nodes   int    `json:"nodes"`
	Quorate int    `json:"quorate"`
	Online  int    `json:"online"`
	Local   int    `json:"local"`
}

// pvesh get /cluster/status: the local node name and, in a cluster, quorum
func parsePveStatus(out []byte) (local string, cl *SCluster, err error) {
	var st pveStatus
	if err = json.Unmarshal(out, &st); err != nil {
		return "", nil, err
	}
	nodes, online := 0, 0
	for _, s := range st {
		if s.Type != "node" {
			continue
		}
		nodes++
		if s.Online == 1 {
			online++
		}
		if s.Local == 1 {
			local = s.Name
		}
	}
	for _, s := range st {
		if s.Type == "cluster" {
			cl = &SCluster{Name: s.Name, Quorate: s.Quorate == 1, Nodes: nodes, Online: online}
			if s.Nodes > nodes {
				cl.Nodes = s.Nodes
			}
		}
	}
	return local, cl, nil
}

// pvesh get /cluster/resources --type vm: every node sees every guest, so
// only the local node's; templates never run and are left out
func parsePveResources(out []byte, node string) ([]SContainer, error) {
	var l []struct {
		VMID     int     `json:"vmid"`
		Name     string  `json:"name"`
		Node     string  `json:"node"`
		Status   string  `json:"status"`
		Type     string  `json:"type"`
		CPU      float64 `json:"cpu"`
		Mem      int64   `json:"mem"`
		MaxMem   int64   `json:"maxmem"`
		Uptime   int64   `json:"uptime"`
		NetIn    int64   `json:"netin"`
		NetOut   int64   `json:"netout"`
		Template int     `json:"template"`
	}
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, err
	}
	var ret []SContainer
	for _, x := range l {
		if x.Node != node || x.Template == 1 || (x.Type != "qemu" && x.Type != "lxc") {
			continue
		}
		c := SContainer{Kind: "pve-" + x.Type, ID: strconv.Itoa(x.VMID), Name: x.Name, State: ctrState(x.Status), Status: x.Status, Node: ptr(x.Node)}
		if x.MaxMem > 0 {
			c.MemLimit = ptr(x.MaxMem)
		}
		if c.State == "running" {
			c.CPUPct, c.MemUsed, c.Uptime = ptr(x.CPU*100), ptr(x.Mem), ptr(x.Uptime)
			c.NetRx, c.NetTx = ptr(x.NetIn), ptr(x.NetOut)
		}
		ret = append(ret, c)
	}
	return ret, nil
}

// Get-VM through ConvertTo-Json: one VM is an object, not a list; State and
// Uptime come as text and seconds from our Select-Object, as enum number and
// TimeSpan object from a plain one
func parseGetVM(out []byte) ([]SContainer, error) {
	type vm struct {
		ID             json.RawMessage `json:"Id"`
		Name           string          `json:"Name"`
		State          json.RawMessage `json:"State"`
		CPUUsage       *float64        `json:"CPUUsage"`
		MemoryAssigned *int64          `json:"MemoryAssigned"`
		Uptime         json.RawMessage `json:"Uptime"`
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return []SContainer{}, nil
	}
	if strings.HasPrefix(s, "{") {
		s = "[" + s + "]"
	}
	var l []vm
	if err := json.Unmarshal([]byte(s), &l); err != nil {
		return nil, err
	}
	// Microsoft.HyperV.PowerShell.VMState
	names := map[int]string{1: "Other", 2: "Running", 3: "Off", 4: "Stopping", 6: "Saved", 9: "Paused", 10: "Starting", 11: "Reset", 32773: "Saving", 32776: "Pausing", 32777: "Resuming", 32779: "FastSaved", 32780: "FastSaving"}
	var ret []SContainer
	for _, v := range l {
		c := SContainer{Kind: "hyperv", Name: v.Name, State: "unknown"}
		var id struct{ Guid string }
		if json.Unmarshal(v.ID, &c.ID) != nil && json.Unmarshal(v.ID, &id) == nil {
			c.ID = id.Guid
		}
		var n int
		if json.Unmarshal(v.State, &c.Status) != nil && json.Unmarshal(v.State, &n) == nil {
			c.Status = names[n]
		}
		switch c.Status {
		case "Running":
			c.State = "running"
		case "Off", "Saved", "FastSaved":
			c.State = "stopped"
		case "Paused":
			c.State = "paused"
		}
		var up float64
		var span struct{ TotalSeconds float64 }
		if json.Unmarshal(v.Uptime, &up) != nil && json.Unmarshal(v.Uptime, &span) == nil {
			up = span.TotalSeconds
		}
		if c.State == "running" {
			c.Uptime = ptr(int64(up))
			if v.CPUUsage != nil {
				c.CPUPct = v.CPUUsage
			}
			if v.MemoryAssigned != nil {
				c.MemUsed = v.MemoryAssigned
			}
		}
		ret = append(ret, c)
	}
	return ret, nil
}

func (a *Agent) ContainerChecks(checks []rmm.CheckDef) {
	ctx, cancel := context.WithTimeout(context.Background(), stateDeadline)
	defer cancel()
	ct := collectContainers(ctx, false)
	for _, c := range checks {
		status, info := containerVerdict(c, ct)
		a.sendCheckResult(WinSvcCheckResult{resultHead: a.checkHead(c), Info: info, State: status})
	}
}

// id (exact or a prefix of 12 and more) or name, in container_kind when set
func containerVerdict(c rmm.CheckDef, ct *SContainers) (status, info string) {
	want := c.Container
	for _, x := range ct.Items {
		if c.ContainerKind != "" && x.Kind != c.ContainerKind {
			continue
		}
		if x.ID == want || x.Name == want || (len(want) >= 12 && strings.HasPrefix(x.ID, want)) {
			info = x.State
			if x.Status != "" {
				info += ": " + x.Status
			}
			if x.State == "running" {
				return "passing", info
			}
			return "failing", info
		}
	}
	kinds := make([]string, 0, len(ct.Sources))
	for k := range ct.Sources {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		if st := ct.Sources[kind]; st != "ok" && (c.ContainerKind == "" || c.ContainerKind == kind) {
			msg := ct.Sources[kind]
			if m := ct.msgs[kind]; m != "" {
				msg = m
			}
			return "failing", kind + ": " + msg
		}
	}
	info = fmt.Sprintf("Container %s not found", want)
	if c.OKIfMissing {
		return "passing", info
	}
	return "failing", info
}
