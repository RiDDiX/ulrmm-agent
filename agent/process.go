// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/user"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/elastic/go-sysinfo"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

type procSample struct {
	name  string
	user  string
	mem   uint64
	cpu   time.Duration
	start int64 // ms, 0 where unknown (macOS, FreeBSD)
}

// last sample; the next request measures CPU against it
var procCPU struct {
	sync.Mutex
	at   time.Time
	last map[int]procSample
	msgs []rmm.ProcInfo
}

const (
	procMinWindow = 500 * time.Millisecond
	procMaxAge    = time.Minute
)

// all processor groups on Windows; runtime.NumCPU stops at the first one
var cpuCount = sync.OnceValue(func() int {
	if n, err := cpu.Counts(true); err == nil && n > 0 {
		return n
	}
	return runtime.NumCPU()
})

// CPU is the share of the whole machine since the previous request, or over
// a short window when there is none. Calls inside the window reuse the last
// answer.
func (a *Agent) GetProcsRPC() []rmm.ProcInfo {
	procCPU.Lock()
	defer procCPU.Unlock()
	if procCPU.msgs != nil && time.Since(procCPU.at) < procMinWindow {
		return procCPU.msgs
	}
	if procCPU.last == nil || time.Since(procCPU.at) > procMaxAge {
		base, err := readProcs()
		if err != nil {
			a.Logger.Debugln("GetProcsRPC():", err)
			return []rmm.ProcInfo{}
		}
		procCPU.last, procCPU.at = base, time.Now()
		time.Sleep(procMinWindow)
	}
	cur, err := readProcs()
	if err != nil {
		a.Logger.Debugln("GetProcsRPC():", err)
		return []rmm.ProcInfo{}
	}
	now := time.Now()
	procCPU.msgs = procMsgs(procCPU.last, cur, now.Sub(procCPU.at), cpuCount())
	procCPU.last, procCPU.at = cur, now
	return procCPU.msgs
}

// id is the position in pid order; the table uses it as the row key.
func procMsgs(prev, cur map[int]procSample, window time.Duration, ncpu int) []rmm.ProcInfo {
	pids := make([]int, 0, len(cur))
	for pid := range cur {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	ret := make([]rmm.ProcInfo, 0, len(pids))
	for i, pid := range pids {
		c := cur[pid]
		used := c.cpu
		// same process only if start time matches and CPU time did not go
		// down; names are not identity, Linux kworkers rename
		if p, ok := prev[pid]; ok && p.start == c.start && p.cpu <= c.cpu {
			used = c.cpu - p.cpu
		}
		pct := 0.0
		if window > 0 && ncpu > 0 {
			pct = math.Min(100, float64(used)/float64(window)/float64(ncpu)*100)
		}
		ret = append(ret, rmm.ProcInfo{
			ProcName: c.name,
			PID:      pid,
			RSSBytes: c.mem,
			Owner:    c.user,
			RowID:    i,
			CPUPct:   fmt.Sprintf("%.1f", pct),
		})
	}
	return ret
}

// PID 0 is left out.
func readProcs() (map[int]procSample, error) {
	switch runtime.GOOS {
	case "darwin":
		// built without cgo: process libraries cannot read names, memory
		// or CPU time; one ps call instead
		out, err := runOut(context.Background(), "/bin/ps", "-axo", "pid=,uid=,rss=,time=,comm=")
		if err != nil {
			return nil, err
		}
		return parsePs(out, uidName), nil
	case "freebsd":
		// go-sysinfo has no FreeBSD provider. FreeBSD ps takes everything
		// after the first = as that column's header, so one -o per column.
		out, err := runOut(context.Background(), "/bin/ps", "-ax", "-o", "pid=", "-o", "uid=", "-o", "rss=", "-o", "time=", "-o", "comm=")
		if err != nil {
			return nil, err
		}
		return parsePs(out, uidName), nil
	}
	procs, err := sysinfo.Processes()
	if err != nil {
		return nil, err
	}
	ret := make(map[int]procSample, len(procs))
	for _, p := range procs {
		info, err := p.Info()
		if err != nil || info.PID == 0 {
			continue
		}
		s := procSample{name: info.Name, start: info.StartTime.UnixMilli()}
		if m, err := p.Memory(); err == nil {
			s.mem = m.Resident
		}
		if t, err := p.CPUTime(); err == nil {
			s.cpu = t.User + t.System
		}
		if gp, err := process.NewProcess(int32(info.PID)); err == nil {
			s.user, _ = gp.Username()
		}
		// uid or SID when no account name resolves, e.g. container users
		if s.user == "" {
			if u, err := p.User(); err == nil {
				s.user = u.UID
			}
		}
		ret[info.PID] = s
	}
	return ret, nil
}

var uidNames sync.Map

func uidName(uid string) string {
	if n, ok := uidNames.Load(uid); ok {
		return n.(string)
	}
	n := uid
	if u, err := user.LookupId(uid); err == nil {
		n = u.Username
	}
	uidNames.Store(uid, n)
	return n
}

// Lines of ps -axo pid=,uid=,rss=,time=,comm=. comm is last because it may
// hold spaces; macOS prints the executable path, the name is its base.
func parsePs(out string, userOf func(uid string) string) map[int]procSample {
	ret := map[int]procSample{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid == 0 {
			continue
		}
		rss, _ := strconv.ParseUint(f[2], 10, 64)
		comm := strings.TrimSpace(line)
		for range 4 {
			comm = strings.TrimLeft(comm[strings.IndexAny(comm, " \t"):], " \t")
		}
		ret[pid] = procSample{
			name: path.Base(comm),
			user: userOf(f[1]),
			mem:  rss * 1024,
			cpu:  parseCPUTime(f[3]),
		}
	}
	return ret
}

// [[dd-]hh:]mm:ss[.ff], as ps prints the time column
func parseCPUTime(s string) time.Duration {
	// a comma when ps runs under a German locale
	s = strings.ReplaceAll(s, ",", ".")
	var d time.Duration
	if days, rest, ok := strings.Cut(s, "-"); ok {
		n, _ := strconv.Atoi(days)
		d, s = time.Duration(n)*24*time.Hour, rest
	}
	parts := strings.Split(s, ":")
	unit := time.Second
	for i := len(parts) - 1; i >= 0; i-- {
		v, _ := strconv.ParseFloat(parts[i], 64)
		d += time.Duration(v * float64(unit))
		if unit < time.Hour {
			unit *= 60
		}
	}
	return d
}

type procEntry struct {
	pid    int32
	ppid   int32
	name   string
	exe    string
	create int64 // ms since the epoch, 0 where unknown
}

// Without details, only pid and ppid; gopsutil starts lsof and ps per
// process for name and exe on macOS. The creation time is read on Windows
// only: orphans keep the pid of their dead parent there, and that pid can
// be reused.
func listProcs(details bool) []procEntry {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}
	ret := make([]procEntry, 0, len(procs))
	for _, p := range procs {
		e := procEntry{pid: p.Pid}
		e.ppid, _ = p.Ppid()
		if details {
			e.name, _ = p.Name()
			e.exe, _ = p.Exe()
		}
		if runtime.GOOS == "windows" {
			e.create, _ = p.CreateTime()
		}
		ret = append(ret, e)
	}
	return ret
}

// A process older than the one its ppid names is an orphan whose parent
// pid was reused, not a child.
func descendants(pid int32, procs []procEntry) []int32 {
	created := make(map[int32]int64, len(procs))
	for _, p := range procs {
		created[p.pid] = p.create
	}
	children := map[int32][]int32{}
	for _, p := range procs {
		if parent := created[p.ppid]; p.pid != p.ppid && (p.create == 0 || p.create >= parent) {
			children[p.ppid] = append(children[p.ppid], p.pid)
		}
	}
	var ret []int32
	seen := map[int32]bool{pid: true}
	queue := []int32{pid}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if !seen[c] {
				seen[c] = true
				ret = append(ret, c)
				queue = append(queue, c)
			}
		}
	}
	return ret
}

func protectedPID(pid int32) bool {
	return pid <= 1 || int(pid) == os.Getpid() || (runtime.GOOS == "windows" && pid == 4)
}

// Errors ignored.
func killTree(pid int32) {
	for _, c := range descendants(pid, listProcs(false)) {
		if protectedPID(c) {
			continue
		}
		if p, err := process.NewProcess(c); err == nil {
			_ = p.Kill()
		}
	}
}

// Refuses the system's first process, the Windows System process and the agent itself.
func KillProc(pid int32) error {
	if protectedPID(pid) {
		return fmt.Errorf("process %d cannot be killed from the dashboard", pid)
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	killTree(pid)
	return p.Kill()
}

func (a *Agent) KillHungUpdates() {
	for _, p := range listProcs(true) {
		if strings.Contains(p.exe, IdentArtifact+"-v") {
			if err := KillProc(p.pid); err != nil {
				a.Logger.Debugln("KillHungUpdates():", err)
			}
		}
	}
}
