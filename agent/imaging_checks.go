// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// imagingCheck is one readiness check of the backup source; times in ms.
type imagingCheck struct {
	ID         string   `json:"id"`
	State      string   `json:"state"`
	Blocking   bool     `json:"blocking"`
	Detail     string   `json:"detail"`
	Fix        string   `json:"fix"`
	FixArgv    []string `json:"fix_argv"`
	FixedAt    *int64   `json:"fixed_at"`
	ObservedAt int64    `json:"observed_at"`
}

// imagingRunProbe: each OS decides whether its fixes run before the
// capability is read. Tests replace it.
var imagingRunProbe = func(ctx context.Context, a *Agent, autoSetup, smart string) (ImagingCapability, []imagingCheck) {
	now := a.serverNowMs()
	capability, osChecks := imagingOSChecks(autoSetup, now, func() ImagingCapability { return nativeImagingCapability(ctx) })
	return capability, imagingCheckList(capability, a.Health().Disks, smart, osChecks, now)
}

// imagingProbe recomputes the capability and the checks with the fixes the
// config state allows. A result is stored only under the config state it
// read; checks_version is that document's version.
func (a *Agent) imagingProbe(ctx context.Context) ImagingCapability {
	s := &a.imaging
	s.probe.Lock()
	defer s.probe.Unlock()
	s.mu.Lock()
	gen, autoSetup, smart, version := s.gen, s.config.autoSetup(), s.config.smart(), 0
	if s.config.raw != nil {
		version = s.config.version
	}
	s.wakeProbe = false
	s.mu.Unlock()
	capability, checks := imagingRunProbe(ctx, a, autoSetup, smart)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return capability
	}
	if !s.fixesSent {
		imagingKeepFixed(s.checks, checks)
	}
	s.capability, s.checks, s.checksAt, s.checksAtMs = capability, checks, time.Now().Round(0), a.serverNowMs()
	s.checksVersion, s.probeGen, s.fixesSent = version, gen, false
	s.probeSeq++
	return capability
}

// imagingKeepFixed carries a fix no answered poll has reported into the
// next list, so the server sees it once.
func imagingKeepFixed(old, next []imagingCheck) {
	for _, o := range old {
		for i := range next {
			if o.State == "fixed" && next[i].ID == o.ID && next[i].State != "fixed" {
				next[i].State, next[i].Fix, next[i].FixArgv, next[i].FixedAt = o.State, o.Fix, o.FixArgv, o.FixedAt
			}
		}
	}
}

// imagingCached is the capability of the last probe; only the first poll
// waits for a probe, every later one goes out first (imagingRecheck).
func (a *Agent) imagingCached(ctx context.Context) ImagingCapability {
	s := &a.imaging
	s.mu.Lock()
	never, capability := s.checksAt.IsZero(), s.capability
	s.mu.Unlock()
	if never {
		return a.imagingProbe(ctx)
	}
	return capability
}

// imagingRecheck tells whether to probe after a poll: once the config state
// was acknowledged, for a new state or a server wake (both sent at once),
// on every poll while the source is not ready, and after 6 h when it is.
func (a *Agent) imagingRecheck() (due, wake bool) {
	s := &a.imaging
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reportedGen != s.gen {
		return false, false
	}
	wake = s.probeGen != s.gen || s.wakeProbe
	return wake || !s.capability.Ready || time.Since(s.checksAt) >= imagingProbeEvery, wake
}

func imagingCheckList(capability ImagingCapability, disks []HDisk, smart string, osChecks []imagingCheck, now int64) []imagingCheck {
	method := imagingCheck{ID: "method." + capability.Method, State: "ok", Blocking: true}
	if !capability.Ready {
		method.State, method.Detail = "missing", capability.Reason
	}
	list := append([]imagingCheck{method, imagingSmartCheck(disks, smart)}, osChecks...)
	for i := range list {
		c := &list[i]
		c.ObservedAt, c.Detail, c.Fix = now, clip(c.Detail, imagingTextMax), clip(c.Fix, imagingTextMax)
		if c.FixArgv == nil {
			c.FixArgv = []string{}
		}
	}
	return list
}

func imagingSmartCheck(disks []HDisk, smart string) imagingCheck {
	c := imagingCheck{ID: "smart.source", State: "ok", Blocking: smart == "abort"}
	if smart == "off" {
		return c
	}
	if bad := imagingBadDisks(disks); len(bad) > 0 {
		c.State, c.Detail = "failed", strings.Join(bad, "; ")
	}
	return c
}

// imagingBadDisks names each disk with a SMART or health warning.
func imagingBadDisks(disks []HDisk) []string {
	var bad []string
	for _, d := range disks {
		if d.Health == "warning" || d.Health == "failing" || d.Smart == "failed" {
			bad = append(bad, fmt.Sprintf("%s: health %s, SMART %s", d.Name, d.Health, d.Smart))
		}
	}
	return bad
}

// imagingServiceCheck reports a Windows service the capture needs. Under
// safe and all a disabled one is set to Manual with run.
func imagingServiceCheck(id, name string, disabled bool, queryErr error, autoSetup string, run func([]string) error, now int64) imagingCheck {
	argv := []string{`C:\Windows\System32\sc.exe`, "config", name, "start=", "demand"}
	c := imagingCheck{ID: id, State: "ok", Blocking: true, FixArgv: argv}
	manual := "Set the " + name + " service start type to Manual."
	switch {
	case queryErr != nil:
		// a check that cannot look must not stop a backup that may work
		c.State, c.Blocking, c.Detail = "failed", false, "The start type of "+name+" cannot be read: "+queryErr.Error()
	case !disabled:
	case autoSetup != "safe" && autoSetup != "all":
		c.State, c.Detail, c.Fix = "missing", "The "+name+" service is disabled.", manual
	default:
		if err := run(argv); err != nil {
			c.State, c.Detail, c.Fix = "failed", "Setting "+name+" to Manual failed: "+err.Error(), manual
			break
		}
		c.State, c.Detail, c.Fix, c.FixedAt = "fixed", "The "+name+" service was disabled and is set to Manual.", strings.Join(argv, " "), &now
	}
	return c
}

// imagingArchCheck: an x64 build on ARM64 Windows waits for the native
// ARM64 build (win.arm64), only a 32-bit agent on 64-bit Windows is missing.
func imagingArchCheck(goarch, osArch string) imagingCheck {
	c := imagingCheck{ID: "win.native_arch", State: "ok", Blocking: true}
	if goarch == "386" && osArch != "x86" {
		c.State, c.Detail, c.Fix = "missing", "A 32-bit agent runs on 64-bit Windows.", "Install the 64-bit agent."
	}
	return c
}

// imagingToolsCheck: the base tools are installed by hand in delivery 1,
// with the command of the package manager found. Only ext4 needs dumpe2fs.
func imagingToolsCheck(found func(string) bool, ext4 bool) imagingCheck {
	c := imagingCheck{ID: "linux.tools.base", State: "ok", Blocking: true}
	tools := []string{"lsblk", "blkid"}
	if ext4 {
		tools = append(tools, "dumpe2fs")
	}
	var missing []string
	for _, tool := range tools {
		if !found(tool) {
			missing = append(missing, tool)
		}
	}
	if len(missing) == 0 {
		return c
	}
	c.State, c.Detail, c.Fix = "manual", "Missing tools: "+strings.Join(missing, ", ")+".", "Install util-linux and e2fsprogs."
	for _, m := range [][2]string{
		{"apt-get", "apt-get install -y util-linux e2fsprogs"},
		{"dnf", "dnf install -y util-linux e2fsprogs"},
		{"zypper", "zypper --non-interactive install util-linux e2fsprogs"},
		{"pacman", "pacman -S --noconfirm util-linux e2fsprogs"},
	} {
		if found(m[0]) {
			c.Fix = m[1]
			break
		}
	}
	return c
}
