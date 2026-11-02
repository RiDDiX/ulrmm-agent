// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ethtoolWolinfo struct {
	Cmd, Supported, Wolopts uint32
	Sopass                  [6]byte // SecureOn password, never read
}

type ifreqData struct {
	Name [unix.IFNAMSIZ]byte
	Data unsafe.Pointer
	_    [16]byte
}

// ETHTOOL_GWOL per nic, no ethtool binary needed
func wolStates(names []string) map[string]string {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(fd)
	ret := make(map[string]string)
	for _, n := range names {
		if len(n) >= unix.IFNAMSIZ {
			continue
		}
		w := ethtoolWolinfo{Cmd: 0x5}
		var ifr ifreqData
		copy(ifr.Name[:], n)
		ifr.Data = unsafe.Pointer(&w)
		_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0x8946, uintptr(unsafe.Pointer(&ifr)))
		runtime.KeepAlive(&w)
		if e == 0 {
			ret[n] = ethtoolWoL(w.Supported, w.Wolopts)
		}
	}
	return ret
}

type nvmeAdminCmd struct {
	Opcode, Flags                                     uint8
	Rsvd1                                             uint16
	NSID, Cdw2, Cdw3                                  uint32
	Metadata, Addr                                    uint64
	MetadataLen, DataLen                              uint32
	Cdw10, Cdw11, Cdw12, Cdw13, Cdw14, Cdw15, Timeout uint32
	Result                                            uint32
}

// NVME_IOCTL_ADMIN_CMD, Get Log Page 0x02 (SMART / Health), hardcoded
func nvmeSmartLog(dev string) ([]byte, error) {
	f, err := os.Open(dev)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 512)
	c := nvmeAdminCmd{Opcode: 0x02, NSID: 0xFFFFFFFF, Addr: uint64(uintptr(unsafe.Pointer(&buf[0]))), DataLen: 512, Cdw10: 127<<16 | 0x02, Timeout: 5000}
	_, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), 0xC0484E41, uintptr(unsafe.Pointer(&c)))
	runtime.KeepAlive(buf)
	if e != 0 {
		return nil, e
	}
	return buf, nil
}

func readInt(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

func readStr(path string) string {
	b, _ := os.ReadFile(path)
	return clip(string(b), 64)
}

func milliC(path string, limit bool) *int {
	if n, ok := readInt(path); ok {
		return saneC(float64(n)/1000, limit)
	}
	return nil
}

var nvmeNameRe = regexp.MustCompile(`^nvme[0-9]{1,3}$`)

func collectHealth(ctx context.Context, h *Health) {
	if b, err := os.ReadFile("/sys/power/state"); err == nil {
		h.Power.S3 = ptr(strings.Contains(string(b), "mem"))
	}
	linuxSecurity(ctx, h)
	linuxDisks(ctx, h)
	linuxBattery(h)
	linuxTemps(h)
}

// reported, not alerted: ClamAV and ufw/firewalld/nftables
func linuxSecurity(ctx context.Context, h *Health) {
	h.AV = make([]HAV, 0)
	if _, err := exec.LookPath("clamscan"); err == nil {
		on := false
		for _, unit := range []string{"clamav-daemon", "clamd@scan"} {
			if _, err := runOut(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
				on = true
			}
		}
		h.AV = append(h.AV, HAV{Name: "ClamAV", Enabled: on, Src: "clamav"})
	}

	fw := &HFirewall{Products: make([]HFwProduct, 0)}
	if _, err := exec.LookPath("ufw"); err == nil {
		if out, err := runOut(ctx, "ufw", "status"); err == nil {
			fw.Products = append(fw.Products, HFwProduct{Name: "ufw", Enabled: strings.Contains(out, "Status: active")})
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		out, _ := runOut(ctx, "firewall-cmd", "--state")
		fw.Products = append(fw.Products, HFwProduct{Name: "firewalld", Enabled: strings.TrimSpace(out) == "running"})
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := runOut(ctx, "nft", "-j", "list", "chains"); err == nil {
			fw.Products = append(fw.Products, HFwProduct{Name: "nftables", Enabled: nftHasInputChain([]byte(out))})
		}
	}
	on := false
	for _, p := range fw.Products {
		on = on || p.Enabled
	}
	if len(fw.Products) > 0 {
		fw.Enabled = ptr(on)
	}
	h.Firewall = fw
}

func linuxDisks(ctx context.Context, h *Health) {
	h.Disks = make([]HDisk, 0)
	ents, _ := os.ReadDir("/sys/class/nvme")
	for _, e := range ents {
		n := e.Name()
		if !nvmeNameRe.MatchString(n) {
			continue
		}
		buf, err := nvmeSmartLog("/dev/" + n)
		if err != nil {
			h.errf("%s: %v", n, err)
			continue
		}
		d, ok := parseNvmeLog(buf)
		if !ok {
			continue
		}
		d.Name = strings.TrimSpace(readStr("/sys/class/nvme/" + n + "/model"))
		if d.Name == "" {
			d.Name = n
		}
		// composite sensor limits from the nvme hwmon (WCTEMP/CCTEMP)
		if hw, _ := filepath.Glob("/sys/class/nvme/" + n + "/hwmon*"); len(hw) > 0 {
			d.TempWarnC = milliC(hw[0]+"/temp1_max", true)
			d.TempCritC = milliC(hw[0]+"/temp1_crit", true)
		}
		h.addDisk(d)
	}

	// the ioctl above has the NVMe disks
	smartctlDisks(ctx, h, true)
}

func linuxBattery(h *Health) {
	bats, _ := filepath.Glob("/sys/class/power_supply/BAT*")
	for _, b := range bats {
		full, ok1 := readInt(b + "/energy_full")
		design, ok2 := readInt(b + "/energy_full_design")
		if !ok1 || !ok2 {
			full, ok1 = readInt(b + "/charge_full")
			design, ok2 = readInt(b + "/charge_full_design")
		}
		bat := &HBattery{Condition: readStr(b + "/health")}
		if ok1 && ok2 && design > 0 {
			bat.MaxCapacityPct = ptr(int(full * 100 / design))
		}
		if c, ok := readInt(b + "/cycle_count"); ok && c > 0 {
			bat.Cycles = ptr(int(c))
		}
		h.Battery = bat
		return
	}
}

const hwmonRoot = "/sys/class/hwmon"

type hwmonInput struct {
	name, base string
	v          int64
}

// hwmon <kind>*_input files (temp, fan, in). acpitz is a static value on the hosts
// measured, nvme is already in disks with its limits, per-core coretemp adds
// nothing to the package.
func hwmonInputs(root, kind string) []hwmonInput {
	var ret []hwmonInput
	inputs, _ := filepath.Glob(filepath.Join(root, "hwmon*", kind+"*_input"))
	for _, in := range inputs {
		dir := filepath.Dir(in)
		chip := readStr(dir + "/name")
		base := strings.TrimSuffix(in, "_input")
		label := readStr(base + "_label")
		if chip == "acpitz" || chip == "nvme" || (chip == "coretemp" && strings.HasPrefix(label, "Core ")) {
			continue
		}
		v, ok := readInt(in)
		if !ok {
			continue
		}
		if label == "" {
			label = filepath.Base(base)
		}
		ret = append(ret, hwmonInput{chip + " " + label, base, v})
	}
	return ret
}

func linuxTemps(h *Health) {
	h.Temps = make([]HTemp, 0)
	for _, in := range hwmonInputs(hwmonRoot, "temp") {
		c := saneC(float64(in.v)/1000, false)
		if c == nil {
			continue
		}
		h.addTemp(HTemp{Name: clip(in.name, 64), C: *c, WarnC: milliC(in.base+"_max", true), CritC: milliC(in.base+"_crit", true)})
	}
}
