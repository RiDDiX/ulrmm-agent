// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// START and PARTN come from sysfs: lsblk of util-linux 2.37 (ubuntu 22.04)
// lacks both, 2.38 (debian 12) lacks PARTN.
const linuxFilesColumns = ",PTUUID,PARTFLAGS"
const linuxFilesRecovery = "Boot ULRMM Linux recovery media in UEFI mode and restore onto a blank disk with the same logical sector size that holds the recorded partitions. Extra volumes are not part of the disk restore. Keep the original disk detached: the restored disk carries the same UUIDs."
const linuxFilesRun = "/run/ulrmm-imaging"

var linuxNetworkFS = []string{"cifs", "smb3", "nfs", "nfs4", "ceph", "9p", "glusterfs", "davfs"}

// linuxFilesReadHook runs after the first read of a large file; tests change the file there.
var linuxFilesReadHook func(name string)

// linuxFilesHost is what the live inventory reads from the running system.
type linuxFilesHost struct {
	Disks     []linuxImagingBlock
	MountInfo string
	Fstab     string
	OSRelease string
	DiskIDs   map[string]string // device path -> by-id name
	UEFI      bool
	DMI       string
	Arch      string
	Probe     func(device string) map[string]string
	Used      func(mount string) int64
}

// linuxFilesPlan is a live capability plus the block devices behind it.
type linuxFilesPlan struct {
	ImagingCapability
	disk  linuxImagingBlock
	nodes map[string]linuxImagingBlock // volume id -> device
	host  linuxFilesHost
}

func linuxFilesCurrent(ctx context.Context) linuxFilesPlan {
	read := func(name string) string {
		data, _ := os.ReadFile(name)
		return string(data)
	}
	h := linuxFilesHost{
		MountInfo: read("/proc/self/mountinfo"), Fstab: read("/etc/fstab"), OSRelease: read("/etc/os-release"),
		DMI: read("/sys/class/dmi/id/product_uuid"), Arch: runtime.GOARCH, DiskIDs: map[string]string{},
		Probe: func(device string) map[string]string { return linuxBlkid(ctx, device) },
		Used: func(mount string) int64 {
			var s unix.Statfs_t
			if unix.Statfs(mount, &s) != nil {
				return 0
			}
			return int64(s.Blocks-s.Bfree) * int64(s.Frsize)
		},
	}
	_, err := os.Stat("/sys/firmware/efi")
	h.UEFI = err == nil
	ids, _ := os.ReadDir(linuxDiskIDs)
	for _, id := range ids {
		device, err := filepath.EvalSymlinks(filepath.Join(linuxDiskIDs, id.Name()))
		if err == nil && linuxDiskIDPattern.MatchString(id.Name()) && h.DiskIDs[device] == "" {
			h.DiskIDs[device] = id.Name()
		}
	}
	h.Disks, err = linuxImagingBlocks(ctx, linuxFilesColumns)
	linuxFilesSysfs("/sys/class/block", h.Disks)
	plan := linuxFilesInventory(h)
	if err != nil {
		plan.Ready, plan.Reason = false, err.Error()
	}
	return plan
}

// linuxFilesSysfs reads the start and number of every partition. A value
// that cannot be read stays 0, as lsblk shows it for dm partitions.
func linuxFilesSysfs(dir string, blocks []linuxImagingBlock) {
	for i := range blocks {
		b := &blocks[i]
		read := func(name string) int64 {
			data, _ := os.ReadFile(filepath.Join(dir, filepath.Base(b.Name), name))
			n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			return n
		}
		if b.Type == "part" {
			b.Start, b.PartN = read("start"), int(read("partition"))
		}
		linuxFilesSysfs(dir, b.Children)
	}
}

// linuxFilesChoice keeps the offline method for layouts the live method refuses.
func linuxFilesChoice(live, offline ImagingCapability, offlineErr error) ImagingCapability {
	if live.Ready || offlineErr != nil {
		return live
	}
	offline.Reason = "Live backup unavailable: " + live.Reason + " " + offline.Reason
	return offline
}

func linuxRecoveryBoot() bool {
	cmdline, _ := os.ReadFile("/proc/cmdline")
	return slices.Contains(strings.Fields(string(cmdline)), "ulrmm.recovery=1")
}

func linuxOSRelease(release, key string) string {
	for _, line := range strings.Split(release, "\n") {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(value, "\"")
		}
	}
	return ""
}

func linuxBlkid(ctx context.Context, name string) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, _ := exec.CommandContext(ctx, "blkid", "-p", "-o", "export", name).Output()
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	return values
}

// linuxUnescape decodes the octal escapes of mountinfo, fstab and /proc/swaps.
func linuxUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func linuxFilesInventory(h linuxFilesHost) linuxFilesPlan {
	p := linuxFilesPlan{nodes: map[string]linuxImagingBlock{}, host: h}
	c := &p.ImagingCapability
	c.Method, c.Encryption, c.BootMode, c.Recovery = linuxFilesMethod, "unknown", "bios", linuxFilesRecovery
	if h.UEFI {
		c.BootMode = "uefi"
	}
	if h.Arch == "arm64" {
		c.Recovery += " Disk restore of arm64 points needs arm64 recovery media, which is not available yet."
	}
	c.DeviceUUID = strings.ToLower(strings.TrimSpace(h.DMI))

	type place struct{ node, disk *linuxImagingBlock }
	devices := map[string]place{} // device path, first occurrence in the tree
	sources := map[string]place{} // fstab source -> device
	mounts := map[string]string{} // mount point -> device path
	uuids := map[string]int{}
	var index func(b, disk *linuxImagingBlock)
	index = func(b, disk *linuxImagingBlock) {
		if _, seen := devices[b.Name]; !seen {
			devices[b.Name] = place{b, disk}
			if b.UUID != "" {
				uuids[strings.ToLower(b.UUID)]++
			}
			for _, key := range []string{"UUID=" + strings.ToLower(b.UUID), "PARTUUID=" + strings.ToLower(b.PartUUID), "LABEL=" + b.Label, "PARTLABEL=" + b.PartLabel, b.Name} {
				if _, ok := sources[key]; !ok && !strings.HasSuffix(key, "=") {
					sources[key] = place{b, disk}
				}
			}
		}
		for _, mount := range b.Mounts {
			mounts[mount] = b.Name
		}
		for i := range b.Children {
			index(&b.Children[i], disk)
		}
	}
	var root, system *linuxImagingBlock
	for i := range h.Disks {
		index(&h.Disks[i], &h.Disks[i])
		if r := linuxImagingRoot(&h.Disks[i]); r != nil && root == nil {
			root, system = r, &h.Disks[i]
		}
	}

	var volumes []ImagingVolume
	listed := map[string]bool{}    // mount points
	devListed := map[string]bool{} // device paths
	mounted := map[string]bool{}
	for _, line := range strings.Split(h.MountInfo, "\n") {
		f := strings.Fields(line)
		sep := slices.Index(f, "-")
		if sep < 6 || sep+2 >= len(f) {
			continue
		}
		point, fs := linuxUnescape(f[4]), f[sep+1]
		// an automount point: the file system mounted on it, if any, has its own line
		if fs == "autofs" {
			continue
		}
		mounted[point] = true
		if listed[point] || !utf8.ValidString(point) || len(point) > 255 {
			continue
		}
		v := ImagingVolume{Mount: point, FS: fs[:min(len(fs), 32)]}
		name, block := mounts[point]
		if slices.Contains(linuxNetworkFS, fs) || strings.HasPrefix(fs, "fuse.") {
			v.Kind, v.Reason = "network", "Network storage is not backed up."
		} else {
			// pseudo file systems and further mounts of a listed one stay out
			if !block || f[3] != "/" || devListed[name] {
				continue
			}
			at := devices[name]
			if at.node.Type == "loop" || strings.HasPrefix(name, "/dev/zram") {
				continue
			}
			devListed[name] = true
			v.ID, v.Disk, v.Size, v.Used = strings.ToLower(at.node.UUID), h.DiskIDs[at.disk.Name], at.node.Size, h.Used(point)
			v.Kind, v.Consistency = "extra", "live"
			switch {
			case at.disk == system:
				v.Kind = "system"
			case fs != "ext4" && fs != "xfs":
				v.Reason = v.FS + " volumes are not supported for live backup."
			case at.node.Type != "part" && at.node.Type != "disk":
				v.Reason = "Volumes on LVM, RAID or encryption are not supported yet."
			case v.ID == "":
				v.Reason = "The file system has no UUID."
			case uuids[v.ID] > 1:
				v.Reason = "Another disk carries the same file system UUID."
			}
			if v.Reason != "" {
				v.Kind, v.Consistency = "unsupported", ""
			} else {
				p.nodes[v.ID] = *at.node
			}
		}
		listed[point] = true
		volumes = append(volumes, v)
	}
	for _, line := range strings.Split(h.Fstab, "\n") {
		entry, _, _ := strings.Cut(line, "#")
		f := strings.Fields(entry)
		if len(f) < 3 || (f[2] != "ext4" && f[2] != "xfs") {
			continue
		}
		point := path.Clean(linuxUnescape(f[1]))
		if !strings.HasPrefix(point, "/") || mounted[point] || listed[point] || !utf8.ValidString(point) || len(point) > 255 {
			continue
		}
		source := f[0]
		if link, ok := strings.CutPrefix(source, "/dev/disk/by-"); ok {
			if kind, value, ok := strings.Cut(link, "/"); ok {
				source = strings.ToUpper(kind) + "=" + value
			}
		}
		prefix, value, _ := strings.Cut(source, "=")
		local := strings.HasPrefix(f[0], "/dev/") || prefix == "LABEL" || prefix == "PARTLABEL"
		if prefix == "UUID" || prefix == "PARTUUID" {
			source, local = prefix+"="+strings.ToLower(value), true
		}
		at := sources[source]
		if !local || (at.node != nil && at.disk == system) {
			continue
		}
		v := ImagingVolume{Mount: point, FS: f[2], Kind: "unmounted", Reason: "Not mounted."}
		if prefix == "UUID" {
			v.ID = strings.ToLower(value)
		} else if at.node != nil {
			v.ID = strings.ToLower(at.node.UUID)
		}
		if at.node != nil {
			v.Size, v.Disk = at.node.Size, h.DiskIDs[at.disk.Name]
		}
		v.ID = cmp.Or(v.ID, "fstab:"+point)
		// a file system mounted elsewhere is listed there
		if slices.ContainsFunc(volumes, func(o ImagingVolume) bool { return o.ID == v.ID }) {
			continue
		}
		listed[point] = true
		volumes = append(volumes, v)
	}
	sort.SliceStable(volumes, func(i, j int) bool {
		if a, b := volumes[i].Kind == "system", volumes[j].Kind == "system"; a != b {
			return a
		}
		return volumes[i].Mount < volumes[j].Mount
	})
	c.Volumes = volumes[:min(len(volumes), 64)]
	var shown []string
	for _, v := range c.Volumes {
		if v.Kind == "system" {
			shown = append(shown, v.Mount)
		}
	}
	c.Scope = "Live file backup of the system disk file systems: " + strings.Join(shown, ", ") + "."
	if name := linuxOSRelease(h.OSRelease, "PRETTY_NAME"); name != "" {
		c.Scope = name + ". " + c.Scope
	}

	c.Reason = func() string {
		switch {
		case !h.UEFI:
			return "Live Linux backup requires UEFI."
		case !linuxUUIDPattern.MatchString(c.DeviceUUID) || c.DeviceUUID == "00000000-0000-0000-0000-000000000000" || c.DeviceUUID == "ffffffff-ffff-ffff-ffff-ffffffffffff":
			return "Live Linux backup requires a valid DMI product UUID."
		case h.Arch != "amd64" && h.Arch != "arm64":
			return "Live Linux backup requires x86-64 or arm64."
		case root == nil:
			return "No mounted Linux root could be associated with a local disk"
		}
		what := ""
		switch {
		case root.Type == "lvm":
			what = "LVM"
		case root.Type == "crypt":
			what = "encryption"
		case root.Type != "part":
			what = root.Type
		case root.FSType != "ext4":
			what = root.FSType
		case system.PTType != "gpt":
			what = "a " + cmp.Or(system.PTType, "missing") + " partition table"
		}
		if what != "" {
			return "Live Linux backup needs an ext4 root on a GPT partition. This root uses " + what + "."
		}
		if (system.SectorSize != 512 && system.SectorSize != 4096) || system.Size <= 0 || system.Size%int64(system.SectorSize) != 0 {
			return "Unsupported Linux disk geometry"
		}
		if h.DiskIDs[system.Name] == "" {
			return "The Linux system disk has no supported stable /dev/disk/by-id identifier"
		}
		for _, at := range devices {
			if at.disk != system && slices.ContainsFunc(at.node.Mounts, func(m string) bool { return slices.Contains(linuxImagingRequired, m) }) {
				return "System volumes span more than one disk."
			}
		}
		if _, err := linuxImagingFstab(system.Children, root.Name, h.Fstab); err != nil {
			return err.Error()
		}
		for _, part := range system.Children {
			switch fs := part.FSType; {
			case len(part.Children) != 0 || (fs != "ext4" && fs != "vfat" && fs != "swap" && fs != ""):
				return fmt.Sprintf("%s on the system disk holds %s, which live backup does not support.", part.Name, cmp.Or(fs, "other volumes"))
			case (fs == "ext4" || fs == "vfat") && !devListed[part.Name]:
				return part.Name + " on the system disk is not mounted."
			case part.PartN <= 0 || part.Start <= 0:
				return "Could not read the start and number of " + part.Name + "."
			}
		}
		for _, v := range c.Volumes {
			if v.Kind != "system" {
				continue
			}
			if v.FS == "vfat" && !slices.Contains([]string{"FAT12", "FAT16", "FAT32"}, h.Probe(p.nodes[v.ID].Name)["VERSION"]) {
				return "Could not read the FAT type of the EFI system partition."
			}
			if v.ID == "" || uuids[v.ID] > 1 {
				return "Another disk carries the same UUID as a system volume."
			}
		}
		return ""
	}()
	if c.Reason != "" {
		return p
	}
	p.disk = *system
	c.Ready, c.Reason, c.Encryption = true, "Ready for a live backup.", "unencrypted source"
	c.SourceID, c.Size, c.SectorSize = h.DiskIDs[system.Name], system.Size, system.SectorSize
	for _, part := range system.Children {
		c.MinTargetSize = max(c.MinTargetSize, part.Start*512+part.Size)
	}
	// the backup GPT: 16 KiB of entries and one header sector
	c.MinTargetSize += 16384 + int64(system.SectorSize)
	return p
}

type linuxFilesVolume struct {
	ImagingVolume
	key  string
	node linuxImagingBlock
}

// linuxFilesPreflight compares the approved source with the current one and
// returns the volumes to read in stream order.
func linuxFilesPreflight(approved ImagingCapability, current linuxFilesPlan) ([]linuxFilesVolume, error) {
	c := current.ImagingCapability
	if !c.Ready {
		return nil, errors.New(c.Reason)
	}
	changed := errors.New("The backup source changed.")
	if approved.Method != c.Method || approved.DeviceUUID != c.DeviceUUID || approved.SourceID != c.SourceID ||
		approved.Size != c.Size || approved.SectorSize != c.SectorSize || approved.Scope != c.Scope {
		return nil, changed
	}
	for _, v := range c.Volumes {
		if v.Kind == "system" && !slices.Contains(approved.Include, v.ID) {
			return nil, changed
		}
	}
	queued := map[string]string{}
	for _, v := range approved.Volumes {
		queued[v.ID] = v.Mount
	}
	var selected []linuxFilesVolume
	for _, id := range approved.Include {
		mount, ok := queued[id]
		if !ok {
			mount = id
		}
		i := slices.IndexFunc(c.Volumes, func(v ImagingVolume) bool { return v.ID == id })
		if i < 0 || (c.Volumes[i].Kind != "system" && c.Volumes[i].Kind != "extra") || c.Volumes[i].Mount != mount {
			return nil, fmt.Errorf("Selected volume %s is not mounted.", mount)
		}
		selected = append(selected, linuxFilesVolume{ImagingVolume: c.Volumes[i], node: current.nodes[id]})
	}
	sort.Slice(selected, func(i, j int) bool {
		if a, b := selected[i].Kind == "system", selected[j].Kind == "system"; a != b {
			return a
		}
		return selected[i].Mount < selected[j].Mount
	})
	keys := map[string]bool{}
	for i := range selected {
		v := &selected[i]
		v.key = "x-" + v.ID
		if v.Kind == "system" {
			v.key = map[string]string{"/": "root", "/boot": "boot", "/boot/efi": "esp", "/efi": "esp"}[v.Mount]
			if v.key == "" || keys[v.key] {
				v.key = "s-" + v.ID
			}
		}
		if keys[v.key] {
			return nil, changed
		}
		keys[v.key] = true
	}
	return selected, nil
}

func startLinuxFiles(ctx context.Context, expected ImagingCapability) (io.ReadCloser, error) {
	if !linuxUUIDPattern.MatchString(expected.JobID) {
		return nil, errors.New("live Linux backup requires a valid capture request ID")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	approved, err := json.Marshal(expected)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, self, "imaging-stream", "--point", expected.JobID)
	cmd.SysProcAttr = linuxFilesAttr()
	return linuxFilesStart(cmd, approved, filepath.Join(linuxFilesRun, expected.JobID))
}

// linuxFilesStart starts the child; tests replace it.
var linuxFilesStart = startImagingStream

// linuxFilesAttr: Go makes / private in the child, so its views never reach
// this namespace, and the child dies with the agent. The signal follows the
// thread that starts the child, so that goroutine holds no LockOSThread.
func linuxFilesAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
}

// linuxFilesNice lowers the CPU priority of the walking thread for a
// background run; the I/O class is idle in every run.
func linuxFilesNice(priority string) {
	if priority == "background" {
		linuxSetpriority(unix.PRIO_PROCESS, 0, 10)
	}
}

// linuxSetpriority is unix.Setpriority; tests replace it.
var linuxSetpriority = unix.Setpriority

// imagingStream passes the child's stdout through and turns its end into
// io.EOF only when the child exited 0 and wrote its trailer.
type imagingStream struct {
	cmd     *exec.Cmd
	out     io.ReadCloser
	trailer *os.File
	stderr  imagingTail
	dir     string
	seal    map[string]any
	err     error
	waited  bool
}

func startImagingStream(cmd *exec.Cmd, stdin []byte, dir string) (*imagingStream, error) {
	s := &imagingStream{cmd: cmd, dir: dir}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdin, cmd.Stderr, cmd.ExtraFiles = bytes.NewReader(stdin), &s.stderr, []*os.File{write}
	if s.out, err = cmd.StdoutPipe(); err == nil {
		err = cmd.Start()
	}
	write.Close()
	if err != nil {
		read.Close()
		return nil, err
	}
	s.trailer = read
	return s, nil
}

func (s *imagingStream) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.out.Read(p)
	if err == io.EOF {
		s.err = s.finish()
	} else if err != nil {
		s.err = &imagingStreamError{err.Error()}
	}
	return n, s.err
}

func (s *imagingStream) finish() error {
	data, _ := io.ReadAll(io.LimitReader(s.trailer, 64<<10))
	err := s.cmd.Wait()
	s.waited = true
	var trailer linuxFilesTrailer
	if err == nil && json.Unmarshal(data, &trailer) == nil && trailer.Index.Size > 0 {
		s.seal = map[string]any{"index": trailer.Index, "report": trailer.Report}
		return io.EOF
	}
	reason := s.stderr.last()
	if reason == "" && err != nil {
		reason = err.Error()
	}
	return &imagingStreamError{cmp.Or(reason, "the stream ended without its trailer")}
}

func (s *imagingStream) SealFields() map[string]any { return s.seal }

func (s *imagingStream) Close() error {
	if !s.waited {
		s.cmd.Process.Kill()
		s.cmd.Wait()
		s.waited = true
	}
	s.trailer.Close()
	// The views died with the child's namespace; only empty directories remain.
	entries, _ := os.ReadDir(s.dir)
	for _, entry := range entries {
		unix.Rmdir(filepath.Join(s.dir, entry.Name()))
	}
	unix.Rmdir(s.dir)
	return nil
}

// imagingTail keeps the last 2 KiB of the child's error output.
type imagingTail struct{ b []byte }

func (t *imagingTail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2048 {
		t.b = append([]byte(nil), t.b[len(t.b)-2048:]...)
	}
	return len(p), nil
}

func (t *imagingTail) last() string {
	lines := strings.Split(strings.TrimSpace(string(t.b)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// ImagingStreamCommand writes the live file backup of one approved point to
// stdout. The agent starts it in a mount namespace of its own.
func ImagingStreamCommand(args []string) error {
	f := flag.NewFlagSet("imaging-stream", flag.ContinueOnError)
	point := f.String("point", "", "Approved image UUID")
	if err := f.Parse(args); err != nil {
		return err
	}
	if !linuxUUIDPattern.MatchString(*point) {
		return errors.New("imaging-stream needs the approved image UUID")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	var approved ImagingCapability
	if err != nil || json.Unmarshal(data, &approved) != nil {
		return errors.New("imaging-stream needs the approved source on stdin")
	}
	// The trailer pipe stays out of the tools this process runs.
	unix.CloseOnExec(3)
	// An I/O priority belongs to a thread, and the walk runs on this one.
	runtime.LockOSThread()
	unix.Syscall(unix.SYS_IOPRIO_SET, 1, 0, 3<<13)
	linuxFilesNice(approved.Priority)
	ctx := context.Background()
	plan := linuxFilesCurrent(ctx)
	volumes, err := linuxFilesPreflight(approved, plan)
	if err != nil {
		return err
	}
	swapFiles, skip := linuxSwapFiles(ctx, volumes)
	layout, err := linuxFilesLayout(ctx, plan, volumes, swapFiles, approved.Missing)
	if err != nil {
		return err
	}
	views, err := linuxFilesBind(*point, volumes)
	if err != nil {
		return err
	}
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	trailer, err := writeLinuxFiles(out, layout, views, skip)
	if err == nil {
		err = out.Flush()
	}
	if err != nil {
		return err
	}
	fd := os.NewFile(3, "trailer")
	if err := json.NewEncoder(fd).Encode(trailer); err != nil {
		return err
	}
	return fd.Close()
}

// linuxFilesBind binds every volume read-only and without its submounts at
// /run/ulrmm-imaging/<point>/<key>. The mounts end with this namespace.
func linuxFilesBind(point string, volumes []linuxFilesVolume) ([]linuxFilesView, error) {
	own, err := os.Readlink("/proc/self/ns/mnt")
	host, hostErr := os.Readlink("/proc/1/ns/mnt")
	if err != nil || hostErr != nil || own == host {
		return nil, errors.New("imaging-stream must run in a mount namespace of its own")
	}
	base := filepath.Join(linuxFilesRun, point)
	for _, dir := range []string{linuxFilesRun, base} {
		if err := linuxPrivateDir(dir); err != nil {
			return nil, err
		}
	}
	var views []linuxFilesView
	for _, v := range volumes {
		dir := filepath.Join(base, v.key)
		if err := linuxPrivateDir(dir); err != nil {
			return nil, err
		}
		if err := unix.Mount(v.Mount, dir, "", unix.MS_BIND, ""); err != nil {
			return nil, fmt.Errorf("bind %s: %w", v.Mount, err)
		}
		if err := unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return nil, fmt.Errorf("make the view of %s read-only: %w", v.Mount, err)
		}
		var root, device unix.Stat_t
		if unix.Stat(dir, &root) != nil || unix.Stat(v.node.Name, &device) != nil || root.Dev != uint64(device.Rdev) {
			return nil, fmt.Errorf("Selected volume %s is not mounted.", v.Mount)
		}
		views = append(views, linuxFilesView{key: v.key, dir: dir})
	}
	return views, nil
}

func linuxPrivateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 {
		return fmt.Errorf("%s is not a directory owned by root", dir)
	}
	return nil
}

// linuxSwapFiles finds the active swap files on the selected volumes. The walk
// skips them and the restore creates them again.
func linuxSwapFiles(ctx context.Context, volumes []linuxFilesVolume) ([]map[string]any, map[[2]uint64]bool) {
	data, _ := os.ReadFile("/proc/swaps")
	files, skip := []map[string]any{}, map[[2]uint64]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "file" {
			continue
		}
		name := linuxUnescape(f[0])
		best := -1
		for i, v := range volumes {
			if (v.Mount == "/" || strings.HasPrefix(name, v.Mount+"/")) && (best < 0 || len(v.Mount) > len(volumes[best].Mount)) {
				best = i
			}
		}
		var st, root unix.Stat_t
		if best < 0 || unix.Stat(name, &st) != nil || unix.Stat(volumes[best].Mount, &root) != nil || st.Dev != root.Dev {
			continue
		}
		skip[[2]uint64{st.Dev, st.Ino}] = true
		id := linuxBlkid(ctx, name)
		files = append(files, map[string]any{
			"key": volumes[best].key, "path": strings.TrimPrefix(strings.TrimPrefix(name, volumes[best].Mount), "/"),
			"size": st.Size, "uuid": id["UUID"], "label": id["LABEL"],
		})
	}
	return files, skip
}

func linuxFilesLayout(ctx context.Context, plan linuxFilesPlan, volumes []linuxFilesVolume, swapFiles []map[string]any, missing []string) ([]byte, error) {
	sector := int64(plan.disk.SectorSize)
	partitions, swap := []map[string]any{}, []map[string]any{}
	for _, part := range plan.disk.Children {
		partitions = append(partitions, map[string]any{
			"number": part.PartN, "start": part.Start * 512 / sector, "size": part.Size / sector,
			"type": strings.ToLower(part.PartType), "uuid": strings.ToLower(part.PartUUID), "name": part.PartLabel,
			"attrs": cmp.Or(strings.ToLower(part.PartFlags), "0x0"),
		})
		if part.FSType == "swap" {
			swap = append(swap, map[string]any{"partition": part.PartN, "uuid": strings.ToLower(part.UUID), "label": part.Label, "size": part.Size})
		}
	}
	filesystems := []map[string]any{}
	for _, v := range volumes {
		fs := map[string]any{
			"key": v.key, "mount": v.Mount, "fs": v.FS, "disk": v.Disk, "partition": nil,
			"uuid": v.ID, "label": v.node.Label, "consistency": v.Consistency,
		}
		if v.node.Type == "part" {
			fs["partition"] = v.node.PartN
		}
		switch v.FS {
		case "ext4":
			ext4, err := linuxExt4Settings(ctx, v.node.Name)
			if err != nil {
				return nil, err
			}
			fs["ext4"] = ext4
		case "vfat":
			bits, _ := strconv.Atoi(strings.TrimPrefix(linuxBlkid(ctx, v.node.Name)["VERSION"], "FAT"))
			if bits != 12 && bits != 16 && bits != 32 {
				return nil, errors.New("Could not read the FAT type of the EFI system partition.")
			}
			fs["vfat"] = map[string]any{"fat_bits": bits, "volume_id": strings.ReplaceAll(v.ID, "-", "")}
		}
		filesystems = append(filesystems, fs)
	}
	return json.Marshal(map[string]any{
		"format": 1, "method": linuxFilesMethod, "boot_mode": plan.BootMode, "device_uuid": plan.DeviceUUID,
		"arch":      map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH],
		"os_id":     linuxOSRelease(plan.host.OSRelease, "ID"),
		"efi_entry": linuxEFIBootEntry("/sys/firmware/efi/efivars"),
		"disk": map[string]any{
			"id": plan.SourceID, "size": plan.Size, "sector_size": plan.SectorSize,
			"pttype": plan.disk.PTType, "ptuuid": strings.ToLower(plan.disk.PTUUID), "partitions": partitions,
		},
		"filesystems": filesystems, "swap": swap, "swap_files": swapFiles,
		"missing": append([]string{}, missing...), "fstab": plan.host.Fstab,
	})
}

func linuxExt4Settings(ctx context.Context, device string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dumpe2fs", "-h", device)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read the ext4 settings of %s: %w", device, err)
	}
	var block, inode, count int64
	features := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch key {
		case "Block size":
			block, _ = strconv.ParseInt(value, 10, 64)
		case "Inode size":
			inode, _ = strconv.ParseInt(value, 10, 64)
		case "Inode count":
			count, _ = strconv.ParseInt(value, 10, 64)
		case "Filesystem features":
			for _, feature := range strings.Fields(value) {
				if feature != "needs_recovery" && feature != "orphan_present" {
					features = append(features, feature)
				}
			}
		}
	}
	if block == 0 || inode == 0 || count == 0 || len(features) == 0 {
		return nil, fmt.Errorf("read the ext4 settings of %s: unexpected dumpe2fs output", device)
	}
	return map[string]any{"block_size": block, "inode_size": inode, "inode_count": count, "features": features}, nil
}

const linuxEFIGlobal = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

type linuxEFIEntry struct {
	Loader string `json:"loader"`
	Label  string `json:"label"`
}

func linuxEFIBootEntry(dir string) *linuxEFIEntry {
	current, err := os.ReadFile(filepath.Join(dir, "BootCurrent-"+linuxEFIGlobal))
	if err != nil || len(current) != 6 {
		return nil
	}
	option, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("Boot%04X-%s", binary.LittleEndian.Uint16(current[4:]), linuxEFIGlobal)))
	if err != nil {
		return nil
	}
	return linuxEFILoadOption(option)
}

// linuxEFILoadOption reads the description and the file path node of an
// EFI_LOAD_OPTION behind the 4 attribute bytes efivarfs puts first.
func linuxEFILoadOption(data []byte) *linuxEFIEntry {
	if len(data) < 10 {
		return nil
	}
	pathLen := int(binary.LittleEndian.Uint16(data[8:10]))
	data = data[10:]
	var label []uint16
	for {
		if len(data) < 2 {
			return nil
		}
		c := binary.LittleEndian.Uint16(data)
		data = data[2:]
		if c == 0 {
			break
		}
		label = append(label, c)
	}
	if len(data) < pathLen {
		return nil
	}
	for nodes := data[:pathLen]; len(nodes) >= 4; {
		size := int(binary.LittleEndian.Uint16(nodes[2:4]))
		if size < 4 || size > len(nodes) || (nodes[0] == 0x7f && nodes[1] == 0xff) {
			return nil
		}
		if nodes[0] == 4 && nodes[1] == 4 {
			var name []uint16
			for i := 4; i+1 < size; i += 2 {
				if c := binary.LittleEndian.Uint16(nodes[i:]); c != 0 {
					name = append(name, c)
				} else {
					break
				}
			}
			if len(name) == 0 {
				return nil
			}
			return &linuxEFIEntry{Loader: string(utf16.Decode(name)), Label: string(utf16.Decode(label))}
		}
		nodes = nodes[size:]
	}
	return nil
}

type linuxFilesView struct{ key, dir string }

type linuxFilesCounts struct {
	Entries    int64 `json:"entries"`
	Changed    int64 `json:"changed"`
	Vanished   int64 `json:"vanished"`
	Skipped    int64 `json:"skipped"`
	Reappended int64 `json:"reappended"`
	Padding    int64 `json:"padding_bytes"`
}

type linuxFilesTrailer struct {
	Index struct {
		Offset int64 `json:"offset"`
		Size   int64 `json:"size"`
	} `json:"index"`
	Report linuxFilesCounts `json:"report"`
}

type linuxFilesSkip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type linuxFilesEntry struct {
	Path    string `json:"path,omitempty"`
	PathB64 string `json:"path_b64,omitempty"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	Mode    int64  `json:"mode"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	MtimeNS int64  `json:"mtime_ns"`
	Offset  int64  `json:"offset"`
	Data    int64  `json:"data"`
	SHA256  string `json:"sha256"`
	Changed bool   `json:"changed"`
}

var linuxFilesTypes = map[byte]string{
	tar.TypeReg: "file", tar.TypeDir: "dir", tar.TypeSymlink: "symlink", tar.TypeLink: "hardlink",
	tar.TypeChar: "char", tar.TypeBlock: "block", tar.TypeFifo: "fifo",
}

type linuxFilesWriter struct {
	archive  *tar.Writer
	written  *tarCounter
	index    bytes.Buffer
	zip      *gzip.Writer
	lines    *json.Encoder
	swap     map[[2]uint64]bool
	counts   linuxFilesCounts
	changed  []string
	vanished []string
	skipped  []linuxFilesSkip
	buf      []byte
	// per volume
	dev   uint64
	links map[uint64]string
	again []linuxFilesAgain
}

type linuxFilesAgain struct {
	f    *os.File
	name string
}

// writeLinuxFiles writes the linux-files-v1 tar stream: layout, the volumes in
// order, the index and the report.
func writeLinuxFiles(out io.Writer, layout []byte, views []linuxFilesView, swap map[[2]uint64]bool) (linuxFilesTrailer, error) {
	w := &linuxFilesWriter{written: &tarCounter{w: out}, swap: swap, buf: make([]byte, 1<<20),
		changed: []string{}, vanished: []string{}, skipped: []linuxFilesSkip{}}
	w.archive = tar.NewWriter(w.written)
	w.zip = gzip.NewWriter(&w.index)
	w.lines = json.NewEncoder(w.zip)
	w.lines.SetEscapeHTML(false)
	var t linuxFilesTrailer
	if _, err := w.meta(".ulrmm/layout.json", layout); err != nil {
		return t, err
	}
	for _, v := range views {
		if err := w.volume(v); err != nil {
			return t, err
		}
	}
	if err := w.zip.Close(); err != nil {
		return t, err
	}
	offset, err := w.meta(".ulrmm/index.jsonl.gz", w.index.Bytes())
	if err != nil {
		return t, err
	}
	t.Index.Offset, t.Index.Size, t.Report = offset, int64(w.index.Len()), w.counts
	report, err := json.Marshal(struct {
		Format int `json:"format"`
		linuxFilesCounts
		ChangedPaths  []string         `json:"changed_paths"`
		VanishedPaths []string         `json:"vanished_paths"`
		SkippedPaths  []linuxFilesSkip `json:"skipped_paths"`
	}{1, w.counts, w.changed, w.vanished, w.skipped})
	if err == nil {
		_, err = w.meta(".ulrmm/report.json", report)
	}
	if err == nil {
		err = w.archive.Close()
	}
	return t, err
}

// header writes h by the grid rules and returns the offsets of its own first
// header record and of its data.
func (w *linuxFilesWriter) header(h *tar.Header, anchor bool) (int64, int64, error) {
	if err := w.archive.Flush(); err != nil {
		return 0, 0, err
	}
	before := w.written.n
	if sum := sha256.Sum256([]byte(h.Name)); h.Size < imagingBlock && sum[0] != 0 && !anchor {
		err := w.archive.WriteHeader(h)
		return before, w.written.n, err
	}
	start, err := writeAnchoredHeader(w.archive, w.written, h)
	w.counts.Padding += w.written.n - before - tarHeaderSize(h)
	return start, w.written.n, err
}

func (w *linuxFilesWriter) meta(name string, body []byte) (int64, error) {
	h := &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
	_, data, err := w.header(h, false)
	if err == nil {
		_, err = w.archive.Write(body)
	}
	return data, err
}

func (w *linuxFilesWriter) line(h *tar.Header, offset, data int64, sum string, changed bool) error {
	e := linuxFilesEntry{Type: linuxFilesTypes[h.Typeflag], Size: h.Size, Mode: h.Mode, UID: h.Uid, GID: h.Gid,
		MtimeNS: h.ModTime.UnixNano(), Offset: offset, Data: data, SHA256: sum, Changed: changed}
	if utf8.ValidString(h.Name) {
		e.Path = h.Name
	} else {
		e.PathB64 = base64.StdEncoding.EncodeToString([]byte(h.Name))
	}
	w.counts.Entries++
	return w.lines.Encode(e)
}

func linuxReportPath(name string) string {
	name = strings.ToValidUTF8(name, "�")
	if len(name) > 512 {
		name = strings.ToValidUTF8(name[:512], "")
	}
	return name
}

func (w *linuxFilesWriter) skip(name, reason string) {
	w.counts.Skipped++
	if len(w.skipped) < 100 {
		w.skipped = append(w.skipped, linuxFilesSkip{linuxReportPath(name), reason})
	}
}

// missing records an entry that could not be read. Unless it vanished, an
// unreadable directory (or entry of unknown type) fails the walk: a point
// never holds a volume without a whole subtree.
func (w *linuxFilesWriter) missing(name string, err error, dir bool) error {
	switch {
	// ELOOP: the entry was swapped for a symlink between stat and open
	case errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP):
		w.counts.Vanished++
		if len(w.vanished) < 100 {
			w.vanished = append(w.vanished, linuxReportPath(name))
		}
	case dir || linuxFilesFatal(err):
		return fmt.Errorf("read %s: %w", linuxReportPath(name), err)
	default:
		w.skip(name, "unreadable")
	}
	return nil
}

// linuxFilesFatal reports errors of the walk itself rather than of one entry.
func linuxFilesFatal(err error) bool {
	return errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE)
}

func linuxFilesHeader(name string, typ byte, st *unix.Stat_t, xattrs map[string]string) *tar.Header {
	return &tar.Header{Typeflag: typ, Name: name, Mode: int64(st.Mode & 0o7777), Uid: int(st.Uid), Gid: int(st.Gid),
		ModTime: time.Unix(st.Mtim.Unix()), PAXRecords: xattrs, Format: tar.FormatPAX}
}

func (w *linuxFilesWriter) volume(v linuxFilesView) error {
	fd, err := unix.Open(v.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", v.dir, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	w.dev, w.links, w.again = st.Dev, map[uint64]string{}, nil
	if err := w.dir(fd, "v/"+v.key+"/", &st, true); err != nil {
		return err
	}
	for _, a := range w.again {
		w.counts.Reappended++
		_, err := w.file(a.f, a.name, false)
		a.f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// dir stores a directory and, in byte order, everything below it on the same
// file system.
func (w *linuxFilesWriter) dir(fd int, name string, st *unix.Stat_t, root bool) error {
	xattrs, err := linuxXattrs(func(b []byte) (int, error) { return unix.Flistxattr(fd, b) },
		func(n string, b []byte) (int, error) { return unix.Fgetxattr(fd, n, b) })
	var names []string
	if err == nil {
		names, err = linuxDirNames(fd)
	}
	if err != nil && root {
		return fmt.Errorf("read %s: %w", name, err)
	} else if err != nil {
		return w.missing(name, err, true)
	}
	h := linuxFilesHeader(name, tar.TypeDir, st, xattrs)
	offset, data, err := w.header(h, root)
	if err == nil {
		err = w.line(h, offset, data, "", false)
	}
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, base := range names {
		if err := w.entry(fd, name, base); err != nil {
			return err
		}
	}
	return nil
}

func linuxDirNames(fd int) ([]string, error) {
	var names []string
	buf := make([]byte, 64<<10)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil || n <= 0 {
			return names, err
		}
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
	}
}

func (w *linuxFilesWriter) entry(dirfd int, parent, base string) error {
	name := parent + base
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return w.missing(name, err, true)
	}
	if w.swap[[2]uint64{st.Dev, st.Ino}] {
		w.skip(name, "swap file")
		return nil
	}
	var h *tar.Header
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if st.Dev != w.dev {
			w.skip(name, "other file system")
			return nil
		}
		fd, err := unix.Openat(dirfd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return w.missing(name+"/", err, true)
		}
		defer unix.Close(fd)
		return w.dir(fd, name+"/", &st, false)
	case unix.S_IFREG:
		if target, ok := w.links[st.Ino]; ok && st.Nlink > 1 {
			h = linuxFilesHeader(name, tar.TypeLink, &st, nil)
			h.Linkname = target
			break
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		fd, err := unix.Openat(dirfd, base, flags|unix.O_NOATIME, 0)
		if err == unix.EPERM {
			fd, err = unix.Openat(dirfd, base, flags, 0)
		}
		if err != nil {
			return w.missing(name, err, false)
		}
		f := os.NewFile(uintptr(fd), name)
		again, err := w.file(f, name, true)
		if again {
			w.again = append(w.again, linuxFilesAgain{f, name})
		} else {
			f.Close()
		}
		return err
	case unix.S_IFLNK, unix.S_IFCHR, unix.S_IFBLK, unix.S_IFIFO:
		at := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, base)
		xattrs, err := linuxXattrs(func(b []byte) (int, error) { return unix.Llistxattr(at, b) },
			func(n string, b []byte) (int, error) { return unix.Lgetxattr(at, n, b) })
		if err != nil {
			return w.missing(name, err, false)
		}
		typ := map[uint32]byte{unix.S_IFLNK: tar.TypeSymlink, unix.S_IFCHR: tar.TypeChar, unix.S_IFBLK: tar.TypeBlock, unix.S_IFIFO: tar.TypeFifo}[st.Mode&unix.S_IFMT]
		h = linuxFilesHeader(name, typ, &st, xattrs)
		if typ == tar.TypeSymlink {
			target := make([]byte, 4096)
			n, err := unix.Readlinkat(dirfd, base, target)
			if err != nil {
				return w.missing(name, err, false)
			}
			h.Linkname = string(target[:n])
		} else if typ != tar.TypeFifo {
			h.Devmajor, h.Devminor = int64(unix.Major(uint64(st.Rdev))), int64(unix.Minor(uint64(st.Rdev)))
		}
	default:
		w.skip(name, "socket")
		return nil
	}
	offset, data, err := w.header(h, false)
	if err != nil {
		return err
	}
	return w.line(h, offset, data, "", false)
}

// file stores an open regular file and reports whether it moved while it was
// read: a large file then gets one more copy at the end of its volume.
func (w *linuxFilesWriter) file(f *os.File, name string, first bool) (bool, error) {
	fd := int(f.Fd())
	var st unix.Stat_t
	xattrs, err := linuxXattrs(func(b []byte) (int, error) { return unix.Flistxattr(fd, b) },
		func(n string, b []byte) (int, error) { return unix.Fgetxattr(fd, n, b) })
	if err == nil {
		err = unix.Fstat(fd, &st)
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, w.missing(name, err, false)
	}
	small, stable := st.Size < imagingBlock, true
	var data []byte
	if small {
		if data, stable, err = linuxReadSmall(f, &st); err != nil {
			return false, w.missing(name, err, false)
		}
	}
	h := linuxFilesHeader(name, tar.TypeReg, &st, xattrs)
	h.Size = st.Size
	if small {
		h.Size = int64(len(data))
	}
	offset, start, err := w.header(h, false)
	if err != nil {
		return false, err
	}
	sum := sha256.New()
	content := io.MultiWriter(w.archive, sum)
	bad := false
	if small {
		_, err = content.Write(data)
	} else if bad, err = w.copy(content, f, h.Size); err == nil {
		if linuxFilesReadHook != nil {
			linuxFilesReadHook(name)
		}
		var after unix.Stat_t
		stable = unix.Fstat(fd, &after) == nil && linuxSameFile(&st, &after)
	}
	if err != nil {
		return false, err
	}
	again := first && !small && !stable && !bad
	if bad {
		w.skip(name, "unreadable")
	} else if !stable && !again {
		w.counts.Changed++
		if len(w.changed) < 100 {
			w.changed = append(w.changed, linuxReportPath(name))
		}
	}
	if first && st.Nlink > 1 {
		w.links[st.Ino] = name
	}
	return again, w.line(h, offset, start, hex.EncodeToString(sum.Sum(nil)), bad || !stable)
}

func linuxSameFile(a, b *unix.Stat_t) bool {
	return a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// linuxReadSmall reads a file below one block whole, up to three times until
// it holds still. st becomes the state after the last read.
func linuxReadSmall(f *os.File, st *unix.Stat_t) ([]byte, bool, error) {
	for try := 1; ; try++ {
		// a file that grew past the block stays unstable and is cut there
		data := make([]byte, imagingBlock-1)
		if st.Size < imagingBlock {
			data = data[:st.Size]
		}
		n, err := f.ReadAt(data, 0)
		if err != nil && err != io.EOF {
			return nil, false, err
		}
		var after unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &after); err != nil {
			return nil, false, err
		}
		stable := int64(n) == st.Size && linuxSameFile(st, &after)
		*st = after
		if stable || try == 3 {
			return data[:n], stable, nil
		}
	}
}

// copy writes size bytes of f. Holes and a tail the file lost while it was
// read become zeros; bad reports a read error, after which the rest is zeros.
func (w *linuxFilesWriter) copy(dst io.Writer, f *os.File, size int64) (bad bool, err error) {
	fd := int(f.Fd())
	// chunk is the buffer cut to at most n bytes (this package shadows min)
	chunk := func(n int64) []byte {
		if n < int64(len(w.buf)) {
			return w.buf[:n]
		}
		return w.buf
	}
	zeros := func(n int64) error {
		clear(w.buf)
		for n > 0 {
			k, err := dst.Write(chunk(n))
			if err != nil {
				return err
			}
			n -= int64(k)
		}
		return nil
	}
	for off := int64(0); off < size; {
		data, e := unix.Seek(fd, off, unix.SEEK_DATA)
		if e == unix.ENXIO || data > size {
			data = size
		} else if e != nil {
			data = off
		}
		hole, e := unix.Seek(fd, data, unix.SEEK_HOLE)
		if e != nil || hole <= data || hole > size {
			hole = size
		}
		if err := zeros(data - off); err != nil {
			return false, err
		}
		for off = data; off < hole; {
			n, e := f.ReadAt(chunk(hole-off), off)
			if _, err := dst.Write(w.buf[:n]); err != nil {
				return false, err
			}
			off += int64(n)
			if linuxFilesFatal(e) {
				return false, e
			} else if e != nil {
				return e != io.EOF, zeros(size - off)
			}
		}
	}
	return false, nil
}

// linuxXattrs reads every extended attribute as PAX records.
func linuxXattrs(list func([]byte) (int, error), get func(string, []byte) (int, error)) (map[string]string, error) {
	// a value that grows or goes away between the size query and the read is read again
	for try := 1; ; try++ {
		records, err := linuxXattrsOnce(list, get)
		if try < 3 && (errors.Is(err, unix.ERANGE) || errors.Is(err, unix.ENODATA)) {
			continue
		}
		return records, err
	}
}

func linuxXattrsOnce(list func([]byte) (int, error), get func(string, []byte) (int, error)) (map[string]string, error) {
	size, err := list(nil)
	if err == unix.ENOTSUP || (err == nil && size == 0) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	names := make([]byte, size)
	if size, err = list(names); err != nil {
		return nil, err
	}
	records, total := map[string]string{}, 0
	for _, name := range strings.Split(string(names[:size]), "\x00") {
		// a PAX key cannot hold "="
		if name == "" || strings.Contains(name, "=") {
			continue
		}
		n, err := get(name, nil)
		if err == unix.ENODATA {
			continue
		} else if err != nil {
			return nil, err
		}
		value := make([]byte, n)
		if n, err = get(name, value); err != nil {
			return nil, err
		}
		// Go's tar refuses PAX headers above 1 MiB, padding included.
		if total += len(name) + n; total > 256<<10 {
			return nil, errors.New("extended attributes too large")
		}
		records["SCHILY.xattr."+name] = string(value[:n])
	}
	return records, nil
}
