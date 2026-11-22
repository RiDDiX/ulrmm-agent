// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsImagingMethod = "windows-wbadmin-tar-v1"

var imagingVolumeGUID = regexp.MustCompile(`(?i)^\\\\\?\\Volume\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\?$`)
var windowsImagingJobID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func imagingSystemCommand(ctx context.Context, executable string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", executable), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

const (
	windowsImagingProbeTimeout = 4 * time.Minute
	windowsBackupTimeout       = 24 * time.Hour
)

func imagingPowerShell(ctx context.Context, script, operation string, env ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, windowsImagingProbeTimeout)
	defer cancel()
	const path = `WindowsPowerShell\v1.0\powershell.exe`
	cmd := imagingSystemCommand(ctx, path, "-NoProfile", "-NonInteractive", "-Command",
		`$ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); `+script)
	cmd.Env = append(os.Environ(), env...)
	data, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", operation, ctx.Err())
		}
		return nil, errors.New(windowsImagingProbeError(operation+" failed.", err))
	}
	return data, nil
}

// The source must match the simple Windows GPT layout that WinRE can recreate.
const windowsImagingProbe = `
$backup = Get-Service -Name wbengine -ErrorAction SilentlyContinue
if (!$backup -or $backup.StartType -eq [System.ServiceProcess.ServiceStartMode]::Disabled) {
    throw 'Enable the native Windows Backup engine service. On Server install Windows Server Backup.'
}
$systemLetter = $env:SystemDrive.TrimEnd(':')
$system = Get-Partition -DriveLetter $systemLetter
$systemVolume = Get-Volume -DriveLetter $systemLetter
$disk = Get-Disk -Number $system.DiskNumber
$parts = @(Get-Partition -DiskNumber $disk.Number)
$efi = @($parts | Where-Object GptType -EQ '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}')
$msr = @($parts | Where-Object GptType -EQ '{e3c9e316-0b5c-4db8-817d-f92df00215ae}')
$recovery = @($parts | Where-Object GptType -EQ '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}')
if ([string]$disk.PartitionStyle -notin @('GPT', '2') -or !$disk.IsBoot -or !$disk.IsSystem -or
    $parts.Count -ne 4 -or $efi.Count -ne 1 -or $msr.Count -ne 1 -or $recovery.Count -ne 1 -or
    !$efi[0].IsSystem -or $system.GptType -ne '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -or
    $systemVolume.FileSystem -ne 'NTFS') { throw 'One GPT boot/system disk with EFI, MSR, NTFS Windows and a recovery partition is required.' }
$re = & (Join-Path $env:SystemRoot 'System32\reagentc.exe') /info | Out-String
if ($LASTEXITCODE -ne 0 -or $re -notmatch ("(?i)harddisk" + $disk.Number + "\\Partition" + $recovery[0].PartitionNumber + "\\Recovery\\WindowsRE")) {
    throw 'Enable Windows RE on the recovery partition on the Windows disk.'
}
$uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
@{ SourceID = ([guid]$disk.Guid).ToString(); Size = [int64]$disk.Size; SectorSize = [int]$disk.LogicalSectorSize;
   DeviceUUID = ([guid]$uuid).ToString(); Used = [int64]($systemVolume.Size - $systemVolume.SizeRemaining) } | ConvertTo-Json -Compress
`

const windowsImagingBitLocker = `
$enc = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter = '$env:SystemDrive'"
if (!$enc) { throw 'Unable to confirm BitLocker state.' }
$result = Invoke-CimMethod -InputObject $enc -MethodName GetConversionStatus
if ($result.ReturnValue -ne 0 -or $null -eq $result.ConversionStatus) { throw 'Unable to confirm BitLocker state.' }
([int]$result.ConversionStatus) | ConvertTo-Json -Compress
`

const windowsImagingStaging = `
$volume = @(Get-Volume | Where-Object { $_.Path -and $_.Path.TrimEnd('\') -eq $env:ULRMM_IMAGING_STAGE_GUID })
if ($volume.Count -ne 1 -or $volume[0].FileSystem -ne 'NTFS' -or !$volume[0].DriveLetter -or
    [string]$volume[0].DriveType -notin @('Fixed', '3')) {
    throw 'Attach the configured local fixed NTFS staging volume with a drive letter.'
}
$letter = $volume[0].DriveLetter
$partition = Get-Partition -DriveLetter $letter
$disk = Get-Disk -Number $partition.DiskNumber
$localBus = [string]$disk.BusType -in @('SCSI', 'ATAPI', 'ATA', '1394', 'SSA', 'USB', 'RAID', 'SAS', 'SATA', 'SD', 'MMC', 'NVMe', 'SCM', 'UFS',
    '1', '2', '3', '4', '5', '7', '8', '10', '11', '12', '13', '17', '18', '19')
if ($disk.IsBoot -or $disk.IsSystem -or $disk.IsReadOnly -or !$localBus -or
    @(Get-Partition -DiskNumber $disk.Number | Where-Object GptType -NE '{e3c9e316-0b5c-4db8-817d-f92df00215ae}').Count -ne 1) {
    throw 'The staging volume must use a dedicated local disk.'
}
$acl = Get-Acl ($letter + ':\')
if (!$acl.AreAccessRulesProtected -or ($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') })) {
    throw 'Protect the staging root with an ACL granting access only to SYSTEM and administrators.'
}
@{ Free = [int64]$volume[0].SizeRemaining; Letter = [string]$letter } | ConvertTo-Json -Compress
`

type windowsImagingSource struct {
	SourceID   string
	Size       int64
	SectorSize int
	DeviceUUID string
	Used       int64
}

func nativeImagingCapability(ctx context.Context) ImagingCapability {
	capability, _, _ := windowsImagingPreflight(ctx)
	return capability
}

func windowsImagingPreflight(ctx context.Context) (capability ImagingCapability, guid string, root string) {
	capability = ImagingCapability{
		Method:   windowsImagingMethod,
		Scope:    "Windows system and boot-critical volumes on one GPT disk. Other disks are excluded.",
		Recovery: "Boot external Windows RE. Stage the selected recovery point on separate NTFS media and restore it to an empty compatible system disk.",
		BootMode: "uefi",
	}
	if runtime.GOARCH != "amd64" {
		capability.Reason = "Windows imaging requires an x64 agent."
		return
	}
	if windows.RtlGetVersion().BuildNumber < 26100 {
		capability.Reason = "Windows build 26100 or newer is required."
		return
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, agentKeyPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		capability.Reason = "Configure the local ImagingStagingVolume registry value."
		return
	}
	value, _, err := key.GetStringValue("ImagingStagingVolume")
	key.Close()
	if err != nil || !imagingVolumeGUID.MatchString(value) {
		capability.Reason = "Configure ImagingStagingVolume as a dedicated local NTFS volume GUID."
		return
	}
	if info, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "wbadmin.exe")); err != nil || !info.Mode().IsRegular() {
		capability.Reason = "The native Windows Backup command is unavailable."
		return
	}
	guid = strings.TrimSuffix(value, `\`)
	data, err := imagingPowerShell(ctx, windowsImagingProbe, "Windows system disk preflight")
	if err != nil {
		capability.Reason = err.Error()
		return
	}
	var source windowsImagingSource
	if err := json.Unmarshal(data, &source); err != nil || source.SourceID == "" || source.DeviceUUID == "" ||
		source.DeviceUUID == "00000000-0000-0000-0000-000000000000" || source.DeviceUUID == "ffffffff-ffff-ffff-ffff-ffffffffffff" ||
		source.Size <= 0 || (source.SectorSize != 512 && source.SectorSize != 4096) {
		capability.Reason = "Windows did not return usable disk and device identity."
		return
	}
	capability.Size, capability.SectorSize, capability.DeviceUUID, capability.SourceID = source.Size, source.SectorSize, source.DeviceUUID, source.SourceID
	data, err = imagingPowerShell(ctx, windowsImagingBitLocker, "Windows BitLocker preflight")
	if err != nil {
		capability.Reason = err.Error()
		return
	}
	var conversionStatus *int
	if json.Unmarshal(data, &conversionStatus) != nil || conversionStatus == nil {
		capability.Reason = "Windows did not return a usable BitLocker conversion status."
		return
	}
	capability.Encryption = "unencrypted"
	if *conversionStatus != 0 {
		capability.Encryption = "bitlocker"
		capability.Reason = "Windows bare-metal imaging currently requires the system volume to be fully decrypted."
		return
	}
	data, err = imagingPowerShell(ctx, windowsImagingStaging, "Windows staging preflight", "ULRMM_IMAGING_STAGE_GUID="+guid)
	if err != nil {
		capability.Reason = err.Error()
		return
	}
	var staging struct {
		Free   int64
		Letter string
	}
	if err := json.Unmarshal(data, &staging); err != nil || len(staging.Letter) != 1 || staging.Letter[0] < 'A' || staging.Letter[0] > 'Z' {
		capability.Reason = "Windows did not return a staging drive letter."
		return
	}
	root = guid + `\`
	state, err := loadWindowsImagingStage(root)
	if err != nil {
		capability.Reason = err.Error()
		return
	}
	if state != nil && !state.Pending {
		capability.Ready = true
		capability.Reason = "The local Windows Backup set is available for its existing capture request."
		return
	}
	// An unfinished set is removed before the next backup, so its space counts as free.
	if state == nil && staging.Free < source.Used {
		capability.Reason = "The Windows backup staging volume has less free space than the Windows partition uses."
		return
	}
	if err := checkWindowsVSS(ctx); err != nil {
		capability.Reason = err.Error()
		return
	}
	capability.Ready = true
	capability.Reason = "The Windows UEFI layout, unencrypted system volume, and required VSS writers passed preflight."
	return
}

func windowsImagingProbeError(fallback string, err error) string {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// PowerShell includes the source command and traceback after the first line.
		line, _, _ := strings.Cut(string(exit.Stderr), "\n")
		if line = strings.TrimSpace(line); line != "" && len(line) <= 220 {
			return line
		}
	}
	return fallback
}

const (
	vssSystemWriter   = "e8132975-6f93-4464-a53e-1050253ae220"
	vssRegistryWriter = "afbab4a2-367d-4d15-a586-71dbb18f8485"
)

var (
	vssWriterGUID  = regexp.MustCompile(`(?i)\{([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\}[ \t]*\r?$`)
	vssWriterState = regexp.MustCompile(`\[([0-9]+)\]`)
)

func validateWindowsVSSWriters(data []byte) error {
	// vssadmin reports the writer ID, instance ID, and numeric state in order.
	// The labels and descriptions are localized, so use only those values.
	var writerID string
	var guidCount int
	var system, registry bool
	for line := range strings.SplitSeq(string(data), "\n") {
		if guid := vssWriterGUID.FindStringSubmatch(line); guid != nil {
			if guidCount == 0 {
				writerID = strings.ToLower(guid[1])
			}
			guidCount++
			continue
		}
		state := vssWriterState.FindStringSubmatch(line)
		if state == nil {
			continue
		}
		if guidCount != 2 {
			return errors.New("VSS reported an incomplete writer state")
		}
		if state[1] != "1" {
			return errors.New("one or more VSS writers are not stable")
		}
		system = system || writerID == vssSystemWriter
		registry = registry || writerID == vssRegistryWriter
		guidCount = 0
	}
	if guidCount != 0 || !system || !registry {
		return errors.New("VSS must report stable System Writer and Registry Writer instances")
	}
	return nil
}

func checkWindowsVSS(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, windowsImagingProbeTimeout)
	defer cancel()
	data, err := imagingSystemCommand(ctx, "vssadmin.exe", "list", "writers").Output()
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fmt.Errorf("VSS writer status: %w", err)
	}
	return validateWindowsVSSWriters(data)
}

func nativeImagingCapture(ctx context.Context, expected ImagingCapability) (io.ReadCloser, error) {
	if !windowsImagingJobID.MatchString(expected.JobID) {
		return nil, errors.New("Windows backup staging requires a valid capture request ID")
	}
	actual, guid, root := windowsImagingPreflight(ctx)
	if !actual.Ready {
		return nil, errors.New(actual.Reason)
	}
	if !sameWindowsImagingSource(expected, actual) {
		return nil, errors.New("Windows source disk no longer matches the capture request")
	}
	lockPath, err := windows.UTF16PtrFromString(filepath.Join(root, ".ulrmm-imaging.lock"))
	if err != nil {
		return nil, err
	}
	// Windows releases this staging lock even if the agent or the host crashes.
	lock, err := windows.CreateFile(lockPath, windows.GENERIC_WRITE|windows.DELETE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_DELETE_ON_CLOSE|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("lock Windows backup staging: %w", err)
	}
	defer func() {
		if lock != 0 {
			windows.CloseHandle(lock)
		}
	}()
	backupPath := filepath.Join(root, "WindowsImageBackup")
	state, err := loadWindowsImagingStage(root)
	if err != nil {
		return nil, err
	}
	desired := windowsImagingStage{JobID: expected.JobID, SourceID: actual.SourceID, DeviceUUID: actual.DeviceUUID}
	if state != nil && *state != desired {
		if state.Pending {
			// wbadmin keeps running when the agent stops during a backup. "get status"
			// returns when that operation ends; if it fails instead, files still in
			// use make the cleanup below fail.
			wait, cancel := context.WithTimeout(ctx, windowsBackupTimeout)
			imagingSystemCommand(wait, "wbadmin.exe", "get", "status").Run()
			cancel()
		}
		if err := retireWindowsImagingStage(ctx, root, *state, expected); err != nil {
			return nil, err
		}
		rechecked, checkedGUID, _ := windowsImagingPreflight(ctx)
		if !rechecked.Ready {
			return nil, errors.New(rechecked.Reason)
		}
		if checkedGUID != guid || !sameWindowsImagingSource(expected, rechecked) {
			return nil, errors.New("Windows capture configuration changed while clearing staging")
		}
		state = nil
	}
	if state == nil {
		if err := createWindowsImagingStage(ctx, guid, root, desired); err != nil {
			return nil, err
		}
	}
	reader, writer := io.Pipe()
	stream := &windowsImagingStream{PipeReader: reader, done: make(chan struct{}), root: root, owner: desired, lock: lock}
	lock = 0
	go func() {
		defer close(stream.done)
		writer.CloseWithError(archiveWindowsBackup(ctx, writer, backupPath))
	}()
	return stream, nil
}

func sameWindowsImagingSource(expected, actual ImagingCapability) bool {
	return expected.Method == actual.Method && expected.SourceID == actual.SourceID && expected.DeviceUUID == actual.DeviceUUID &&
		expected.Size == actual.Size && expected.SectorSize == actual.SectorSize && expected.BootMode == actual.BootMode &&
		expected.Scope == actual.Scope && expected.Encryption == actual.Encryption
}

var windowsBackupVersion = regexp.MustCompile(`\b[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}-[0-9]{1,2}:[0-9]{2}\b`)

const windowsImagingStateFile = ".ulrmm-imaging.json"

// Pending marks a record written before Windows Backup started. Its set is
// unfinished until the record is rewritten after the checks.
type windowsImagingStage struct {
	JobID      string
	SourceID   string
	DeviceUUID string
	Pending    bool `json:",omitempty"`
}

func loadWindowsImagingStage(root string) (*windowsImagingStage, error) {
	statePath := filepath.Join(root, windowsImagingStateFile)
	stateInfo, stateErr := os.Lstat(statePath)
	backup, backupErr := os.Lstat(filepath.Join(root, "WindowsImageBackup"))
	if errors.Is(stateErr, os.ErrNotExist) && errors.Is(backupErr, os.ErrNotExist) {
		return nil, nil
	}
	unowned := errors.New("Windows backup staging contains an incomplete or unowned backup set. Inspect staging locally")
	if stateErr != nil || !stateInfo.Mode().IsRegular() || windowsReparsePoint(stateInfo) || stateInfo.Size() > 1024 {
		return nil, unowned
	}
	data, err := os.ReadFile(statePath)
	var state windowsImagingStage
	if err != nil || json.Unmarshal(data, &state) != nil || !windowsImagingJobID.MatchString(state.JobID) ||
		!windowsImagingJobID.MatchString(state.SourceID) || !windowsImagingJobID.MatchString(state.DeviceUUID) {
		return nil, errors.New("Windows backup staging has an invalid ownership record. Inspect staging locally")
	}
	// Windows Backup may not have created the set yet when its run was
	// interrupted, or a cleanup stopped before it removed this record.
	if errors.Is(backupErr, os.ErrNotExist) {
		state.Pending = true
	} else if backupErr != nil || !backup.IsDir() || windowsReparsePoint(backup) {
		return nil, unowned
	}
	return &state, nil
}

func createWindowsImagingStage(ctx context.Context, guid, root string, state windowsImagingStage) error {
	pending := state
	pending.Pending = true
	if err := writeWindowsImagingStage(root, pending); err != nil {
		return err
	}
	backup, cancel := context.WithTimeout(ctx, windowsBackupTimeout)
	err := imagingSystemCommand(backup, "wbadmin.exe", "start", "backup", "-backupTarget:"+guid,
		"-allCritical", "-vssCopy", "-quiet").Run()
	cancel()
	if err != nil {
		return fmt.Errorf("Windows Backup failed. Review Microsoft-Windows-Backup events; the next capture clears this set: %w", err)
	}
	if err := checkWindowsVSS(ctx); err != nil {
		return err
	}
	probe, cancel := context.WithTimeout(ctx, windowsImagingProbeTimeout)
	data, err := imagingSystemCommand(probe, "wbadmin.exe", "get", "versions", "-backupTarget:"+guid).Output()
	cancel()
	if err != nil || !windowsBackupVersion.Match(data) {
		return errors.New("Windows Backup did not report a version on the staging volume")
	}
	if info, err := os.Lstat(filepath.Join(root, "WindowsImageBackup")); err != nil || !info.IsDir() || windowsReparsePoint(info) {
		return errors.New("Windows Backup did not create a regular image directory")
	}
	return writeWindowsImagingStage(root, state)
}

func writeWindowsImagingStage(root string, state windowsImagingStage) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(root, ".ulrmm-imaging-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(data); err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), filepath.Join(root, windowsImagingStateFile))
}

type windowsImagingStream struct {
	*io.PipeReader
	done  chan struct{}
	root  string
	owner windowsImagingStage
	lock  windows.Handle
}

func (s *windowsImagingStream) Close() error {
	err := s.PipeReader.Close()
	<-s.done
	return errors.Join(err, windows.CloseHandle(s.lock))
}

func (s *windowsImagingStream) Finish() error {
	<-s.done
	return clearWindowsImagingStage(s.root, s.owner)
}

func retireWindowsImagingStage(ctx context.Context, root string, staged windowsImagingStage, expected ImagingCapability) error {
	if staged.DeviceUUID != expected.DeviceUUID {
		return errors.New("a different Windows backup request owns staging; preserve or clear that set locally before retrying")
	}
	// An unfinished set was never uploaded and cannot be resumed.
	if staged.Pending {
		return clearWindowsImagingStage(root, staged)
	}
	if expected.PriorCaptureFinished != nil && staged.JobID != expected.JobID {
		finished, err := expected.PriorCaptureFinished(ctx, staged.JobID)
		if err != nil {
			return fmt.Errorf("unable to confirm the previous Windows capture ended before clearing staging: %w", err)
		}
		if finished {
			return clearWindowsImagingStage(root, staged)
		}
	}
	return errors.New("a different Windows backup request owns staging; preserve or clear that set locally before retrying")
}

func clearWindowsImagingStage(root string, owner windowsImagingStage) error {
	state, err := loadWindowsImagingStage(root)
	if err != nil {
		return err
	}
	if state == nil || *state != owner {
		return errors.New("Windows backup staging ownership changed before cleanup")
	}
	if _, err := os.Lstat(filepath.Join(root, "WindowsImageBackup")); errors.Is(err, os.ErrNotExist) {
		return os.Remove(filepath.Join(root, windowsImagingStateFile))
	}
	// Windows rejects handle-relative RemoveAll on this volume GUID path.
	// Validate the complete tree and remove each absolute path on that volume.
	var paths []string
	err = filepath.WalkDir(filepath.Join(root, "WindowsImageBackup"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if windowsReparsePoint(info) || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("refusing to remove a nonregular Windows backup path: %s", path)
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if err := os.Remove(paths[i]); err != nil {
			return err
		}
	}
	return os.Remove(filepath.Join(root, windowsImagingStateFile))
}

// shortcut: a reused partial download is not checked against its owner SID or
// ACL, the restore guide requires an output folder only the operator can write;
// read the owner from the handle once restores run from shared folders.
func imagingPartialPrivate(os.FileInfo) bool { return true }

func windowsReparsePoint(info fs.FileInfo) bool {
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return !ok || attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func archiveWindowsBackup(ctx context.Context, dst io.Writer, backupPath string) error {
	written := &tarCounter{w: dst}
	archive := tar.NewWriter(written)
	err := filepath.WalkDir(backupPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if windowsReparsePoint(info) || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("Windows backup contains an unsupported file type: %s", entry.Name())
		}
		rel, err := filepath.Rel(filepath.Dir(backupPath), path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			header.Name += "/"
		}
		if err := writeAlignedHeader(archive, written, header); err != nil || info.IsDir() {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(archive, file)
		return err
	})
	if err != nil {
		return err
	}
	return archive.Close()
}
