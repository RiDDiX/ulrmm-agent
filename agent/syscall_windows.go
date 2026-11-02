// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DLL entry points x/sys/windows does not wrap.
var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modpowrprof = windows.NewLazySystemDLL("powrprof.dll")
	modwtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")

	procAdjustTokenPrivileges      = modadvapi32.NewProc("AdjustTokenPrivileges")
	procSetSuspendState            = modpowrprof.NewProc("SetSuspendState")
	procWTSQuerySessionInformation = modwtsapi32.NewProc("WTSQuerySessionInformationW")
)

const wtsUserName = 5 // WTS_INFO_CLASS WTSUserName

// CreateEnvironmentBlock is the environment of the user behind token, without
// the agent's own variables. Free it with DestroyEnvironmentBlock.
func CreateEnvironmentBlock(token windows.Token) (*uint16, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
		return nil, err
	}
	return block, nil
}

func DestroyEnvironmentBlock(block *uint16) error {
	return windows.DestroyEnvironmentBlock(block)
}

// NAME=value strings from a CreateEnvironmentBlock.
func EnvironmentBlockToSlice(block *uint16) []string {
	if block == nil {
		return nil
	}
	// the block ends with two NULs in a row, an empty one with its first
	n := 0
	for prev := uint16(0); ; n++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(block), 2*n))
		if c == 0 && (n == 0 || prev == 0) {
			break
		}
		prev = c
	}
	return envBlockStrings(unsafe.Slice(block, n+1))
}

// CreateProcessAsUser starts cmdLine with token. si may be the StartupInfo
// of a STARTUPINFOEX when flags carry EXTENDED_STARTUPINFO_PRESENT. The
// caller closes the handles in the returned ProcessInformation.
func CreateProcessAsUser(token windows.Token, cmdLine string, inheritHandles bool, flags uint32, env *uint16, dir string, si *windows.StartupInfo) (*windows.ProcessInformation, error) {
	cl, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, err
	}
	var cwd *uint16
	if dir != "" {
		if cwd, err = windows.UTF16PtrFromString(dir); err != nil {
			return nil, err
		}
	}
	if env != nil {
		flags |= windows.CREATE_UNICODE_ENVIRONMENT
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, nil, cl, nil, nil, inheritHandles, flags, env, cwd, si, &pi); err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	return &pi, nil
}

// sessionUserNames lists the user of every terminal session (console and
// remote desktop) in the order the session manager returns them; sessions
// without a user give "".
func sessionUserNames() ([]string, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	names := make([]string, 0, count)
	for _, s := range unsafe.Slice(info, count) {
		var buf *uint16
		var size uint32
		r, _, _ := procWTSQuerySessionInformation.Call(0, uintptr(s.SessionID), wtsUserName,
			uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)))
		if r == 0 || buf == nil {
			names = append(names, "")
			continue
		}
		names = append(names, windows.UTF16PtrToString(buf))
		windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	}
	return names, nil
}

// enablePrivilege switches on a privilege the process token holds but has
// disabled, for example SeShutdownPrivilege.
func enablePrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	if err := windows.LookupPrivilegeValue(nil, p, &tp.Privileges[0].Luid); err != nil {
		return err
	}
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	// it also succeeds when the token lacks the privilege and says so only
	// in the last error, which Call captures right after the call
	r, _, e := procAdjustTokenPrivileges.Call(uintptr(tok), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %w", e)
	}
	if e == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("%s: %w", name, e)
	}
	return nil
}
