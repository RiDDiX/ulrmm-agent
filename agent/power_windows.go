// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procPowerCreateRequest = modkernel32.NewProc("PowerCreateRequest")
	procPowerSetRequest    = modkernel32.NewProc("PowerSetRequest")
	procPowerClearRequest  = modkernel32.NewProc("PowerClearRequest")
	procGetTickCount       = modkernel32.NewProc("GetTickCount")
	procGetLastInputInfo   = windows.NewLazySystemDLL("user32.dll").NewProc("GetLastInputInfo")
)

// REASON_CONTEXT with POWER_REQUEST_CONTEXT_SIMPLE_STRING; the padding
// covers the larger Detailed member of the union
type reasonContext struct {
	Version uint32
	Flags   uint32
	Reason  *uint16
	_       [2]uintptr
}

const powerRequestSystemRequired = 1

var awakeStateDir = func() string {
	exe, err := os.Executable()
	if err != nil {
		return os.TempDir()
	}
	return filepath.Dir(exe)
}

func powercfg(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return runOut(ctx, "powercfg", args...)
}

// The power request blocks idle sleep. Lid close is LIDACTION in the scheme:
// AC and DC are 0 (do nothing) during the hold, saved indexes restored after.
func holdLid(st *awakeState) error {
	if st.LidAC == "" || st.LidDC == "" {
		out, err := powercfg("/q", "SCHEME_CURRENT", "SUB_BUTTONS", "LIDACTION")
		if err != nil {
			return errors.New("powercfg /q: " + err.Error())
		}
		if st.LidAC, st.LidDC, err = parseLidIndexes(out); err != nil {
			return err
		}
	}
	return setLid("0", "0")
}

func undoLid(st awakeState) error {
	if st.LidAC == "" || st.LidDC == "" {
		return nil
	}
	return setLid(lidIndexArg(st.LidAC), lidIndexArg(st.LidDC))
}

func setLid(ac, dc string) error {
	for _, a := range [][]string{
		{"/setacvalueindex", "SCHEME_CURRENT", "SUB_BUTTONS", "LIDACTION", ac},
		{"/setdcvalueindex", "SCHEME_CURRENT", "SUB_BUTTONS", "LIDACTION", dc},
		{"/S", "SCHEME_CURRENT"},
	} {
		if out, err := powercfg(a...); err != nil {
			return errors.New("powercfg " + a[0] + ": " + clip(out, 128))
		}
	}
	return nil
}

// A PowerRequestSystemRequired request, not SetThreadExecutionState: both
// land in the same power request list that the idle and unattended-wake
// (UNATTENDSLEEP, 120 s) timers honour, but the request is a handle owned by
// the service process instead of a flag on one OS thread, so no goroutine has
// to stay locked to a thread for hours, and powercfg /requests shows the reason.
func holdAwake(time.Duration) (func(), error) {
	reason, _ := windows.UTF16PtrFromString(BrandProductName + " maintenance window")
	rc := reasonContext{Flags: 1, Reason: reason}
	h, _, err := procPowerCreateRequest.Call(uintptr(unsafe.Pointer(&rc)))
	if h == 0 || windows.Handle(h) == windows.InvalidHandle {
		return nil, err
	}
	if r, _, err := procPowerSetRequest.Call(h, powerRequestSystemRequired); r == 0 {
		windows.CloseHandle(windows.Handle(h))
		return nil, err
	}
	return func() {
		procPowerClearRequest.Call(h, powerRequestSystemRequired)
		windows.CloseHandle(windows.Handle(h))
	}, nil
}

// WTSSessionInfo.LastInputTime is 0 for the console session (checked on
// Windows 11 25H2), and GetLastInputInfo in a service only sees session 0.
// So the agent starts itself as `-m idle` with the session user's token,
// which calls GetLastInputInfo inside that session. Minimum over all active
// sessions with a user; none = -1.
func userIdleSeconds() (int64, error) {
	path, err := os.Executable()
	if err != nil {
		return 0, err
	}
	var p *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &p, &n); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(p)))
	sessions := unsafe.Slice(p, n)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	best := int64(-1)
	for _, s := range sessions {
		if s.State != windows.WTSActive {
			continue
		}
		var tok windows.Token
		if err := windows.WTSQueryUserToken(s.SessionID, &tok); err != nil {
			// no user logged on in this session; anything else is unknown
			if errors.Is(err, windows.ERROR_NO_TOKEN) {
				continue
			}
			return 0, err
		}
		idle, err := idleInSession(ctx, path, tok)
		tok.Close()
		if err != nil {
			return 0, err
		}
		if best < 0 || idle < best {
			best = idle
		}
	}
	return best, nil
}

func idleInSession(ctx context.Context, exe string, tok windows.Token) (int64, error) {
	var out capBuf
	cmd := exec.CommandContext(ctx, exe, "-m", "idle")
	cmd.Dir = filepath.Dir(exe)
	// the exe manifest requires administrator and the session token is the
	// filtered one (or a standard user's): without RunAsInvoker
	// CreateProcessAsUser fails with 740 (seen on RiDDiX-PC and PC-WZ-HA)
	cmd.Env = append(os.Environ(), "__COMPAT_LAYER=RunAsInvoker")
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Run(); err != nil {
		return 0, err
	}
	return parseIdleMillis(out.String())
}

type lastInputInfo struct {
	CbSize uint32
	DwTime uint32
}

func lastInputMillis() (int64, error) {
	lii := lastInputInfo{CbSize: uint32(unsafe.Sizeof(lastInputInfo{}))}
	if r, _, err := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii))); r == 0 {
		return 0, err
	}
	now, _, _ := procGetTickCount.Call()
	// both are 32-bit tick counts; unsigned subtraction survives the 49.7 day wrap
	return int64(uint32(now) - lii.DwTime), nil
}
