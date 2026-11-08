// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// authFileOwnerOK reads owner and DACL from the open handle, not the path:
// the path could point elsewhere by now.
func authFileOwnerOK(f *os.File, _ os.FileInfo) error {
	path := f.Name()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	var user *windows.SID
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		user = u.User.Sid
	}
	trusted := func(s *windows.SID) bool {
		return s.IsWellKnown(windows.WinBuiltinAdministratorsSid) || s.IsWellKnown(windows.WinLocalSystemSid) || (user != nil && s.Equals(user))
	}
	if !trusted(owner) {
		return fmt.Errorf("%s must belong to Administrators, SYSTEM or the user running the installer", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil && err != windows.ERROR_OBJECT_NOT_FOUND {
		return err
	}
	readable := fmt.Errorf("%s must be readable only by Administrators, SYSTEM and its owner", path)
	if dacl == nil {
		// no DACL or a NULL one: everyone has access
		return readable
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// other allow types (callback, object) are refused as well
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			!(trusted(sid) || sid.Equals(owner) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) || sid.IsWellKnown(windows.WinCreatorOwnerSid)) {
			return readable
		}
	}
	return nil
}
