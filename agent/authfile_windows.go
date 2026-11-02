// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func authFileOwnerOK(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && owner.Equals(u.User.Sid) {
		return nil
	}
	return fmt.Errorf("%s must belong to Administrators, SYSTEM or the user running the installer", path)
}
