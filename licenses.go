// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"embed"
	"fmt"
	"io"
)

// The license and notice files ship inside every agent binary.
//
//go:embed LICENSE.md NOTICE.md THIRD_PARTY_NOTICES.md
var licenseFiles embed.FS

var licenseOrder = []string{"LICENSE.md", "NOTICE.md", "THIRD_PARTY_NOTICES.md"}

// printLicenses is -m licenses.
func printLicenses(w io.Writer) error {
	for _, name := range licenseOrder {
		b, err := licenseFiles.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "==> %s <==\n%s\n", name, b); err != nil {
			return err
		}
	}
	return nil
}
