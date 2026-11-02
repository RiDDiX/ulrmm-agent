// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "fmt"

// sha256 of the python zips GetPython downloads from BrandPyURL.
// unknown name or wrong hash: don't extract.
var pyZipSHA256 = map[string]string{
	"py3.14.5_amd64.zip": "ec25284a6261f7e6d594459def1926443c583407076f49db2bf87c497ed041e8",
	"py3.14.5_386.zip":   "60a13caa0b0dee260819cff367a6726543d1cc416b0d4ae84c1ce38c6ab6f675",
	"py3.11.9_amd64.zip": "334e93804bda491a7d656760692b1a73fe93844c1627978c6f8d1eced05017f0",
	"py3.11.9_386.zip":   "0a12d83cde8270d6b051076029ac000274c33911ebc4025eb1cf56de707f246a",
	"py3.8.7_amd64.zip":  "f7b3eb2852c49f7fdf9afc1607c94555e15778be22ca20c7cb7e778ab9582393",
	"py3.8.7_386.zip":    "161cacaf12ce8ada3de217bb189daaf03808a4082da5fc69b2e06b45290b9101",
}

// checkPyZip errors if name isn't listed, or the file hash doesn't match.
func checkPyZip(path, name string) error {
	want, ok := pyZipSHA256[name]
	if !ok {
		return fmt.Errorf("%s: no sha256 known for this zip", name)
	}
	got, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: sha256 is %s, expected %s", name, got, want)
	}
	return nil
}
