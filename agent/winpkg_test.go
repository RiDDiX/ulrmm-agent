// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
)

func TestSoftwareInstallDate(t *testing.T) {
	cases := map[string]string{
		"20240305":   "2024-3-05",
		"20191231":   "2019-12-31",
		" 20200125 ": "2020-1-25",
		"":           "01-1-01",
		"2024-03-05": "01-1-01",
		"20241305":   "01-1-01",
		"5/3/2024":   "01-1-01",
	}
	for in, want := range cases {
		if got := softwareInstallDate(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestUninstallEntryRecord(t *testing.T) {
	e := uninstallEntry{
		name: "7-Zip 19.00 (x64)\x00", version: "19.00", publisher: "Igor Pavlov",
		installDate: "20190609", sizeKiB: 5324, location: `C:\Program Files\7-Zip\`,
		uninstall: `"C:\Program Files\7-Zip\Uninstall.exe"`, source: "bad\xffutf8",
	}
	want := rmm.InstalledApp{
		Title: "7-Zip 19.00 (x64)", Ver: "19.00", Vendor: "Igor Pavlov",
		Installed: "2019-6-09", SizeText: "5.2 MB", Origin: "badutf8",
		Path: `C:\Program Files\7-Zip\`, UninstallCmd: `"C:\Program Files\7-Zip\Uninstall.exe"`,
	}
	if got := e.record(); got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if got := (uninstallEntry{name: "x"}).record(); got.SizeText != "0 B" || got.Installed != "01-1-01" {
		t.Errorf("empty entry: %+v", got)
	}
}

func TestWuaIDQuery(t *testing.T) {
	q, ok := wuaIDQuery("07609d43-d518-4e77-856e-d1b316d1b8a8")
	if !ok || q != "UpdateID='07609d43-d518-4e77-856e-d1b316d1b8a8'" {
		t.Errorf("valid guid: %q %v", q, ok)
	}
	for _, bad := range []string{
		"", "07609d43-d518-4e77-856e-d1b316d1b8a", "07609d43-d518-4e77-856e-d1b316d1b8a8' or IsInstalled=1 or UpdateID='",
		"07609d43 d518 4e77 856e d1b316d1b8a8", "{07609d43-d518-4e77-856e-d1b316d1b8a8}", "07609d43-d518-4e77-856e-d1b316d1b8ag",
	} {
		if q, ok := wuaIDQuery(bad); ok || q != "" {
			t.Errorf("%q accepted: %q", bad, q)
		}
	}
}

func TestWuaScanQuery(t *testing.T) {
	if got := wuaScanQuery(false); got != "IsInstalled=1 or IsInstalled=0 and Type='Software' and IsHidden=0" {
		t.Errorf("software only: %q", got)
	}
	want := "IsInstalled=1 or IsInstalled=0 and Type='Software' and IsHidden=0 or IsInstalled=0 and Type='Driver' and IsHidden=0"
	if got := wuaScanQuery(true); got != want {
		t.Errorf("with drivers: %q", got)
	}
}

func TestWuaUpdateType(t *testing.T) {
	for v, want := range map[int64]string{0: "software", 1: "software", 2: "driver", 3: "software"} {
		if got := wuaUpdateType(v); got != want {
			t.Errorf("%d: %q", v, got)
		}
	}
}

func TestWuaIDQueries(t *testing.T) {
	g := "07609d43-d518-4e77-856e-d1b316d1b8a8"
	q, ok := wuaIDQueries(g)
	if !ok || !reflect.DeepEqual(q, []string{"UpdateID='" + g + "'", "UpdateID='" + g + "' and Type='Driver'"}) {
		t.Errorf("queries: %q %v", q, ok)
	}
	if q, ok := wuaIDQueries(g + "' or IsInstalled=1 or UpdateID='"); ok || q != nil {
		t.Errorf("injection accepted: %q", q)
	}
}

func TestWUAPackageType(t *testing.T) {
	b, err := json.Marshal(rmm.UpdatePackage{Caption: "Intel - Net - 1.2", Kind: "driver"})
	if err != nil || !strings.Contains(string(b), `"type":"driver"`) || !strings.Contains(string(b), `"kb_article_ids":null`) {
		t.Errorf("json: %s %v", b, err)
	}
}

func TestWuaSucceeded(t *testing.T) {
	for code, want := range map[int64]bool{0: false, 1: false, 2: true, 3: true, 4: false, 5: false} {
		if wuaSucceeded(code) != want {
			t.Errorf("code %d: want %v", code, want)
		}
	}
}

func TestChocoScriptSource(t *testing.T) {
	sha := strings.Repeat("a1", 32)
	cases := []struct{ url, sha, wantURL, wantSha string }{
		{"https://rmm.example/agentdist/chocolatey-install.ps1", sha, "https://rmm.example/agentdist/chocolatey-install.ps1", sha},
		{"", "", chocoScriptURL, ""},
		{"https://rmm.example/x.ps1", "", chocoScriptURL, ""},
		{"https://rmm.example/x.ps1", "abc", chocoScriptURL, ""},
		{"", sha, chocoScriptURL, ""},
	}
	for _, c := range cases {
		u, s := chocoScriptSource(c.url, c.sha)
		if u != c.wantURL || s != c.wantSha {
			t.Errorf("%q %q: got %q %q", c.url, c.sha, u, s)
		}
	}
}

func TestChocoArgs(t *testing.T) {
	args, err := chocoArgs("notepadplusplus.install")
	want := []string{"install", "notepadplusplus.install", "--yes", "--force", "--force-dependencies", "--no-progress"}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Errorf("got %v %v", args, err)
	}
	for _, ok := range []string{"7zip", "dotnet-6.0-runtime", "vcredist140", "a", "notepad++"} {
		if _, err := chocoArgs(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-y", "--source=http://evil", "a b", "a;b", "a&calc", "a\"b", ".hidden", strings.Repeat("a", 129)} {
		if _, err := chocoArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestChocoResult(t *testing.T) {
	for _, code := range []int{0, 1605, 1614, 1641, 3010} {
		if out, err := chocoResult("The install of x was successful.", "", code, false, nil); err != nil || out != "The install of x was successful." {
			t.Errorf("code %d: %q %v", code, out, err)
		}
	}
	if out, err := chocoResult("out", "warn", 0, false, nil); err != nil || out != "warn" {
		t.Errorf("stderr wins on success: %q %v", out, err)
	}
	out, err := chocoResult("The install of x was NOT successful.", "", 1, false, nil)
	if err == nil || out != "The install of x was NOT successful.\nchoco exited with code 1" {
		t.Errorf("failure: %q %v", out, err)
	}
	out, err = chocoResult("partial", "", 98, true, nil)
	if err == nil || !strings.HasSuffix(out, "choco timed out after 1200 seconds") || !strings.HasPrefix(out, "partial\n") {
		t.Errorf("timeout: %q %v", out, err)
	}
	out, err = chocoResult("", "", -1, false, errors.New("exec: not found"))
	if err == nil || out != "exec: not found" {
		t.Errorf("start error: %q %v", out, err)
	}
}
