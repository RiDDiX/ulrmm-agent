// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseWingetUpgrade(t *testing.T) {
	apps, table := parseWingetUpgrade(fixture(t, "winget_upgrade_en.txt"))
	want := []AppUpdate{
		{"winget", "Mozilla.Firefox.de", "Mozilla Firefox (x64 de)", "130.0.1", "131.0"},
		{"winget", "7zip.7zip", "7-Zip 23.01 (x64)", "23.01", "24.08"},
		{"winget", "Microsoft.VCRedist.2015+.x64", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", "14.38.33135.0", "14.40.33810.0"},
		{"winget", "Tencent.WeChat", "微信 WeChat", "3.9.10", "3.9.12"},
		{"winget", "Notepad++.Notepad++", "Notepad++ (64-bit x64)", "Unknown", "8.7"},
		// the table of packages that need explicit targeting
		{"winget", "PuTTY.PuTTY", "PuTTY release 0.80 (64-bit)", "0.80.0.0", "0.81.0.0"},
	}
	if !table || !reflect.DeepEqual(apps, want) {
		t.Fatalf("got %v %+v", table, apps)
	}
}

func TestParseWingetLocalisedAndTruncated(t *testing.T) {
	apps, _ := parseWingetUpgrade(fixture(t, "winget_upgrade_de_120.txt"))
	var ids []string
	for _, a := range apps {
		ids = append(ids, a.ID)
	}
	// the truncated id cannot be targeted and is left out
	want := []string{"Mozilla.Firefox.de", "7zip.7zip", "Microsoft.VCRedist.2015+.x64"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids %v", ids)
	}
	if apps[2].Name != "Microsoft Visual C++ 2015-2022 Redistrib…" || apps[2].Available != "14.40.33810.0" {
		t.Fatalf("row %+v", apps[2])
	}
}

func TestParseWingetHeaderWithSpace(t *testing.T) {
	row := "%-24s %-18s %-7s %-11s %s\n"
	out := fmt.Sprintf(row, "Název", "ID", "Verze", "K dispozici", "Zdroj") + strings.Repeat("-", 70) + "\n" +
		fmt.Sprintf(row, "Mozilla Firefox (x64 cs)", "Mozilla.Firefox.cs", "130.0.1", "131.0.2", "winget") +
		fmt.Sprintf(row, "Git", "Git.Git", "2.46.0", "2.47.0", "winget") + "2 aktualizace k dispozici.\n"
	apps, _ := parseWingetUpgrade(out)
	want := []AppUpdate{
		{"winget", "Mozilla.Firefox.cs", "Mozilla Firefox (x64 cs)", "130.0.1", "131.0.2"},
		{"winget", "Git.Git", "Git", "2.46.0", "2.47.0"},
	}
	if !reflect.DeepEqual(apps, want) {
		t.Fatalf("got %+v", apps)
	}
}

func TestParseWingetSummaryIsNoRow(t *testing.T) {
	apps, table := parseWingetUpgrade(fixture(t, "winget_upgrade_short.txt"))
	if !table || len(apps) != 1 || apps[0].ID != "Git.Git" || apps[0].Available != "2.47.0" {
		t.Fatalf("got %+v", apps)
	}
	apps, table = parseWingetUpgrade(fixture(t, "winget_upgrade_none.txt"))
	if table || apps == nil || len(apps) != 0 {
		t.Fatalf("no table: %v %+v", table, apps)
	}
}

// live output of the console user's winget 1.29 on Windows 11: the msstore
// agreements come before the table
func TestParseWingetAgreementsPreamble(t *testing.T) {
	apps, table := parseWingetUpgrade(fixture(t, "winget_upgrade_msstore.txt"))
	want := []AppUpdate{
		{"winget", "Microsoft.AppInstaller", "App Installer", "1.29.379.0", "1.29.380"},
		{"winget", "Microsoft.Edge", "Microsoft Edge", "154.0.4258.62", "155.0.4283.45"},
		{"winget", "RedHat.VirtIO", "Virtio-win-guest-tools", "< 0.1.285-1", "0.1.285-1"},
		{"winget", "Microsoft.WindowsTerminal", "Windows-Terminal", "1.24.12741.0", "1.25.2733.0"},
	}
	if !table || !reflect.DeepEqual(apps, want) {
		t.Fatalf("got %v %+v", table, apps)
	}
}

func TestWingetNeedsUser(t *testing.T) {
	// an exit code as runApp reports it: int of the uint32, negative on 386
	exit := func(c uint32) int { return int(c) }
	table := fixture(t, "winget_upgrade_msstore.txt")
	none := fixture(t, "winget_upgrade_none.txt")
	notStarted := errors.New("exec: file does not exist")
	for i, c := range []struct {
		stdout        string
		code          int
		err           error
		list, upgrade bool
	}{
		{"", exit(statusDLLNotFound), nil, true, true}, // 3221225781 on 64-bit
		{"", -1073741515, nil, true, true},             // the same exit on windows/386
		{"", -1, notStarted, true, true},               // did not start
		{table, 0, nil, false, false},                  // works as SYSTEM
		{none, 0, nil, false, false},                   // nothing installed that winget knows
		{none, exit(wingetNoUpdate), nil, false, false},
		{"", exit(wingetNoApps), nil, false, false},
		// failed without a table: the list asks the user, an upgrade that ran is not repeated
		{"Failed when searching source: msstore", exit(0x8A15000F), nil, true, false},
		{"", 1, nil, true, false},
		{"Installer failed with exit code: 1603", exit(0x8A150011), nil, true, false},
	} {
		if got := wingetListNeedsUser(c.stdout, c.code, c.err); got != c.list {
			t.Errorf("%d: list %v", i, got)
		}
		if got := wingetNeedsUser(c.stdout, c.code, c.err); got != c.upgrade {
			t.Errorf("%d: upgrade %v", i, got)
		}
	}
}

func TestParseBrewOutdated(t *testing.T) {
	apps, err := parseBrewOutdated(fixture(t, "brew_outdated_v2.json"))
	want := []AppUpdate{
		{"brew", "openssl@3", "openssl@3", "3.3.2", "3.4.0"},
		{"brew", "terraform", "hashicorp/tap/terraform", "1.9.5", "1.9.7"},
		{"brew", "firefox", "firefox", "130.0.1", "131.0.2"},
		{"brew", "visual-studio-code", "visual-studio-code", "1.93.1", "1.94.2"},
	}
	if err != nil || !reflect.DeepEqual(apps, want) {
		t.Fatalf("got %+v %v", apps, err)
	}
	if _, err := parseBrewOutdated("Error: no such command"); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestParseMasOutdated(t *testing.T) {
	want := []AppUpdate{
		{"mas", "497799835", "Xcode", "15.4", "16.0"},
		{"mas", "409183694", "Keynote", "13.2", "14.2"},
		{"mas", "1295203466", "Microsoft Remote Desktop (Beta)", "10.9.8", "10.9.10"},
	}
	if got := parseMasOutdated(fixture(t, "mas_outdated.txt")); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestAppIDValidation(t *testing.T) {
	ids, err := parseAppIDs(" Mozilla.Firefox.de,7zip.7zip,,Notepad++.Notepad++,497799835,openssl@3,7zip.7zip")
	if err != nil || !reflect.DeepEqual(ids, []string{"Mozilla.Firefox.de", "7zip.7zip", "Notepad++.Notepad++", "497799835", "openssl@3"}) {
		t.Fatalf("got %v %v", ids, err)
	}
	for _, bad := range []string{"", ",", "a b", "a;b", "a/b", "$(id)", "a\nb", "a:b", "--force", "-a", strings.Repeat("a", 129)} {
		if ids, err := parseAppIDs("ok.id," + bad); err == nil && bad != "" && bad != "," {
			t.Fatalf("accepted %q: %v", bad, ids)
		}
	}
	if _, err := parseAppIDs(","); err == nil {
		t.Fatal("empty list accepted")
	}
	many := make([]string, appIDsMax+1)
	for i := range many {
		many[i] = fmt.Sprintf("app%d", i)
	}
	if _, err := parseAppIDs(strings.Join(many, ",")); err == nil {
		t.Fatal("too many ids accepted")
	}
}

func TestNewestAppInstaller(t *testing.T) {
	base := `C:\Program Files\WindowsApps\`
	paths := []string{
		base + `Microsoft.DesktopAppInstaller_1.9.25200.0_x64__8wekyb3d8bbwe\winget.exe`,
		base + `Microsoft.DesktopAppInstaller_1.23.1911.0_x64__8wekyb3d8bbwe\winget.exe`,
		base + `Microsoft.DesktopAppInstaller_1.22.11261.0_x64__8wekyb3d8bbwe\winget.exe`,
	}
	for i := range paths {
		paths[i] = filepath.FromSlash(strings.ReplaceAll(paths[i], `\`, "/"))
	}
	if got := newestAppInstaller(paths, "x64"); got != paths[1] {
		t.Fatalf("got %s", got)
	}
	if newestAppInstaller(nil, "x64") != "" {
		t.Fatal("empty")
	}
	mixed := []string{
		filepath.Join("WindowsApps", "Microsoft.DesktopAppInstaller_1.30.1.0_x86__8wekyb3d8bbwe", "winget.exe"),
		filepath.Join("WindowsApps", "Microsoft.DesktopAppInstaller_1.29.1.0_arm64__8wekyb3d8bbwe", "winget.exe"),
		filepath.Join("WindowsApps", "Microsoft.DesktopAppInstaller_1.28.1.0_x64__8wekyb3d8bbwe", "winget.exe"),
	}
	for arch, want := range map[string]string{"x64": mixed[2], "arm64": mixed[1], "x86": mixed[0]} {
		if got := newestAppInstaller(mixed, arch); got != want {
			t.Errorf("%s: got %s", arch, got)
		}
	}
	if got := newestAppInstaller(mixed[:1], "x64"); got != "" {
		t.Errorf("x86 taken on a 64-bit Windows: %s", got)
	}
}

func TestAppxArch(t *testing.T) {
	for dir, want := range map[string]string{
		"Microsoft.DesktopAppInstaller_1.28.1.0_x64__8wekyb3d8bbwe":          "x64",
		"Microsoft.DesktopAppInstaller_1.28.1.0_x86__8wekyb3d8bbwe":          "x86",
		"Microsoft.DesktopAppInstaller_1.28.1.0_arm64__8wekyb3d8bbwe":        "arm64",
		"Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__8wekyb3d8bbwe": "x64",
		"winget":                                 "",
		"Microsoft.DesktopAppInstaller_1.28.1.0": "",
	} {
		if got := appxArch(dir); got != want {
			t.Errorf("%s: %q, want %q", dir, got, want)
		}
	}
}

func TestWingetExitText(t *testing.T) {
	for code, want := range map[uint32]string{
		0x8A150111: "exit code 0x8A150111\nan application is in use, close it",
		0x80072EE2: "exit code 0x80072EE2\ndownload failed: network or server",
		0x801901F6: "exit code 0x801901F6\ndownload failed: network or server",
		0x8A15002B: "exit code 0x8A15002B\nalready installed",
		0x8A150061: "exit code 0x8A150061",
	} {
		// winget codes reach the agent as negative ints
		if got := wingetExitText(int(int32(code))); got != want {
			t.Errorf("%08X: %q", code, got)
		}
	}
}

// Each package has its own limit: the call's deadline does not cut a running
// one, it only keeps the next from starting.
func TestUpgradeEachBudgets(t *testing.T) {
	old := wingetUpgradeMax
	defer func() { wingetUpgradeMax = old }()
	wingetUpgradeMax = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res := upgradeEach(ctx, []string{"a", "b"}, func(ctx context.Context, id string) (string, bool, error) {
		select {
		case <-ctx.Done():
			return "", false, errors.New("time limit reached")
		case <-time.After(100 * time.Millisecond):
			return "done", true, nil
		}
	})
	if len(res) != 2 || !res[0].OK || res[0].Status != "" || res[1].OK || res[1].Status != appNotStarted {
		t.Fatalf("call deadline: %+v", res)
	}

	wingetUpgradeMax = 20 * time.Millisecond
	res = upgradeEach(context.Background(), []string{"slow"}, func(ctx context.Context, id string) (string, bool, error) {
		<-ctx.Done()
		return "Downloading", false, errors.New("time limit reached")
	})
	if len(res) != 1 || res[0].OK || res[0].Status != appTimedOut || res[0].OutputTail != "Downloading\n"+appTimedOutText {
		t.Fatalf("package limit: %+v", res)
	}

	// a cancel, unlike the deadline, ends the running package; it is not a
	// time limit
	wingetUpgradeMax = time.Minute
	cctx, ccancel := context.WithCancel(context.Background())
	start := time.Now()
	res = upgradeEach(cctx, []string{"a"}, func(ctx context.Context, id string) (string, bool, error) {
		ccancel()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		return "", false, errors.New("time limit reached")
	})
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancel did not reach the package")
	}
	if len(res) != 1 || res[0].OK || res[0].Status != "" || !strings.HasSuffix(res[0].OutputTail, "cancelled") {
		t.Fatalf("cancel: %+v", res)
	}
}

// A package that starts last still ends before the server stops waiting.
func TestUpgradeEachAnswersInTime(t *testing.T) {
	oldNow, oldMax := appNow, wingetUpgradeMax
	defer func() { appNow, wingetUpgradeMax = oldNow, oldMax }()
	lateBudget := func() time.Duration {
		clock := time.Now()
		appNow = func() time.Time { return clock }
		var late time.Duration
		upgradeEach(context.Background(), []string{"first", "late"}, func(ctx context.Context, id string) (string, bool, error) {
			dl, _ := ctx.Deadline()
			late = time.Until(dl)
			// the first package runs until just before appUpgradeMax
			clock = clock.Add(569 * time.Second)
			return "", true, nil
		})
		return late
	}
	if b := lateBudget(); b > 1201*time.Second || b < 1190*time.Second {
		t.Fatalf("real limits: %v", b)
	}
	// a longer own limit is cut to what is left
	wingetUpgradeMax = time.Hour
	if b := lateBudget(); b > 1201*time.Second || b < 1195*time.Second {
		t.Fatalf("cut limit: %v", b)
	}
}

func TestOutputTailDropsProgress(t *testing.T) {
	out := "\r  -\r  \\\n  ██████▒▒▒▒  1.2 MB / 3 MB\r  ██████████  3 MB / 3 MB\nSuccessfully installed\n"
	if got := outputTail(out, appTailMax); got != "Successfully installed" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("ä", appTailMax)
	if got := outputTail(long, appTailMax); len(got) > appTailMax || !strings.HasSuffix(long, got) {
		t.Fatalf("tail %d bytes", len(got))
	}
}

func TestAppUpdatesRejectsBadInput(t *testing.T) {
	for _, d := range []map[string]string{
		{"action": "nope"},
		{"action": "upgrade", "ids": "a;b", "source": "winget"},
		{"action": "upgrade", "ids": ""},
	} {
		if _, err := AppUpdates(d); err == nil {
			t.Fatalf("accepted %v", d)
		}
	}
}

// winget ids outside [A-Za-z0-9.+_-], from the winget index of 2026-10-20
var oddWingetIDs = []string{"Allen&Heath.AvantisDirector", "BJLive!.LumineaRemote", "BRÖTJE.ProfiTool",
	"COMPELSONLaboratories.MOBILedit!SIMClone", "Chappée.PRO", "ClémentGrennerat.ThreeFingerDrag", "DaniRodríguez.Cartero",
	"Febooti.Hash&CRC", "IDMComputerSolutions,Inc.UltraEdit", "InvokeAI,Inc.InvokeCommunityEdition", "JanJoneš.ipaSim",
	"KIDASASoftware,Inc.MilestonesProfessional2019-64", "NHNCorporation.Dooray!Drive", "PicoTechnology.Picoscope.T&M.EA",
	"ReceitaFederaldoBrasil.EscrituraçãoDigitalECF", "ReceitaFederaldoBrasil.SpedContábil", "Rohde&Schwarz.SDC.IETDViewAutark",
	"SoftpointerInc.Tag&Rename", "Ty&Neal.Wally", "nitichote@dev.thaikeyfix"}

func TestWingetIDValidation(t *testing.T) {
	good := append([]string{"7zip.7zip", "Mozilla.Firefox", "Notepad++.Notepad++", "Microsoft.VCRedist.2015+.x64", "a",
		strings.Repeat("a", 128), strings.Repeat("ö", 128)}, oddWingetIDs...)
	for _, id := range good {
		if !wingetIDRe.MatchString(id) {
			t.Errorf("refused %q", id)
		}
	}
	for _, bad := range []string{"", "-x", "--force", ".a", "_a", "a b", `a"b`, "a'b", "a;b", "a/b", `a\b`, "a\nb", "$(id)",
		"a|b", "a…", strings.Repeat("a", 129), "e\u0301"} {
		if wingetIDRe.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
		if out, code := InstallWithWinget(bad); code != -1 || !strings.HasPrefix(out, "invalid winget id") {
			t.Errorf("InstallWithWinget(%q) = %q, %d", bad, out, code)
		}
	}
}

func TestAppIDTakesWingetIDs(t *testing.T) {
	for _, id := range oddWingetIDs {
		if ok := validAppID(id); ok == strings.Contains(id, ",") {
			t.Errorf("validAppID(%q) = %v", id, ok)
		}
	}
	if _, err := parseAppIDs("Febooti.Hash&CRC,BRÖTJE.ProfiTool"); err != nil {
		t.Fatal(err)
	}
}

func TestWingetInstallArgs(t *testing.T) {
	want := []string{"install", "--id", "7zip.7zip", "--exact", "--source", "winget", "--scope", "machine", "--silent",
		"--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}
	if got := wingetInstallArgs("7zip.7zip"); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestWingetInstallResult(t *testing.T) {
	if out, code := wingetInstallResult("Found 7-Zip [7zip.7zip]\r\n  ██▒▒ 1 MB\rSuccessfully installed\n", "", 0, nil); out != "Found 7-Zip [7zip.7zip]\nSuccessfully installed" || code != 0 {
		t.Fatalf("ok: %q %d", out, code)
	}
	// negative as int on Windows, the server gets the HRESULT as uint32
	if out, code := wingetInstallResult("Found an existing package", "", int(int32(-1978335135)), nil); code != 0x8A150061 || out != "Found an existing package\nexit code 0x8A150061" {
		t.Fatalf("already installed: %q %d", out, code)
	}
	if out, code := wingetInstallResult("", "", 3010, nil); code != 3010 || out != "exit code 0x00000BC2" {
		t.Fatalf("3010: %q %d", out, code)
	}
	if out, code := wingetInstallResult("Downloading", "", 1, errors.New("winget: time limit reached")); code != -1 || out != "Downloading\nwinget: time limit reached" {
		t.Fatalf("timeout: %q %d", out, code)
	}
	if out, code := wingetInstallResult("", "", -1, errors.New("winget is not installed")); code != -1 || out != "winget is not installed" {
		t.Fatalf("not installed: %q %d", out, code)
	}
	long := strings.Repeat("line\n", 30000)
	if out, _ := wingetInstallResult(long, "", 0, nil); len(out) > wingetInstallTail || len(out) < wingetInstallTail-8 {
		t.Fatalf("tail %d bytes", len(out))
	}
}

func TestWingetInstallWaitsForAppUpdates(t *testing.T) {
	appUpdatesMu.Lock()
	out, code := InstallWithWinget("7zip.7zip")
	appUpdatesMu.Unlock()
	if code != -1 || out != "winget is busy with app updates, try again in a few minutes" {
		t.Fatalf("got %q %d", out, code)
	}
}
