// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"archive/tar"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPkgJob(t *testing.T) {
	fastPkg(t)
	root := t.TempDir()
	for _, d := range []string{"pkg-7", "pkg-x"} {
		if err := os.MkdirAll(filepath.Join(root, d, "y"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "app.tar.gz")
	pkgWriteTarGz(t, archive,
		pkgTarEntry{&tar.Header{Name: "app/", Typeflag: tar.TypeDir, Mode: 0o755}, ""},
		pkgTarEntry{&tar.Header{Name: "app/run.sh", Typeflag: tar.TypeReg, Mode: 0o755},
			"#!/bin/sh\necho \"args=$1|$2\"\necho \"dir=$PKG_DIR\"\npwd\necho oops >&2\nexit 3\n"},
	)
	body, _ := os.ReadFile(archive)
	srv := newPkgServer(t, body)
	api := &pkgAPI{final: []int{502}, plan: func(int) *pkgPlan {
		p := pkgTestPlan(srv.URL+"/packages/download/t1/", body)
		p.Filename, p.Extract = "app.tar.gz", "tar.gz"
		p.Run = pkgRun{Type: "command", Exe: "app/run.sh", Args: "unused on unix", Argv: []string{"a b", "c"}, Timeout: 60}
		p.RebootCodes = []int64{3010, 3}
		return p
	}}
	a := pkgTestAgent(t, api)
	a.UnixTmpDir = root
	a.runPkgJob(pkgTestJob)

	size := float64(len(body))
	patches, _ := api.got()
	if len(patches) != 5 {
		t.Fatalf("patches %v", patches)
	}
	for i, want := range []map[string]interface{}{
		{"state": "downloading", "done": 0.0, "total": size},
		{"state": "extracting", "done": size, "total": size},
		{"state": "installing", "done": size, "total": size},
	} {
		if !reflect.DeepEqual(patches[i], want) {
			t.Fatalf("patch %d: %v", i, patches[i])
		}
	}
	files := filepath.Join(root, "pkg-"+pkgTestJob, "files")
	for _, final := range patches[3:] {
		out, _ := final["output"].(string)
		if final["state"] != "done" || final["exit_code"] != 3.0 || final["detail"] != "" || len(final) != 4 ||
			!strings.Contains(out, "args=a b|c\ndir="+files+"\n"+files+"\n") || !strings.Contains(out, "oops") {
			t.Fatalf("result %v", final)
		}
	}
	if left, _ := os.ReadDir(root); len(left) != 1 || left[0].Name() != "pkg-x" {
		t.Fatalf("left in the work dir: %v", left)
	}
}

func TestPkgJobScript(t *testing.T) {
	fastPkg(t)
	root := t.TempDir()
	body := []byte("installer bytes")
	srv := newPkgServer(t, body)
	api := &pkgAPI{plan: func(int) *pkgPlan {
		p := pkgTestPlan(srv.URL+"/packages/download/t1/", body)
		p.Run = pkgRun{Type: "script", Shell: "shell", Timeout: 60,
			Env:  map[string]string{"FOO": "bar", "PKG_FILE": "/elsewhere"},
			Body: "#!/bin/sh\necho \"file=$PKG_FILE\"\necho \"dir=$PKG_DIR\"\necho \"foo=$FOO\"\ncat \"$PKG_FILE\"; echo\necho warn >&2\necho 'ULRMM-PKG {\"result\":\"ok\"}'\n"}
		return p
	}}
	a := pkgTestAgent(t, api)
	a.UnixTmpDir = root
	a.runPkgJob(pkgTestJob)

	patches, _ := api.got()
	final := patches[len(patches)-1]
	work := filepath.Join(root, "pkg-"+pkgTestJob)
	want := "warn\nfile=" + filepath.Join(work, "setup.bin") + "\ndir=" + work + "\nfoo=bar\ninstaller bytes\nULRMM-PKG {\"result\":\"ok\"}"
	if final["state"] != "done" || final["exit_code"] != 0.0 || final["output"] != want {
		t.Fatalf("result %v", final)
	}
	if b := patches[len(patches)-2]; b["state"] != "installing" {
		t.Fatalf("patches %v", patches)
	}
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Fatalf("left in the work dir: %v", left)
	}
}

func TestPkgJobFails(t *testing.T) {
	fastPkg(t)
	free := pkgFree
	t.Cleanup(func() { pkgFree = free })
	body := []byte("installer bytes")
	srv := newPkgServer(t, body)
	plan := pkgTestPlan(srv.URL+"/packages/download/t1/", body)
	api := &pkgAPI{plan: func(int) *pkgPlan { return plan }}
	a := pkgTestAgent(t, api)
	a.UnixTmpDir = t.TempDir()

	pkgFree = func(string) (uint64, error) { return 1 << 20, nil }
	a.runPkgJob(pkgTestJob)
	patches, _ := api.got()
	if len(patches) != 1 || patches[0]["state"] != "failed" || patches[0]["exit_code"] != nil ||
		!strings.HasPrefix(patches[0]["detail"].(string), "not enough disk space") {
		t.Fatalf("patches %v", patches)
	}

	pkgFree = free
	plan.Sha256 = pkgSum([]byte("the plan's file"))
	a.runPkgJob(pkgTestJob)
	patches, _ = api.got()
	if len(patches) != 3 || patches[2]["state"] != "failed" ||
		!strings.HasPrefix(patches[2]["detail"].(string), "sha256 of the download is "+pkgSum(body)) {
		t.Fatalf("patches %v", patches)
	}
	if left, _ := os.ReadDir(a.UnixTmpDir); len(left) != 0 {
		t.Fatalf("left in the work dir: %v", left)
	}
}

func TestPkgCommandExitCodes(t *testing.T) {
	a := testUpdateAgent()
	run := pkgRun{Type: "command", Exe: "sh", Argv: []string{"-c", "echo out; echo err >&2; exit 5"}, Timeout: 30}
	for _, tc := range []struct {
		success []int64
		state   string
		detail  string
	}{
		{[]int64{0}, "failed", "exit code 5"},
		{[]int64{0, 5}, "done", ""},
	} {
		res := a.pkgInstall(&pkgPlan{Run: run, SuccessCodes: tc.success}, "", t.TempDir())
		if res.State != tc.state || res.Detail != tc.detail || res.ExitCode == nil || *res.ExitCode != 5 || res.Output != "out\nerr" {
			t.Fatalf("%v: %+v", tc.success, res)
		}
	}
	res := a.pkgInstall(&pkgPlan{Run: pkgRun{Type: "command", Exe: "../sh", Timeout: 30}}, "", t.TempDir())
	if res.State != "failed" || res.ExitCode != nil || !strings.Contains(res.Detail, "leaves its folder") {
		t.Fatalf("path escape: %+v", res)
	}
}

func TestPkgCommandTimeout(t *testing.T) {
	a := testUpdateAgent()
	dir := t.TempDir()
	run := pkgRun{Type: "command", Exe: "sh", Argv: []string{"-c", "sleep 60 & echo $! > bg; wait"}, Timeout: 1}
	start := time.Now()
	res := a.pkgInstall(&pkgPlan{Run: run, SuccessCodes: []int64{0}}, "", dir)
	if res.State != "failed" || res.ExitCode != nil || res.Detail != "the installer did not finish within 1 s" {
		t.Fatalf("%+v", res)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatal("took", took)
	}
	if runtime.GOOS != "linux" {
		return
	}
	b, _ := os.ReadFile(filepath.Join(dir, "bg"))
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal("no pid of the background child:", err)
	}
	// killed: gone, or a zombie nobody has reaped yet
	for i := 0; ; i++ {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if f := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:])); err != nil || (len(f) > 0 && (f[0] == "Z" || f[0] == "X")) {
			break
		}
		if i == 40 {
			t.Fatal("the background child still runs")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPkgScriptTimeout(t *testing.T) {
	a := testUpdateAgent()
	a.UnixTmpDir = t.TempDir()
	code := int64(98)
	for _, tc := range []struct {
		body    string
		timeout int
		detail  string
		code    *int64
	}{
		{"#!/bin/sh\nsleep 30\n", 1, "the installer did not finish within 1 s", nil},
		// a script's own exit code 98 is no timeout
		{"#!/bin/sh\nexit 98\n", 30, "exit code 98", &code},
	} {
		run := pkgRun{Type: "script", Shell: "shell", Body: tc.body, Timeout: tc.timeout}
		res := a.pkgInstall(&pkgPlan{Run: run, SuccessCodes: []int64{0}}, "", t.TempDir())
		if res.State != "failed" || res.Detail != tc.detail || !reflect.DeepEqual(res.ExitCode, tc.code) {
			t.Fatalf("%q: %+v", tc.body, res)
		}
	}
}

func TestPkgCleanup(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"pkg-1", "pkg-22", "pkg-x", "pkg-", "other"} {
		if err := os.MkdirAll(filepath.Join(root, d, "f"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "pkg-3"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a := testUpdateAgent()
	a.UnixTmpDir = root
	names := func() (n []string) {
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			n = append(n, e.Name())
		}
		return n
	}
	pkgMu.Lock()
	a.pkgCleanup()
	pkgMu.Unlock()
	if got := names(); len(got) != 6 {
		t.Fatal("removed while a job runs:", got)
	}
	a.pkgCleanup()
	if got := names(); !reflect.DeepEqual(got, []string{"other", "pkg-", "pkg-3", "pkg-x"}) {
		t.Fatal(got)
	}
}
