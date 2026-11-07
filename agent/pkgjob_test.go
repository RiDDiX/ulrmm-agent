// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const pkgTestJob = "42"

func fastPkg(t *testing.T) {
	fastSdio(t)
	wait := pkgRetryWait
	pkgRetryWait = time.Millisecond
	t.Cleanup(func() { pkgRetryWait = wait })
}

func pkgSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func pkgTestPlan(link string, body []byte) *pkgPlan {
	return &pkgPlan{Job: 42, URL: link, Sha256: pkgSum(body), Size: int64(len(body)), Filename: "setup.bin", Extract: "none",
		Run: pkgRun{Type: "command", Exe: "setup.bin", Timeout: 60}, SuccessCodes: []int64{0}}
}

// pkgServer serves body with Range support. Paths in refuse answer 403;
// drop cuts the next answer after half of the bytes, stall stops sending
// there until the client gives up.
type pkgServer struct {
	*httptest.Server
	mu     sync.Mutex
	body   []byte
	paths  []string
	ranges []string
	refuse map[string]bool
	drop   bool
	stall  bool
}

func newPkgServer(t *testing.T, body []byte) *pkgServer {
	s := &pkgServer{body: body, refuse: map[string]bool{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.ranges = append(s.ranges, r.Header.Get("Range"))
		drop, stall, refused := s.drop, s.stall, s.refuse[r.URL.Path]
		s.drop, s.stall = false, false
		s.mu.Unlock()
		switch {
		case refused:
			http.Error(w, "used", http.StatusForbidden)
		case drop || stall:
			w.Header().Set("Content-Length", strconv.Itoa(len(s.body)))
			w.WriteHeader(http.StatusOK)
			w.Write(s.body[:len(s.body)/2])
			w.(http.Flusher).Flush()
			if stall {
				<-r.Context().Done()
			}
			panic(http.ErrAbortHandler)
		default:
			http.ServeContent(w, r, "pkg", time.Time{}, bytes.NewReader(s.body))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *pkgServer) seen() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, r := s.paths, s.ranges
	s.paths, s.ranges = nil, nil
	return p, r
}

// pkgAPI is the RMM: plans by GET (n counts them), PATCHes recorded.
type pkgAPI struct {
	mu      sync.Mutex
	plans   int
	plan    func(n int) *pkgPlan
	patches []map[string]interface{}
	final   []int
}

func (s *pkgAPI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/agent1/pkgjob/"+pkgTestJob+"/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Method == http.MethodGet {
			s.plans++
			json.NewEncoder(w).Encode(s.plan(s.plans))
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		s.patches = append(s.patches, body)
		if st := body["state"]; (st == "done" || st == "failed") && len(s.final) > 0 {
			w.WriteHeader(s.final[0])
			s.final = s.final[1:]
		}
	}
}

// got reads under the lock the handler writes with
func (s *pkgAPI) got() ([]map[string]interface{}, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.patches, s.plans
}

func pkgTestAgent(t *testing.T, api *pkgAPI) *Agent {
	return apiAgent(t, api.handler(t))
}

func TestPkgAnswer(t *testing.T) {
	for _, job := range []string{"", "0", "007", "-1", "4x", "12345678901234567890"} {
		if got := pkgAnswer(job); got != "invalid job id" {
			t.Fatalf("%q: %q", job, got)
		}
	}
	if got := pkgAnswer("42"); got != "ok" {
		t.Fatal(got)
	}
	if got := pkgAnswer("43"); got != "busy" {
		t.Fatal("while a job runs:", got)
	}
	pkgMu.Unlock()
	if got := pkgAnswer("43"); got != "ok" {
		t.Fatal("after the job:", got)
	}
	pkgMu.Unlock()
}

func TestPkgPlanCheck(t *testing.T) {
	body := []byte("x")
	ok := func() *pkgPlan { return pkgTestPlan("https://rmm.example/packages/download/tok/", body) }
	p := ok()
	p.Sha256, p.SuccessCodes = strings.ToUpper(p.Sha256), nil
	if err := p.check(pkgTestJob); err != nil || p.Sha256 != pkgSum(body) || !reflect.DeepEqual(p.SuccessCodes, []int64{0}) {
		t.Fatalf("valid plan: %v %+v", err, p)
	}
	script := pkgRun{Type: "script", Shell: pkgShell, Body: "x", Timeout: 60}
	for _, tc := range []struct {
		change func(*pkgPlan)
		want   string
	}{
		{func(p *pkgPlan) { p.Job = 43 }, "another job"},
		{func(p *pkgPlan) { p.URL = "http://rmm.example/dl" }, "no https download link"},
		{func(p *pkgPlan) { p.URL = "https:///dl" }, "no https download link"},
		{func(p *pkgPlan) { p.Sha256 = "abc" }, "no valid sha256"},
		{func(p *pkgPlan) { p.Size = 0 }, "file size"},
		{func(p *pkgPlan) { p.Size = pkgSizeMax + 1 }, "file size"},
		{func(p *pkgPlan) { p.Filename = "../setup.bin" }, "invalid file name"},
		{func(p *pkgPlan) { p.Filename = `C:\setup.bin` }, "invalid file name"},
		{func(p *pkgPlan) { p.Filename = ".." }, "invalid file name"},
		{func(p *pkgPlan) { p.Filename = "" }, "invalid file name"},
		{func(p *pkgPlan) { p.Extract = "rar" }, "unknown archive type"},
		{func(p *pkgPlan) { p.Extract, p.Filename = "zip", "Files" }, "extract folder"},
		{func(p *pkgPlan) { p.Run.Timeout = 0 }, "run timeout"},
		{func(p *pkgPlan) { p.Run.Timeout = 86401 }, "run timeout"},
		{func(p *pkgPlan) { p.Run.Type = "magic" }, "unknown run type"},
		{func(p *pkgPlan) { p.Run.Exe = "" }, "names no program"},
		{func(p *pkgPlan) {
			if runtime.GOOS == "windows" {
				p.Run.Argv = []string{"/S"}
			} else {
				p.Run.Args = "/S"
			}
		}, "no arguments for " + runtime.GOOS},
		{func(p *pkgPlan) { p.Deadline = -1 }, "deadline"},
		{func(p *pkgPlan) { p.Deadline = 86401 }, "deadline"},
		{func(p *pkgPlan) { p.Run = script; p.Run.Shell = "cmd" }, "script"},
		{func(p *pkgPlan) { p.Run = script; p.Run.Body = "" }, "script"},
		{func(p *pkgPlan) { p.Run = script; p.Run.Env = map[string]string{"A=B": "1"} }, "invalid environment name"},
	} {
		p := ok()
		tc.change(p)
		if err := p.check(pkgTestJob); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v: %v, want %q", p, err, tc.want)
		}
	}
}

func TestPkgSpace(t *testing.T) {
	for _, tc := range []struct {
		extract string
		free    uint64
		ok      bool
	}{
		{"none", 2 << 30, true},
		{"none", 3 << 29, false},
		{"zip", 2 << 30, false},
		{"zip", 3 << 30, true},
	} {
		err := pkgSpace(tc.free, &pkgPlan{Size: 1 << 30, Extract: tc.extract})
		if (err == nil) != tc.ok || (err != nil && !strings.HasPrefix(err.Error(), "not enough disk space: need")) {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

func TestPkgDownloadResume(t *testing.T) {
	fastPkg(t)
	body := randBytes(t, 300000)
	srv := newPkgServer(t, body)
	api := &pkgAPI{}
	a := pkgTestAgent(t, api)
	plan := pkgTestPlan(srv.URL+"/dl/a", body)

	srv.drop = true
	dest := filepath.Join(t.TempDir(), "setup.bin")
	if err := a.pkgDownload(pkgTestJob, plan, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, body) {
		t.Fatal("the download differs")
	}
	_, ranges := srv.seen()
	var from int
	if len(ranges) != 2 || ranges[0] != "" || !strings.HasPrefix(ranges[1], "bytes=") {
		t.Fatalf("ranges %q", ranges)
	}
	if n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(ranges[1], "bytes="), "-")); err == nil {
		from = n
	}
	if from <= 0 || from > len(body)/2 {
		t.Fatalf("resumed at %q", ranges[1])
	}
	if patches, _ := api.got(); len(patches) == 0 || !reflect.DeepEqual(patches[0], map[string]interface{}{"state": "downloading", "done": 0.0, "total": float64(len(body))}) {
		t.Fatalf("progress %v", patches)
	}

	// no data for sdioStall ends a try too
	srv.stall = true
	dest = filepath.Join(t.TempDir(), "setup.bin")
	if err := a.pkgDownload(pkgTestJob, plan, dest); err != nil {
		t.Fatal(err)
	}
	if _, ranges := srv.seen(); len(ranges) != 2 || ranges[1] == "" {
		t.Fatalf("ranges after a stall %q", ranges)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, body) {
		t.Fatal("the download after a stall differs")
	}

	// a partial file is hashed first and continued
	dest = filepath.Join(t.TempDir(), "setup.bin")
	if err := os.WriteFile(dest, body[:1000], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.pkgDownload(pkgTestJob, plan, dest); err != nil {
		t.Fatal(err)
	}
	if _, ranges := srv.seen(); !reflect.DeepEqual(ranges, []string{"bytes=1000-"}) {
		t.Fatalf("ranges %q", ranges)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, body) {
		t.Fatal("the continued download differs")
	}
}

func TestPkgDownloadShaMismatch(t *testing.T) {
	fastPkg(t)
	body := randBytes(t, 5000)
	srv := newPkgServer(t, body)
	a := pkgTestAgent(t, &pkgAPI{})

	plan := pkgTestPlan(srv.URL+"/dl/a", []byte("another file"))
	plan.Size = int64(len(body))
	err := a.pkgDownload(pkgTestJob, plan, filepath.Join(t.TempDir(), "f"))
	if err == nil || !strings.HasPrefix(err.Error(), "sha256 of the download is "+pkgSum(body)) {
		t.Fatal(err)
	}
	// more bytes than planned: no second try
	srv.seen()
	plan = pkgTestPlan(srv.URL+"/dl/a", body)
	plan.Size--
	err = a.pkgDownload(pkgTestJob, plan, filepath.Join(t.TempDir(), "f"))
	if paths, _ := srv.seen(); err == nil || err.Error() != "the download is larger than the plan says" || len(paths) != 1 {
		t.Fatal(err, paths)
	}
}

func TestPkgDownloadRefreshesPlan(t *testing.T) {
	fastPkg(t)
	body := randBytes(t, 5000)
	srv := newPkgServer(t, body)
	srv.refuse["/dl/a"] = true
	api := &pkgAPI{plan: func(int) *pkgPlan { return pkgTestPlan(srv.URL+"/dl/b", body) }}
	a := pkgTestAgent(t, api)

	dest := filepath.Join(t.TempDir(), "f")
	if err := a.pkgDownload(pkgTestJob, pkgTestPlan(srv.URL+"/dl/a", body), dest); err != nil {
		t.Fatal(err)
	}
	if paths, _ := srv.seen(); !reflect.DeepEqual(paths, []string{"/dl/a", "/dl/b"}) {
		t.Fatalf("paths %q", paths)
	}
	if _, plans := api.got(); plans != 1 {
		t.Fatal("plans fetched:", plans)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, body) {
		t.Fatal("the download differs")
	}

	api.plan = func(int) *pkgPlan { return pkgTestPlan(srv.URL+"/dl/b", []byte("new build")) }
	err := a.pkgDownload(pkgTestJob, pkgTestPlan(srv.URL+"/dl/a", body), filepath.Join(t.TempDir(), "f"))
	if err == nil || err.Error() != "the package changed during the download" {
		t.Fatal(err)
	}

	srv.seen()
	srv.refuse["/dl/b"] = true
	api.plan = func(int) *pkgPlan { return pkgTestPlan(srv.URL+"/dl/b", body) }
	err = a.pkgDownload(pkgTestJob, pkgTestPlan(srv.URL+"/dl/a", body), filepath.Join(t.TempDir(), "f"))
	if paths, _ := srv.seen(); err == nil || err.Error() != "the server answered 403" || len(paths) != pkgTries {
		t.Fatal(err, paths)
	}
}

func TestPkgPlanDeadline(t *testing.T) {
	p := pkgTestPlan("https://rmm.example/dl", []byte("x"))
	p.Size = 1 << 20
	if got := p.deadline(); got != 16+60 {
		t.Fatal("from size:", got)
	}
	p.Size = pkgSizeMax
	if got := p.deadline(); got != 86400 {
		t.Fatal("capped:", got)
	}
	p.Deadline = 5
	if got := p.deadline(); got != 5 {
		t.Fatal("from the plan:", got)
	}
}

func TestPkgDownloadDeadline(t *testing.T) {
	fastPkg(t)
	body := randBytes(t, 5000)
	// a byte every 20 ms: never a stall, but far slower than the deadline
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		for _, b := range body {
			w.Write([]byte{b})
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}))
	t.Cleanup(srv.Close)
	a := pkgTestAgent(t, &pkgAPI{})
	plan := pkgTestPlan(srv.URL+"/dl/a", body)
	plan.Deadline = 1
	start := time.Now()
	err := a.pkgDownload(pkgTestJob, plan, filepath.Join(t.TempDir(), "f"))
	if err == nil || err.Error() != "the job did not finish within 1 s" || time.Since(start) > 5*time.Second {
		t.Fatal(err, time.Since(start))
	}
}

func TestPatchWithRetry(t *testing.T) {
	var mu sync.Mutex
	var calls int
	var codes []int
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		code := http.StatusOK
		if calls < len(codes) {
			code = codes[calls]
		}
		calls++
		w.WriteHeader(code)
	})
	for _, tc := range []struct {
		codes []int
		calls int
		fail  bool
	}{
		{nil, 1, false},
		{[]int{500, 502}, 3, false},
		{[]int{403}, 1, true},
		{[]int{500, 500, 500, 500, 500}, 4, true},
	} {
		mu.Lock()
		calls, codes = 0, tc.codes
		mu.Unlock()
		err := a.patchWithRetry("/api/v4/agent1/pkgjob/42/", map[string]string{"state": "done"}, time.Millisecond)
		mu.Lock()
		n := calls
		mu.Unlock()
		if (err != nil) != tc.fail || n != tc.calls {
			t.Fatalf("codes %v: %v after %d calls, want %d", tc.codes, err, n, tc.calls)
		}
	}
}

type pkgZipEntry struct {
	name string
	mode fs.FileMode
	body string
}

func pkgWriteZip(t *testing.T, path string, entries ...pkgZipEntry) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

type pkgTarEntry struct {
	h    *tar.Header
	body string
}

func pkgWriteTarGz(t *testing.T, path string, entries ...pkgTarEntry) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		e.h.Size = int64(len(e.body))
		if err := tw.WriteHeader(e.h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	gz.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPkgExtract(t *testing.T) {
	tmp := t.TempDir()
	zipped := filepath.Join(tmp, "ok.zip")
	pkgWriteZip(t, zipped,
		pkgZipEntry{"app/", fs.ModeDir | 0o755, ""},
		pkgZipEntry{"app/bin/run", 0o755, "run"},
		pkgZipEntry{`app\data.txt`, 0o644, "data"},
	)
	tarred := filepath.Join(tmp, "ok.tgz")
	pkgWriteTarGz(t, tarred,
		pkgTarEntry{&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}, ""},
		pkgTarEntry{&tar.Header{Name: "app/bin/run", Typeflag: tar.TypeReg, Mode: 0o755}, "run"},
		pkgTarEntry{&tar.Header{Name: "app/data.txt", Typeflag: tar.TypeReg, Mode: 0o644}, "data"},
	)
	for _, tc := range []struct{ kind, file string }{{"zip", zipped}, {"tar.gz", tarred}} {
		dest := filepath.Join(tmp, tc.kind)
		if err := pkgExtract(tc.kind, tc.file, dest, 1<<20); err != nil {
			t.Fatal(tc.kind, err)
		}
		for name, want := range map[string]string{"app/bin/run": "run", "app/data.txt": "data"} {
			p := filepath.Join(dest, filepath.FromSlash(name))
			got, err := os.ReadFile(p)
			if err != nil || string(got) != want {
				t.Fatalf("%s %s: %q %v", tc.kind, name, got, err)
			}
			fi, _ := os.Stat(p)
			if wantMode := map[bool]fs.FileMode{true: 0o700, false: 0o600}[name == "app/bin/run"]; runtime.GOOS != "windows" && fi.Mode().Perm() != wantMode {
				t.Fatalf("%s %s: mode %v", tc.kind, name, fi.Mode())
			}
		}
	}

	bad := []struct {
		kind  string
		write func(path string)
		want  string
	}{
		{"zip", func(p string) { pkgWriteZip(t, p, pkgZipEntry{"../evil", 0o644, "x"}) }, "leaves its folder"},
		{"zip", func(p string) { pkgWriteZip(t, p, pkgZipEntry{"/etc/evil", 0o644, "x"}) }, "absolute path"},
		{"zip", func(p string) { pkgWriteZip(t, p, pkgZipEntry{`C:\evil`, 0o644, "x"}) }, "drive letter"},
		{"zip", func(p string) { pkgWriteZip(t, p, pkgZipEntry{"link", fs.ModeSymlink | 0o777, "/etc/passwd"}) }, "is a link or a special file"},
		{"zip", func(p string) { pkgWriteZip(t, p, pkgZipEntry{"dev", fs.ModeDevice | 0o600, ""}) }, "is a link or a special file"},
		{"zip", func(p string) {
			pkgWriteZip(t, p, pkgZipEntry{"a", 0o644, "123456"}, pkgZipEntry{"b", 0o644, "123456"})
		}, "unpacks to more than 10 B"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "a/../../evil", Typeflag: tar.TypeReg, Mode: 0o644}, "x"})
		}, "leaves its folder"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "/evil", Typeflag: tar.TypeReg, Mode: 0o644}, "x"})
		}, "absolute path"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, ""})
		}, "is a link or a special file"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}, ""})
		}, "is a link or a special file"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "tty", Typeflag: tar.TypeChar, Devmajor: 5}, ""})
		}, "is a link or a special file"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "fifo", Typeflag: tar.TypeFifo}, ""})
		}, "is a link or a special file"},
		{"tar.gz", func(p string) {
			pkgWriteTarGz(t, p, pkgTarEntry{&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644}, "12345678901"})
		}, "unpacks to more than 10 B"},
	}
	for i, tc := range bad {
		archive := filepath.Join(tmp, "bad"+strconv.Itoa(i))
		tc.write(archive)
		dest := filepath.Join(tmp, "out"+strconv.Itoa(i))
		if err := pkgExtract(tc.kind, archive, dest, 10); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%d %s: %v, want %q", i, tc.kind, err, tc.want)
		}
		if _, err := os.Lstat(filepath.Join(tmp, "evil")); err == nil {
			t.Fatalf("%d: a file landed outside", i)
		}
	}

	// the 7z test pack has a link after its plain files
	dest := filepath.Join(tmp, "7z")
	err := pkgExtract("7z", filepath.Join("testdata", "sdio", "pack.7z.bin"), dest, 1<<20)
	if err == nil || err.Error() != "links/allx64/L_1.0/link.inf is a link or a special file" {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "DRV", "AllX64", "Test_1.0", "test.inf")); err != nil || fi.Size() != 140 {
		t.Fatal("7z file not extracted:", err)
	}
}

func TestPkgExe(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "sub", "run")
	if err := os.MkdirAll(filepath.Dir(run), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, exe := range []string{"sub/run", `sub\run`, "./sub/run"} {
		if p, err := pkgExe(dir, exe); err != nil || p != run {
			t.Fatalf("%q: %q %v", exe, p, err)
		}
	}
	for _, exe := range []string{"../run", "sub/../../run", `..\run`, "/bin/true", `C:\Windows\notepad.exe`, `\\host\share\x.exe`, "sub", "missing", "sub/run:x", ""} {
		if p, err := pkgExe(dir, exe); err == nil {
			t.Fatalf("%q accepted as %q", exe, p)
		}
	}
}

func TestPkgBeatRepeatsTheStepUntilStopped(t *testing.T) {
	api := &pkgAPI{}
	a := pkgTestAgent(t, api)
	defer func(d time.Duration) { pkgBeatEvery = d }(pkgBeatEvery)
	pkgBeatEvery = 20 * time.Millisecond
	stop := a.pkgBeat(pkgTestJob, "extracting", 7)
	time.Sleep(110 * time.Millisecond)
	stop()
	patches, _ := api.got()
	if len(patches) < 3 {
		t.Fatalf("only %d reports while extracting", len(patches))
	}
	for _, p := range patches {
		if p["state"] != "extracting" || p["done"] != 7.0 || p["total"] != 7.0 {
			t.Fatalf("report %v", p)
		}
	}
	time.Sleep(60 * time.Millisecond)
	if after, _ := api.got(); len(after) != len(patches) {
		t.Fatalf("reports went on after stop: %d -> %d", len(patches), len(after))
	}
}
