// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testJob = "0123456789abcdef0123456789abcdef"

type sdioTestFile struct {
	name string
	data []byte
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// sdioLayout lays files out as one torrent stream and gives the plan entry
// for files[k], the way the server builds it.
func sdioLayout(base string, files []sdioTestFile, k int, plen int64) sdioPack {
	var stream []byte
	offs := make([]int64, len(files))
	for i, f := range files {
		offs[i] = int64(len(stream))
		stream = append(stream, f.data...)
	}
	off, size := offs[k], int64(len(files[k].data))
	first, last := off/plen, (off+size-1)/plen
	ranges := func(s, e int64) []sdioRange {
		var rs []sdioRange
		for i, f := range files {
			gs, ge := offs[i], offs[i]+int64(len(f.data))
			lo, hi := max(s, gs), min64(e, ge)
			if lo < hi {
				rs = append(rs, sdioRange{URL: base + "/" + f.name, Start: lo - gs, Length: hi - lo})
			}
		}
		return rs
	}
	p := sdioPack{
		Name: files[k].name, URL: base + "/" + files[k].name, Size: size, PieceLength: plen,
		Head: ranges(first*plen, off), Tail: ranges(off+size, min64((last+1)*plen, int64(len(stream)))),
		Folders: []string{"x/"},
	}
	for n := first; n <= last; n++ {
		s := sha1.Sum(stream[n*plen : min64((n+1)*plen, int64(len(stream)))])
		p.Hashes = append(p.Hashes, hex.EncodeToString(s[:]))
	}
	return p
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

type sdioMirror struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	hook  func(w http.ResponseWriter, r *http.Request, n int) bool
}

func newSdioMirror(t *testing.T, files []sdioTestFile) *sdioMirror {
	m := &sdioMirror{files: map[string][]byte{}, hits: map[string]int{}}
	for _, f := range files {
		m.files[f.name] = f.data
	}
	m.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		m.mu.Lock()
		m.hits[name]++
		n, data, ok := m.hits[name], m.files[name], m.files[name] != nil
		m.mu.Unlock()
		if m.hook != nil && m.hook(w, r, n) {
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(m.Close)
	old := sdioTestRoots
	sdioTestRoots = x509.NewCertPool()
	sdioTestRoots.AddCert(m.Certificate())
	t.Cleanup(func() { sdioTestRoots = old })
	return m
}

func (m *sdioMirror) count(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits[name]
}

func fastSdio(t *testing.T) {
	stall, wait := sdioStall, sdioRetryWait
	sdioStall, sdioRetryWait = 200*time.Millisecond, time.Millisecond
	every := sdioProgressEvery
	sdioProgressEvery = time.Hour
	t.Cleanup(func() { sdioStall, sdioRetryWait, sdioProgressEvery = stall, wait, every })
}

func sdioTestAgent() *Agent { return testUpdateAgent() }

func sdioFetch(t *testing.T, a *Agent, p sdioPack) ([]byte, error) {
	t.Helper()
	return sdioFetchProgress(t, a, p, nil)
}

func sdioFetchProgress(t *testing.T, a *Agent, p sdioPack, progress func(int64)) ([]byte, error) {
	t.Helper()
	if err := p.check(); err != nil {
		t.Fatalf("plan refused: %v", err)
	}
	c, err := a.sdioClient()
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), p.Name)
	err = a.sdioDownload(t.Context(), c, &p, dest, progress)
	b, _ := os.ReadFile(dest)
	return b, err
}

func TestSdioAnswer(t *testing.T) {
	if got := sdioAnswer(testJob, false); got != "not supported on this OS" {
		t.Fatalf("unsupported: %q", got)
	}
	for _, bad := range []string{"", "0123456789ABCDEF0123456789ABCDEF", testJob[:31], testJob + "0", "../" + testJob[3:]} {
		if got := sdioAnswer(bad, true); got != "invalid job id" {
			t.Fatalf("%q: %q", bad, got)
		}
	}
	if got := sdioAnswer(testJob, true); got != "ok" {
		t.Fatalf("first: %q", got)
	}
	if got := sdioAnswer(testJob, true); got != "busy" {
		t.Fatalf("second while running: %q", got)
	}
	sdioMu.Unlock()
	if got := sdioAnswer(testJob, true); got != "ok" {
		t.Fatalf("after the job: %q", got)
	}
	sdioMu.Unlock()
}

func TestSdioPieceLayouts(t *testing.T) {
	fastSdio(t)
	const plen = 16384
	cases := []struct {
		name  string
		files []int
		k     int
	}{
		{"at stream start", []int{40000, 5000}, 0},
		{"in the middle", []int{10000, 40000, 30000}, 1},
		{"smaller than a piece", []int{1000, 2000, 20000}, 1},
		{"on piece borders", []int{plen, 2 * plen, 100}, 1},
		{"at stream end", []int{5000, 30000}, 1},
		{"head from two files", []int{100, 200, 20000, 10}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var files []sdioTestFile
			for i, n := range tc.files {
				files = append(files, sdioTestFile{fmt.Sprintf("f%d.7z", i), randBytes(t, n)})
			}
			m := newSdioMirror(t, files)
			p := sdioLayout(m.URL, files, tc.k, plen)
			got, err := sdioFetch(t, sdioTestAgent(), p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, files[tc.k].data) {
				t.Fatal("pack differs")
			}
		})
	}
}

func TestSdioPieceMismatch(t *testing.T) {
	fastSdio(t)
	files := []sdioTestFile{{"a.7z", randBytes(t, 3000)}, {"p.7z", randBytes(t, 50000)}, {"b.7z", randBytes(t, 100)}}
	m := newSdioMirror(t, files)
	p := sdioLayout(m.URL, files, 1, 16384)
	bad := bytes.Clone(files[1].data)
	bad[20000] ^= 1
	m.files["p.7z"] = bad
	_, err := sdioFetch(t, sdioTestAgent(), p)
	if err == nil || err.Error() != "piece 1 of p.7z does not match the torrent" {
		t.Fatalf("got %v", err)
	}
	if m.count("p.7z") != 1 {
		t.Fatalf("a bad piece was fetched %d times", m.count("p.7z"))
	}

	// head bytes that differ fail piece 0
	m.files["p.7z"] = files[1].data
	m.files["a.7z"] = randBytes(t, 3000)
	if _, err := sdioFetch(t, sdioTestAgent(), p); err == nil || !strings.Contains(err.Error(), "piece 0 of p.7z") {
		t.Fatalf("head: %v", err)
	}

	// tail bytes that differ fail the last piece
	m.files["a.7z"] = files[0].data
	m.files["b.7z"] = randBytes(t, 100)
	if _, err := sdioFetch(t, sdioTestAgent(), p); err == nil || !strings.Contains(err.Error(), "piece 3 of p.7z") {
		t.Fatalf("tail: %v", err)
	}
}

func TestSdioPackSize(t *testing.T) {
	fastSdio(t)
	files := []sdioTestFile{{"p.7z", randBytes(t, 40000)}, {"b.7z", randBytes(t, 100)}}
	m := newSdioMirror(t, files)
	p := sdioLayout(m.URL, files, 0, 16384)

	m.files["p.7z"] = append(bytes.Clone(files[0].data), 1, 2, 3)
	if _, err := sdioFetch(t, sdioTestAgent(), p); err == nil || err.Error() != "p.7z is larger than the torrent says" {
		t.Fatalf("longer: %v", err)
	}
	if m.count("p.7z") != 1 {
		t.Fatalf("a longer pack was fetched %d times", m.count("p.7z"))
	}

	m.files["p.7z"] = files[0].data[:39000]
	_, err := sdioFetch(t, sdioTestAgent(), p)
	if err == nil || !strings.Contains(err.Error(), "39000 of 40000 bytes") {
		t.Fatalf("shorter: %v", err)
	}
}

func TestSdioResumesAfterStall(t *testing.T) {
	fastSdio(t)
	t.Run("head checked", func(t *testing.T) { testSdioResume(t, true) })
	// an unchecked first piece counts as verified once it is written
	t.Run("head not checked", func(t *testing.T) { testSdioResume(t, false) })
}

func testSdioResume(t *testing.T, headCheck bool) {
	const plen = 16384
	files := []sdioTestFile{{"a.7z", randBytes(t, 1000)}, {"p.7z", randBytes(t, 60000)}}
	m := newSdioMirror(t, files)
	p := sdioLayout(m.URL, files, 1, plen)
	if !headCheck {
		p.HeadCheck = &headCheck
		p.Head[0].URL = m.URL + "/gone.7z"
	}
	var ranges []string
	m.hook = func(w http.ResponseWriter, r *http.Request, n int) bool {
		if r.URL.Path != "/p.7z" {
			return false
		}
		m.mu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		m.mu.Unlock()
		if n > 1 {
			return false
		}
		// one and a half pieces, then nothing
		w.Header().Set("Content-Length", strconv.Itoa(60000))
		w.Write(files[1].data[:plen-1000+plen/2])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	}
	var seen []int64
	got, err := sdioFetchProgress(t, sdioTestAgent(), p, func(n int64) { seen = append(seen, n) })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, files[1].data) {
		t.Fatal("pack differs after the resume")
	}
	if m.count("gone.7z") != 0 {
		t.Fatal("an unchecked head was fetched")
	}
	// progress steps back once, to the resume offset, not to 0
	var back int
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			back++
			if seen[i] <= plen-1000 {
				t.Fatalf("after the resume progress is %d", seen[i])
			}
		}
	}
	if back != 1 || seen[len(seen)-1] != 60000 {
		t.Fatalf("progress %v", seen)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(ranges) != 2 || ranges[0] != "" || ranges[1] != fmt.Sprintf("bytes=%d-", plen-1000) {
		t.Fatalf("requests: %q", ranges)
	}
}

func TestSdioUncheckedEnds(t *testing.T) {
	fastSdio(t)
	var p sdioPack
	if json.Unmarshal([]byte(`{}`), &p); !sdioOn(p.HeadCheck) || !sdioOn(p.TailCheck) {
		t.Fatal("missing flags must mean checked")
	}
	if json.Unmarshal([]byte(`{"head_check": false, "tail_check": true}`), &p); sdioOn(p.HeadCheck) || !sdioOn(p.TailCheck) {
		t.Fatal("flags not read")
	}

	no := false
	head := func(p *sdioPack, base string) { p.HeadCheck = &no; p.Head[0].URL = base + "/gone.7z" }
	tail := func(p *sdioPack, base string) { p.TailCheck = &no; p.Tail[0].URL = base + "/gone.7z" }
	// p.7z: bytes up to 13383 are piece 0, 13384-29767 piece 1, from 46152 piece 3 (the last)
	long := []sdioTestFile{{"a.7z", randBytes(t, 3000)}, {"p.7z", randBytes(t, 50000)}, {"b.7z", randBytes(t, 100)}}
	// p.7z lies inside piece 0
	short := []sdioTestFile{{"a.7z", randBytes(t, 1000)}, {"p.7z", randBytes(t, 2000)}, {"b.7z", randBytes(t, 20000)}}
	cases := []struct {
		name    string
		files   []sdioTestFile
		mod     func(*sdioPack, string)
		other   string // neighbor that is still fetched
		missed  int    // a changed byte here goes unnoticed
		caught  int    // a changed byte here is found, -1 none
		caughtN int
	}{
		{"head", long, head, "b.7z", 100, 20000, 1},
		{"tail", long, tail, "a.7z", 49000, 20000, 1},
		{"one piece, head", short, head, "b.7z", 500, -1, 0},
		{"one piece, tail", short, tail, "a.7z", 1500, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSdioMirror(t, tc.files)
			p := sdioLayout(m.URL, tc.files, 1, 16384)
			tc.mod(&p, m.URL)
			want := tc.files[1].data
			if got, err := sdioFetch(t, sdioTestAgent(), p); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("clean pack: %v", err)
			}
			bad := bytes.Clone(want)
			bad[tc.missed] ^= 1
			m.files["p.7z"] = bad
			if got, err := sdioFetch(t, sdioTestAgent(), p); err != nil || !bytes.Equal(got, bad) {
				t.Fatalf("a byte in the unchecked piece: %v", err)
			}
			if tc.caught >= 0 {
				bad = bytes.Clone(want)
				bad[tc.caught] ^= 1
				m.files["p.7z"] = bad
				_, err := sdioFetch(t, sdioTestAgent(), p)
				if err == nil || err.Error() != fmt.Sprintf("piece %d of p.7z does not match the torrent", tc.caughtN) {
					t.Fatalf("a byte in a checked piece: %v", err)
				}
			}
			if m.count("gone.7z") != 0 || m.count(tc.other) == 0 {
				t.Fatalf("requests: gone %d, %s %d", m.count("gone.7z"), tc.other, m.count(tc.other))
			}
		})
	}
}

func TestSdioPlanCheck(t *testing.T) {
	files := []sdioTestFile{{"a.7z", make([]byte, 100)}, {"p.7z", make([]byte, 40000)}, {"b.7z", make([]byte, 30000)}}
	good := func() sdioPack { return sdioLayout("https://mirror.example/x", files, 1, 16384) }
	plan := func(p sdioPack) *sdioPlan {
		return &sdioPlan{Job: testJob, Deadline: 14400, Script: "x", ScriptTimeout: 1800, Packs: []sdioPack{p}}
	}

	p := good()
	p.Folders = []string{`Intel\allx64\X_1.2`}
	if err := plan(p).check(testJob); err != nil || p.Folders[0] != "Intel/allx64/X_1.2/" {
		t.Fatalf("%v, folder %q", err, p.Folders)
	}
	if err := plan(good()).check("ffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("plan of another job taken")
	}

	bad := map[string]func(p *sdioPack){
		"http pack":     func(p *sdioPack) { p.URL = "http://mirror.example/x/p.7z" },
		"http head":     func(p *sdioPack) { p.Head[0].URL = "http://mirror.example/x/a.7z" },
		"no scheme":     func(p *sdioPack) { p.Tail[0].URL = "//mirror.example/x/a.7z" },
		"hash missing":  func(p *sdioPack) { p.Hashes = p.Hashes[1:] },
		"hash too many": func(p *sdioPack) { p.Hashes = append(p.Hashes, p.Hashes[0]) },
		"hash not hex":  func(p *sdioPack) { p.Hashes[0] = strings.Repeat("z", 40) },
		"head too long": func(p *sdioPack) { p.Head[0].Length = 16384 },
		"tail too long": func(p *sdioPack) { p.Tail[0].Length += 16384 * 2 },
		"size":          func(p *sdioPack) { p.Size = 0 },
		"piece length":  func(p *sdioPack) { p.PieceLength = 1 },
		"name":          func(p *sdioPack) { p.Name = `..\p.7z` },
		"no folder":     func(p *sdioPack) { p.Folders = nil },
		"folder up":     func(p *sdioPack) { p.Folders = []string{"a/../../b/"} },
		"folder root":   func(p *sdioPack) { p.Folders = []string{"/a/"} },
		"folder drive":  func(p *sdioPack) { p.Folders = []string{`C:\a`} },
		"folder empty":  func(p *sdioPack) { p.Folders = []string{"/"} },
		"folder dot":    func(p *sdioPack) { p.Folders = []string{"./a/"} },
	}
	for name, mod := range bad {
		p := good()
		mod(&p)
		if err := plan(p).check(testJob); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	p = good()
	p.URL = "http://mirror.example/x/p.7z"
	if err := plan(p).check(testJob); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("http message: %v", err)
	}
	p = good()
	p.Hashes = p.Hashes[1:]
	if err := plan(p).check(testJob); err == nil || err.Error() != "p.7z: the plan does not fit the torrent" {
		t.Fatalf("misfit message: %v", err)
	}
	for _, mod := range []func(*sdioPlan){
		func(p *sdioPlan) { p.Deadline = 0 },
		func(p *sdioPlan) { p.ScriptTimeout = 60 },
		func(p *sdioPlan) { p.Script = "" },
		func(p *sdioPlan) { p.Packs = nil },
	} {
		p := plan(good())
		mod(p)
		if p.check(testJob) == nil {
			t.Errorf("plan %+v taken", p)
		}
	}
}

func TestSdioEntry(t *testing.T) {
	folders := []string{"intel/allx64/x_1.2/", "Other/"}
	for name, want := range map[string]string{
		"intel/allx64/x_1.2/a.inf":     "intel/allx64/x_1.2/a.inf",
		"Intel/AllX64/X_1.2/Sub/b.sys": "Intel/AllX64/X_1.2/Sub/b.sys",
		`intel\allx64\x_1.2\c.cat`:     "intel/allx64/x_1.2/c.cat",
		"intel/allx64/x_1.2/":          "intel/allx64/x_1.2",
		"other/d.inf":                  "other/d.inf",
	} {
		got, i, err := sdioEntry(name, folders)
		if err != nil || i < 0 || got != want {
			t.Errorf("%q: %q %d %v", name, got, i, err)
		}
	}
	for _, name := range []string{"intel/allx64/x_1.20/a.inf", "intel/allx64/x_1.2", "intel/a.inf", "x/intel/allx64/x_1.2/a.inf", "/intel/allx64/x_1.2/a.inf", "../intel/allx64/x_1.2/a.inf"} {
		if _, i, err := sdioEntry(name, folders); i != -1 || err != nil {
			t.Errorf("%q matched (%d, %v)", name, i, err)
		}
	}
	for _, name := range []string{"intel/allx64/x_1.2/../../../evil.dll", `intel\allx64\x_1.2\..\..\..\evil.dll`, "intel/allx64/x_1.2/a.inf:ads", "other/C:/x", "intel/allx64/x_1.2/a\x00.inf"} {
		if _, _, err := sdioEntry(name, folders); err == nil {
			t.Errorf("%q not refused", name)
		}
	}
}

func TestSdioExtract(t *testing.T) {
	pack := filepath.Join("testdata", "sdio", "pack.7z.bin")
	dest := filepath.Join(t.TempDir(), "files")
	if err := sdioExtract(pack, "pack.7z", []string{"drv/allx64/test_1.0/"}, dest, sdioExtractMax); err != nil {
		t.Fatal(err)
	}
	var got []string
	filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dest, p)
			got = append(got, filepath.ToSlash(rel))
		}
		return err
	})
	want := []string{"DRV/AllX64/Test_1.0/sub/test.sys", "DRV/AllX64/Test_1.0/test.cat", "DRV/AllX64/Test_1.0/test.inf"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("extracted %q", got)
	}
	inf, _ := os.ReadFile(filepath.Join(dest, "DRV", "AllX64", "Test_1.0", "test.inf"))
	if !bytes.HasPrefix(inf, []byte("[Version]")) {
		t.Fatalf("test.inf: %q", inf)
	}
	if fi, err := os.Stat(filepath.Join(dest, "DRV", "AllX64", "Test_1.0", "sub", "test.sys")); err != nil || fi.Size() != 3000 {
		t.Fatalf("test.sys: %v", err)
	}

	err := sdioExtract(pack, "pack.7z", []string{"links/allx64/L_1.0/"}, t.TempDir(), sdioExtractMax)
	if err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("link: %v", err)
	}
	err = sdioExtract(pack, "pack.7z", []string{"drv/allx64/test_1.0/", "nope/x/"}, t.TempDir(), sdioExtractMax)
	if err == nil || err.Error() != "nope/x/ is not in pack.7z" {
		t.Fatalf("missing folder: %v", err)
	}
	err = sdioExtract(pack, "pack.7z", []string{"drv/allx64/test_1.0/"}, t.TempDir(), 1000)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("cap: %v", err)
	}
}

func TestSdioSpace(t *testing.T) {
	if err := sdioSpace(3<<30, 1<<30); err != nil {
		t.Fatal(err)
	}
	err := sdioSpace(2<<30, 1<<30)
	if err == nil || err.Error() != "not enough disk space: need 3.0 GB, free 2.0 GB" {
		t.Fatalf("got %v", err)
	}
}

func TestSdioMarker(t *testing.T) {
	r := sdioMarker("p.7z", "x\r\nULRMM-PKG {\"result\":\"fail\",\"exit\":1,\"sig\":\"\",\"signer\":\"\",\"msg\":\"old\"}\r\n"+
		"ULRMM-PKG {\"result\":\"reboot\",\"exit\":3010,\"sig\":\"valid\",\"signer\":\"Intel\",\"msg\":\"\"}\r\n")
	if r.Pack != "p.7z" || r.Result != "reboot" || r.Exit == nil || *r.Exit != 3010 || r.Signer != "Intel" {
		t.Fatalf("%+v", r)
	}
	if r := sdioMarker("p.7z", "ULRMM-PKG {\"result\":\"ok\",\"exit\":null,\"sig\":\"\",\"signer\":\"\",\"msg\":\"\"}"); r.Result != "ok" || r.Exit != nil {
		t.Fatalf("null exit: %+v", r)
	}
	r = sdioMarker("p.7z", "ULRMM-PKG {\"result\":\"refused\",\"exit\":null,\"sig\":\"NotSigned\",\"signer\":\"\",\"msg\":\"x.cat is not signed\"}\r\n")
	if r.Result != "refused" || r.Msg != "x.cat is not signed" || r.Sig != "NotSigned" || r.Pack != "p.7z" {
		t.Fatalf("refused: %+v", r)
	}
	for _, out := range []string{"", "no marker", "ULRMM-PKG {broken", "ULRMM-PKG {\"result\":\"maybe\"}"} {
		if r := sdioMarker("p.7z", out); r.Result != "fail" || r.Msg != "the install script stopped early" {
			t.Fatalf("%q: %+v", out, r)
		}
	}
}

type sdioAPI struct {
	mu      sync.Mutex
	patches []map[string]interface{}
	plan    func() *sdioPlan
	final   []int
	mirror  *sdioMirror
}

func (s *sdioAPI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/agent1/sdio/"+testJob+"/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(s.plan())
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.patches = append(s.patches, body)
		if st := body["state"]; (st == "done" || st == "failed") && len(s.final) > 0 {
			w.WriteHeader(s.final[0])
			s.final = s.final[1:]
		}
	}
}

func sdioJobSetup(t *testing.T) (*Agent, *sdioAPI, sdioPack, string) {
	pack, err := os.ReadFile(filepath.Join("testdata", "sdio", "pack.7z.bin"))
	if err != nil {
		t.Fatal(err)
	}
	files := []sdioTestFile{{"DP_A_1.7z", randBytes(t, 5000)}, {"DP_Test_26101.7z", pack}, {"DP_B_1.7z", randBytes(t, 20000)}}
	m := newSdioMirror(t, files)
	p := sdioLayout(m.URL, files, 1, 16384)
	p.Folders = []string{"drv/allx64/test_1.0/"}
	api := &sdioAPI{mirror: m, plan: func() *sdioPlan {
		return &sdioPlan{Job: testJob, Deadline: 600, Script: "script", ScriptTimeout: 300, Packs: []sdioPack{p}}
	}}
	a := apiAgent(t, api.handler(t))
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sdio-0000", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	return a, api, p, root
}

func TestSdioJob(t *testing.T) {
	fastSdio(t)
	a, api, p, root := sdioJobSetup(t)
	api.final = []int{502}
	var ran bool
	h := sdioHost{
		root: func() (string, error) { return root, nil },
		free: func(string) (uint64, error) { return 8 << 30, nil },
		install: func(script, dir string, timeout int) (string, string) {
			ran = true
			if script != "script" || timeout != 300 || dir != filepath.Join(root, "sdio-"+testJob, "files") {
				t.Errorf("install(%q, %q, %d)", script, dir, timeout)
			}
			if _, err := os.Stat(filepath.Join(dir, "DRV", "AllX64", "Test_1.0", "test.inf")); err != nil {
				t.Error("approved driver not extracted:", err)
			}
			for _, gone := range []string{filepath.Join(dir, "other"), filepath.Join(dir, "DRV", "AllX64", "Test_1.0x"), filepath.Join(filepath.Dir(dir), p.Name)} {
				if _, err := os.Lstat(gone); err == nil {
					t.Error(gone, "is there during the install")
				}
			}
			return "pnputil output\nULRMM-PKG {\"result\":\"ok\",\"exit\":0,\"sig\":\"valid\",\"signer\":\"Test\",\"msg\":\"\"}\n", "a warning"
		},
	}
	a.runSdioJob(testJob, h)
	if !ran {
		t.Fatal("install script did not run")
	}
	if len(api.patches) != 4 {
		t.Fatalf("patches %v", api.patches)
	}
	if b := api.patches[0]; b["state"] != "downloading" || b["detail"] != "DP_Test_26101.7z (3.5 kB)" || b["done"] != 0.0 || b["total"] != 3589.0 || len(b) != 4 {
		t.Fatalf("downloading: %v", b)
	}
	if b := api.patches[1]; b["state"] != "installing" || len(b) != 1 {
		t.Fatalf("installing: %v", b)
	}
	final := api.patches[3]
	res, _ := json.Marshal(final["results"])
	if final["state"] != "done" || final["detail"] != "" ||
		string(res) != `[{"exit":0,"msg":"","pack":"DP_Test_26101.7z","result":"ok","sig":"valid","signer":"Test"}]` {
		t.Fatalf("final: %v %s", final, res)
	}
	if out, _ := final["output"].(string); !strings.Contains(out, "DP_Test_26101.7z\npnputil output") || !strings.HasSuffix(out, "a warning") {
		t.Fatalf("output %q", final["output"])
	}
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Fatalf("left in the work dir: %v", left)
	}
}

func TestSdioProgress(t *testing.T) {
	fastSdio(t)
	sdioProgressEvery = 40 * time.Millisecond
	a, api, p, root := sdioJobSetup(t)
	// the mirror sends the pack in 500 byte steps, 20 ms apart
	pack, _ := os.ReadFile(filepath.Join("testdata", "sdio", "pack.7z.bin"))
	api.mirror.hook = func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path != "/"+p.Name {
			return false
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(pack)))
		for i := 0; i < len(pack); i += 500 {
			w.Write(pack[i:min64(int64(i+500), int64(len(pack)))])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
		return true
	}
	start := time.Now()
	a.runSdioJob(testJob, sdioHost{
		root: func() (string, error) { return root, nil },
		free: func(string) (uint64, error) { return 8 << 30, nil },
		install: func(string, string, int) (string, string) {
			return "ULRMM-PKG {\"result\":\"ok\",\"exit\":0,\"sig\":\"\",\"signer\":\"\",\"msg\":\"\"}", ""
		},
	})
	elapsed := time.Since(start)

	var done []float64
	installing := -1
	for i, b := range api.patches {
		switch b["state"] {
		case "downloading":
			if installing >= 0 {
				t.Fatal("progress after the installing PATCH")
			}
			if b["total"] != 3589.0 || b["detail"] != "DP_Test_26101.7z (3.5 kB)" || len(b) != 4 {
				t.Fatalf("progress body %v", b)
			}
			done = append(done, b["done"].(float64))
		case "installing":
			installing = i
		}
	}
	if installing < 0 || len(done) < 2 || done[0] != 0 {
		t.Fatalf("progress %v, installing at %d", done, installing)
	}
	for i := 1; i < len(done); i++ {
		if done[i] < done[i-1] || done[i] > 3589 {
			t.Fatalf("progress not monotonic: %v", done)
		}
	}
	if max := int(elapsed/sdioProgressEvery) + 1; len(done) > max {
		t.Fatalf("%d progress PATCHes in %s, at most %d", len(done), elapsed, max)
	}
}

// A server that does not answer must not hold up report (the download).
func TestSdioMeterNeverBlocks(t *testing.T) {
	fastSdio(t)
	sdioProgressEvery = 0
	release := make(chan struct{})
	var mu sync.Mutex
	var got []map[string]interface{}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		var b map[string]interface{}
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
		<-release
	})
	m := a.newSdioMeter(t.Context(), testJob, "p.7z (1 kB)", 1000)
	start := time.Now()
	for i := int64(1); i <= 1000; i++ {
		m.report(i)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("1000 reports took %s while the server hung", d)
	}
	close(release)
	m.stop()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0]["done"] != 0.0 || got[0]["total"] != 1000.0 {
		t.Fatalf("progress while one was out: %v", got)
	}
}

func TestSdioJobRefused(t *testing.T) {
	fastSdio(t)
	a, api, _, root := sdioJobSetup(t)
	a.runSdioJob(testJob, sdioHost{
		root: func() (string, error) { return root, nil },
		free: func(string) (uint64, error) { return 8 << 30, nil },
		install: func(string, string, int) (string, string) {
			return "ULRMM-PKG {\"result\":\"refused\",\"exit\":null,\"sig\":\"NotSigned\",\"signer\":\"\",\"msg\":\"test.cat is not signed\"}\n", ""
		},
	})
	final := api.patches[len(api.patches)-1]
	res, _ := json.Marshal(final["results"])
	if final["state"] != "failed" || final["detail"] != "DP_Test_26101.7z: test.cat is not signed" ||
		string(res) != `[{"exit":null,"msg":"test.cat is not signed","pack":"DP_Test_26101.7z","result":"refused","sig":"NotSigned","signer":""}]` {
		t.Fatalf("final: %v %s", final, res)
	}
}

// The RMM's own CA never reaches the mirror client.
func TestSdioMirrorTLS(t *testing.T) {
	fastSdio(t)
	files := []sdioTestFile{{"p.7z", randBytes(t, 100)}}
	m := newSdioMirror(t, files)
	sdioTestRoots = nil
	a := sdioTestAgent()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	a.Cert = ca
	_, err := sdioFetch(t, a, sdioLayout(m.URL, files, 0, 16384))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted mirror: %v", err)
	}
	if m.count("p.7z") != 0 {
		t.Fatal("the mirror got a request")
	}
}

func TestSdioJobFails(t *testing.T) {
	fastSdio(t)
	a, api, _, root := sdioJobSetup(t)
	h := sdioHost{
		root:    func() (string, error) { return root, nil },
		free:    func(string) (uint64, error) { return 1024, nil },
		install: func(string, string, int) (string, string) { t.Error("install ran"); return "", "" },
	}
	a.runSdioJob(testJob, h)
	final := api.patches[len(api.patches)-1]
	if final["state"] != "failed" || final["detail"] != "DP_Test_26101.7z: not enough disk space: need 1.0 GB, free 1.0 kB" {
		t.Fatalf("no space: %v", final)
	}

	// a plan with an http link is refused before anything is fetched
	api.patches = nil
	inner := api.plan
	api.plan = func() *sdioPlan {
		p := inner()
		p.Packs[0].URL = strings.Replace(p.Packs[0].URL, "https://", "http://", 1)
		return p
	}
	h.free = func(string) (uint64, error) { t.Error("plan not refused"); return 0, nil }
	a.runSdioJob(testJob, h)
	if len(api.patches) != 1 || api.patches[0]["state"] != "failed" || !strings.Contains(api.patches[0]["detail"].(string), "not https") {
		t.Fatalf("http plan: %v", api.patches)
	}
	if r, _ := api.patches[0]["results"].([]interface{}); r == nil || len(r) != 0 {
		t.Fatalf("results must be an empty list: %v", api.patches[0]["results"])
	}

	// a 4xx on the final PATCH is not retried
	api.patches, api.final = nil, []int{404, 404}
	a.runSdioJob(testJob, h)
	if len(api.patches) != 1 {
		t.Fatalf("404: %d patches", len(api.patches))
	}
}
