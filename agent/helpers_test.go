// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	nats "github.com/nats-io/nats.go"
)

func TestStringHelpers(t *testing.T) {
	for in, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 kB", 1536: "1.5 kB", 1 << 30: "1.0 GB", 1536 << 20: "1.5 GB"} {
		if got := ByteCountSI(in); got != want {
			t.Fatalf("ByteCountSI(%d) = %q, want %q", in, got, want)
		}
	}
	if StripAll(" 1.2.3.4\r\n") != "1.2.3.4" || DjangoStringResp(`"x"`) != "x" || CleanString("a\x00b\xffc") != "abc" {
		t.Fatal("string helpers")
	}
	if removeWinNewLines("a\r\nb") != "a\nb" || removeNewlines("a\nb\n") != "ab" {
		t.Fatal("newline helpers")
	}
	if !contains("loop0", []string{"ram", "loop"}) || contains("sda", []string{"ram", "loop"}) {
		t.Fatal("contains")
	}
	id := GenerateAgentID()
	if len(id) != 40 || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		t.Fatalf("agent id %q", id)
	}
}

func TestRandomRanges(t *testing.T) {
	for i := 0; i < 10000; i++ {
		if v := randRange(100, 400); v < 100 || v >= 400 {
			t.Fatalf("randRange gave %d", v)
		}
	}
	if randRange(3, 4) != 3 || randRange(5, 5) != 5 || randRange(9, 2) != 9 {
		t.Fatal("degenerate ranges")
	}
	if regRangeToInt("5,6") != 5 {
		t.Fatal("regRangeToInt")
	}
	for _, bad := range []string{"5", "6,5", "x,9", "", "0,4", "1,2,3"} {
		if regRangeToInt(bad) != 0 {
			t.Fatalf("regRangeToInt(%q) not 0", bad)
		}
	}
}

func TestPythonForWindows(t *testing.T) {
	for _, c := range []struct {
		major, minor int
		want         string
	}{{10, 0, "3.14.5"}, {11, 0, "3.14.5"}, {6, 3, "3.11.9"}, {6, 1, "3.8.7"}} {
		if got := pythonForWindows(c.major, c.minor); got != c.want {
			t.Fatalf("%d.%d: %s", c.major, c.minor, got)
		}
	}
}

func TestCompleteUTF8(t *testing.T) {
	e := []byte("é") // c3 a9
	euro := []byte("€")
	cases := []struct {
		in   []byte
		want int
	}{
		{[]byte("abc"), 3},
		{append([]byte("ab"), e[0]), 2},
		{append([]byte("ab"), e...), 4},
		{append([]byte("a"), euro[:2]...), 1},
		{[]byte{'a', 0xff}, 2},
		{[]byte{0xa9, 0xa9}, 2},
		{nil, 0},
	}
	for _, c := range cases {
		if got := completeUTF8(c.in); got != c.want {
			t.Fatalf("% x: got %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFetchFileErrorStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("download sent an Authorization header")
		}
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer ts.Close()
	dest := filepath.Join(t.TempDir(), "f")
	a := testUpdateAgent()
	a.Cert = writeCA(t, ts)
	err := a.fetchFile(ts.URL, dest, "", time.Minute)
	if err == nil || err.Error() != "download answered 404" {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("error body left on disk")
	}
}

func TestFetchFileSizeCap(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "0123456789")
	}))
	defer ts.Close()
	old := fetchFileMax
	defer func() { fetchFileMax = old }()
	dest := filepath.Join(t.TempDir(), "f")
	a := testUpdateAgent()
	a.Cert = writeCA(t, ts)
	fetchFileMax = 9
	if err := a.fetchFile(ts.URL, dest, "", time.Minute); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("10 bytes past a 9 byte cap: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("partial file left on disk")
	}
	fetchFileMax = 10
	if err := a.fetchFile(ts.URL, dest, "", time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestPublicIP(t *testing.T) {
	answers := map[string]string{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "ua" {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		io.WriteString(w, answers[r.URL.Path])
	}))
	defer ts.Close()
	old := BrandPubIPURL
	defer func() { BrandPubIPURL = old }()
	a := testUpdateAgent()
	a.AgentHeader = "ua"
	a.ApiURL, a.Cert = "127.0.0.1", writeCA(t, ts)

	BrandPubIPURL = ts.URL + "/v4"
	answers["/v4"] = " 203.0.113.9\n"
	if ip := a.PublicIP(); ip != "203.0.113.9" {
		t.Fatalf("got %q", ip)
	}
	answers["/v4"] = "<html>proxy login</html>"
	if ip := a.PublicIP(); ip != "<html>proxy login</html>" {
		t.Fatalf("non-IP answer: %q", ip)
	}
	BrandPubIPURL = "https://127.0.0.1:1/x"
	if ip := a.PublicIP(); ip != "error" {
		t.Fatalf("nothing answered: %q", ip)
	}
	BrandPubIPURL = strings.Replace(ts.URL, "https", "http", 1) + "/v4"
	if ip := a.PublicIP(); ip != "error" {
		t.Fatalf("plain http: %q", ip)
	}
}

func TestMacServicePlist(t *testing.T) {
	old := BrandServiceDisplay
	defer func() { BrandServiceDisplay = old }()
	BrandServiceDisplay = `R&D <Agent>`
	p := macServicePlist("/opt/ulrmm-agent/ulrmm-agent")
	d := xml.NewDecoder(strings.NewReader(p))
	for {
		if _, err := d.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("not well-formed: %v\n%s", err, p)
		}
	}
	for _, want := range []string{"<string>" + macPlistName + "</string>", "R&amp;D &lt;Agent&gt;", "<string>-m</string>", "<string>svc</string>", "<key>KeepAlive</key>"} {
		if !strings.Contains(p, want) {
			t.Fatalf("plist lacks %q", want)
		}
	}
}

// The sizes of all entries count together.
func TestUnzipSizeLimit(t *testing.T) {
	old := unzipMax
	unzipMax = 10
	defer func() { unzipMax = old }()
	dir := t.TempDir()
	zp := filepath.Join(dir, "a.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"one", "two"} {
		w, _ := zw.Create(name)
		w.Write([]byte("123456"))
	}
	zw.Close()
	os.WriteFile(zp, buf.Bytes(), 0o600)
	if err := Unzip(zp, filepath.Join(dir, "out")); err == nil || !strings.Contains(err.Error(), "unpacks to more than") {
		t.Fatalf("12 bytes past a 10 byte limit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "one")); err == nil {
		t.Fatal("wrote before the check")
	}
	unzipMax = 12
	if err := Unzip(zp, filepath.Join(dir, "ok")); err != nil {
		t.Fatal(err)
	}
}

func TestUnzipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "a.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../evil")
	w.Write([]byte("x"))
	zw.Close()
	os.WriteFile(zp, buf.Bytes(), 0o600)
	if err := Unzip(zp, filepath.Join(dir, "out")); err == nil {
		t.Fatal("zip slip accepted")
	}

	buf.Reset()
	zw = zip.NewWriter(&buf)
	w, _ = zw.Create("deno")
	w.Write([]byte("bin"))
	zw.Close()
	os.WriteFile(zp, buf.Bytes(), 0o600)
	out := filepath.Join(dir, "ok")
	if err := Unzip(zp, out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "deno")); string(b) != "bin" {
		t.Fatalf("content %q", b)
	}
}

func TestUnzipDropsSpecialModeBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no setuid on Windows")
	}
	dir := t.TempDir()
	zp := filepath.Join(dir, "a.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "suid"}
	h.SetMode(0o755 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("x"))
	zw.Close()
	os.WriteFile(zp, buf.Bytes(), 0o600)
	out := filepath.Join(dir, "out")
	if err := Unzip(zp, out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(out, "suid"))
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode(); m&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || m.Perm()&0o700 != 0o700 {
		t.Fatalf("mode %v", m)
	}
}

func writeTarGz(t *testing.T, path string, hdrs ...*tar.Header) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			tw.Write(bytes.Repeat([]byte("n"), int(h.Size)))
		}
	}
	tw.Close()
	gz.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	a := testUpdateAgent()
	p := filepath.Join(dir, "nu.tar.gz")
	writeTarGz(t, p,
		&tar.Header{Name: "nu-0.1/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "nu-0.1/nu", Typeflag: tar.TypeReg, Mode: 0o755, Size: 3},
	)
	got, err := a.ExtractTarGz(p, dir)
	if err != nil || got != "nu-0.1/" {
		t.Fatalf("got %q %v", got, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "nu-0.1", "nu")); string(b) != "nnn" {
		t.Fatalf("content %q", b)
	}

	writeTarGz(t, p, &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	if _, err := a.ExtractTarGz(p, filepath.Join(dir, "x")); err == nil {
		t.Fatal("symlink accepted")
	}
	writeTarGz(t, p, &tar.Header{Name: "../../evil", Typeflag: tar.TypeReg, Size: 1})
	if _, err := a.ExtractTarGz(p, filepath.Join(dir, "y")); err == nil {
		t.Fatal("traversal accepted")
	}
}

func TestExtractTarGzLimits(t *testing.T) {
	oldMax, oldEntries := unzipMax, unzipEntriesMax
	defer func() { unzipMax, unzipEntriesMax = oldMax, oldEntries }()
	dir := t.TempDir()
	a := testUpdateAgent()
	p := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, p,
		&tar.Header{Name: "one", Typeflag: tar.TypeReg, Mode: 0o644, Size: 6},
		&tar.Header{Name: "two", Typeflag: tar.TypeReg, Mode: 0o644, Size: 6},
	)
	unzipMax = 10
	if _, err := a.ExtractTarGz(p, filepath.Join(dir, "big")); err == nil || !strings.Contains(err.Error(), "unpacks to more than") {
		t.Fatalf("12 bytes past a 10 byte limit: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "big", "two")); err != nil || fi.Size() > 5 {
		t.Fatalf("copy not stopped at the limit: %v %v", fi, err)
	}
	unzipMax = 12
	if _, err := a.ExtractTarGz(p, filepath.Join(dir, "fits")); err != nil {
		t.Fatal(err)
	}
	unzipEntriesMax = 1
	if _, err := a.ExtractTarGz(p, filepath.Join(dir, "many")); err == nil || !strings.Contains(err.Error(), "more than 1 entries") {
		t.Fatalf("two entries past a limit of one: %v", err)
	}
}

// fakeProxy answers one CONNECT with status and then sends extra bytes.
func fakeProxy(t *testing.T, status string, gotReq chan<- *http.Request) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		gotReq <- req
		io.WriteString(c, "HTTP/1.1 "+status+"\r\n\r\nINFO {}\r\n")
		time.Sleep(200 * time.Millisecond)
	}()
	return l.Addr().String()
}

func TestHTTPConnectDialer(t *testing.T) {
	reqs := make(chan *http.Request, 1)
	addr := fakeProxy(t, "200 Connection established", reqs)
	u, _ := url.Parse("http://user:pw@" + addr)
	conn, err := newHTTPConnectDialer(u).Dial("tcp", "nats.example:4222")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := <-reqs
	if req.Method != http.MethodConnect || req.Host != "nats.example:4222" {
		t.Fatalf("request %s %s", req.Method, req.Host)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pw")); req.Header.Get("Proxy-Authorization") != want {
		t.Fatalf("auth %q", req.Header.Get("Proxy-Authorization"))
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "INFO {}\r\n" {
		t.Fatalf("bytes after the answer lost: %q %v", line, err)
	}

	addr = fakeProxy(t, "407 Proxy Authentication Required", reqs)
	u, _ = url.Parse("http://" + addr)
	if _, err := newHTTPConnectDialer(u).Dial("tcp", "nats.example:4222"); err == nil || !strings.Contains(err.Error(), "proxy rejected connection: 407") {
		t.Fatalf("407: %v", err)
	}
}

func TestProxyAddr(t *testing.T) {
	for in, want := range map[string]string{
		"http://proxy.corp":          "proxy.corp:80",
		"https://proxy.corp":         "proxy.corp:443",
		"http://u:p@proxy.corp:3128": "proxy.corp:3128",
		"http://[2001:db8::1]":       "[2001:db8::1]:80",
		"https://[2001:db8::1]:8443": "[2001:db8::1]:8443",
	} {
		u, _ := url.Parse(in)
		if got := proxyAddr(u); got != want {
			t.Errorf("proxyAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNatsOptionsProxyScheme(t *testing.T) {
	var log strings.Builder
	a := testUpdateAgent()
	a.Logger.SetOutput(&log)
	a.Proxy = "socks5://user:secret@127.0.0.1:1"
	o := nats.GetDefaultOptions()
	for _, opt := range a.setupNatsOptions() {
		opt(&o)
	}
	if !strings.Contains(log.String(), "unsupported proxy scheme: socks5") || strings.Contains(log.String(), "secret") {
		t.Fatalf("log: %s", log.String())
	}
	// never around the proxy: no connection at all
	if o.CustomDialer == nil {
		t.Fatal("no dialer: the agent would connect directly")
	}
	if _, err := o.CustomDialer.Dial("tcp", "nats.example:4222"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("dial: %v", err)
	}
}

func TestPumpTermOutput(t *testing.T) {
	collect := func(write func(w io.Writer)) []string {
		r, w := io.Pipe()
		var msgs []string
		done := make(chan error)
		go func() {
			done <- pumpTermOutput(r, func(b []byte) error { msgs = append(msgs, string(b)); return nil }, func() {})
		}()
		write(w)
		w.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return msgs
	}

	// small writes in quick succession go out together, a cut é is held
	msgs := collect(func(w io.Writer) {
		w.Write([]byte("ab"))
		w.Write([]byte("c\xc3"))
		w.Write([]byte("\xa9d"))
	})
	if strings.Join(msgs, "|") != "abcéd" {
		t.Fatalf("coalesced %q", msgs)
	}

	// a flood is split into messages of at most termMaxMsg, each valid UTF-8
	big := strings.Repeat("é", termMaxMsg)
	msgs = collect(func(w io.Writer) { io.WriteString(w, big) })
	if len(msgs) < 2 || strings.Join(msgs, "") != big {
		t.Fatalf("%d messages", len(msgs))
	}
	for _, m := range msgs {
		if len(m) > termMaxMsg || !utf8.ValidString(m) {
			t.Fatalf("message of %d bytes, valid %v", len(m), utf8.ValidString(m))
		}
	}

	// output past the rate waits
	oldRate, oldBurst := termRate, termBurst
	termRate, termBurst = 64<<10, 0
	defer func() { termRate, termBurst = oldRate, oldBurst }()
	start := time.Now()
	collect(func(w io.Writer) { io.WriteString(w, strings.Repeat("x", 32<<10)) })
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Fatalf("32 KiB at 64 KiB/s took %v", d)
	}

	// a failed publish ends the pump with that error
	r, w := io.Pipe()
	go w.Write([]byte("x"))
	errBoom := errors.New("boom")
	if err := pumpTermOutput(r, func([]byte) error { return errBoom }, func() {}); err != errBoom {
		t.Fatalf("publish error: %v", err)
	}
	w.Close()
}

func TestLogFileRotates(t *testing.T) {
	old := logMaxSize
	logMaxSize = 100
	defer func() { logMaxSize = old }()
	path := filepath.Join(t.TempDir(), "agent.log")
	opened := 0
	l, err := OpenLogFile(path, func(string) { opened++ })
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 39) + "\n"
	for i := 0; i < 20; i++ {
		l.Write([]byte(line))
	}
	for _, p := range []string{path, path + ".1", path + ".2"} {
		st, err := os.Stat(p)
		if err != nil || st.Size() > 100 || st.Size() == 0 {
			t.Fatalf("%s: %v %v", p, st, err)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", p, st.Mode().Perm())
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil || opened < 3 {
		t.Fatalf("more than two old logs kept, or created not called (%d)", opened)
	}
}

// a failed reopen falls back to stderr; stderr must survive the next
// rotation and the file comes back once it can be opened again
func TestLogFileStderrFallback(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLogFile(filepath.Join(dir, "agent.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "gone")
	l.path = filepath.Join(sub, "agent.log")
	l.rotate()
	if l.f != os.Stderr {
		t.Fatal("no stderr fallback")
	}
	l.rotate()
	if _, err := os.Stderr.Stat(); err != nil {
		t.Fatal("stderr closed:", err)
	}
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	l.Write([]byte("back\n"))
	defer l.f.Close()
	if b, err := os.ReadFile(l.path); err != nil || string(b) != "back\n" {
		t.Fatalf("log not reopened: %q %v", b, err)
	}
}
