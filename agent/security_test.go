// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
)

func updateSig(k ed25519.PrivateKey, kv ...interface{}) string {
	c := map[string]interface{}{"v": 1, "typ": updateTyp, "agent": "agent-1", "url": "https://rmm.example/agentdist/a",
		"version": "1.26.10.2026", "sha256": strings.Repeat("ab", 32), "iat": time.Now().Unix()}
	for i := 0; i+1 < len(kv); i += 2 {
		c[kv[i].(string)] = kv[i+1]
	}
	return mintJWS(k, map[string]string{"alg": "EdDSA", "kid": testKid(k), "typ": updateTyp}, c)
}

func TestCheckUpdate(t *testing.T) {
	key := testEnrollKey(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	link, ver, sha := "https://rmm.example/agentdist/a", "1.26.10.2026", strings.Repeat("ab", 32)
	a := testUpdateAgent()
	a.AgentID, a.Version = "agent-1", "2.25.10.2026"
	for _, tc := range []struct {
		name, link, ver, sha, sig string
		noop                      bool
		err                       string
	}{
		{"valid", link, ver, sha, updateSig(key), false, ""},
		{"no signature", link, ver, sha, "", false, "unsigned"},
		{"other key", link, ver, sha, updateSig(other), false, "another key"},
		{"pin document as signature", link, ver, sha, pinDoc(key, link, 1, "x"), false, "type"},
		{"other url", link + "x", ver, sha, updateSig(key), false, "does not cover"},
		{"other version", link, "2.26.10.2026", sha, updateSig(key), false, "does not cover"},
		{"other sha256", link, ver, strings.Repeat("cd", 32), updateSig(key), false, "does not cover"},
		{"other agent", link, ver, sha, updateSig(key, "agent", "agent-2"), false, "another agent"},
		{"no sha256", link, ver, "", updateSig(key, "sha256", ""), false, "no valid sha256"},
		{"short sha256", link, ver, "abcd", updateSig(key, "sha256", "abcd"), false, "no valid sha256"},
		{"http", "http://rmm.example/a", ver, sha, updateSig(key, "url", "http://rmm.example/a"), false, "not https"},
		{"downgrade", link, "1.24.10.2026", sha, updateSig(key, "version", "1.24.10.2026"), false, "downgrade"},
		{"same version", link, "2.25.10.2026", sha, updateSig(key, "version", "2.25.10.2026"), true, ""},
		{"no version", link, "latest", sha, updateSig(key, "version", "latest"), false, "cannot be compared"},
	} {
		noop, err := a.checkUpdate(tc.link, tc.ver, tc.sha, tc.sig)
		if tc.err == "" && (err != nil || noop != tc.noop) {
			t.Errorf("%s: noop %v, %v", tc.name, noop, err)
		}
		if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.err, err)
		}
	}
	// a build without the key cannot check signatures and takes no update
	BrandEnrollPubKey = ""
	for _, sig := range []string{"", updateSig(key)} {
		if _, err := a.checkUpdate(link, ver, sha, sig); err == nil || !strings.Contains(err.Error(), "unsigned") {
			t.Fatalf("no key, sig %q: %v", sig, err)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2.25.10.2026", "1.25.10.2026", 1},
		{"1.26.10.2026", "9.25.10.2026", 1},
		{"1.01.11.2026", "3.31.10.2026", 1},
		{"1.1.1.2027", "5.31.12.2026", 1},
		{"v2.25.10.2026", "2.25.10.2026", 0},
		{"1.25.10.2026", "2.25.10.2026", -1},
	} {
		if got, ok := compareVersions(tc.a, tc.b); !ok || got != tc.want {
			t.Errorf("%s vs %s: %d %v", tc.a, tc.b, got, ok)
		}
	}
	if _, ok := compareVersions("2.8.0", "2.25.10.2026"); ok {
		t.Error("a version of another format compared")
	}
}

// A refused agentupdate is reported and leaves the next update possible.
func TestAgentUpdateRefusedIsReported(t *testing.T) {
	testEnrollKey(t)
	a := testUpdateAgent()
	a.AgentID, a.Version = "agent-1", "2.25.10.2026"
	r := &rpcReq{a: a, msg: &nats.Msg{}, p: &NatsMsg{Func: "agentupdate", Data: payloadMap{
		"url": "https://rmm.example/a", "version": "2.26.10.2026", "inno": "setup.exe", "sha256": strings.Repeat("ab", 32)}}}
	a.rpcAgentUpdate(r)
	if updateRunning.Load() {
		t.Fatal("update still marked running")
	}
	if len(a.events) != 1 || a.events[0].Kind != "update_refused" || !strings.HasPrefix(a.events[0].Detail, "unsigned") {
		t.Fatalf("events %+v", a.events)
	}
}

// A copy of the test binary run with -version is the stand-in for a
// downloaded agent of another version: a host binary such as /bin/echo
// stops working under another name on multi-call systems.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "-version" {
		fmt.Println("-version")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A download that is not the file the server signed is refused and
// reported, one that fails on the way is only logged.
func TestAgentUpdateBadDownloadReported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the update runs the downloaded ELF")
	}
	key := testEnrollKey(t)
	// the test binary itself answers -version with -version, see TestMain
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	flipped := append([]byte{}, body...)
	flipped[len(flipped)/2] ^= 1
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flipped":
			w.Write(flipped)
		case "/signed":
			w.Write(body)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer ts.Close()
	a := testUpdateAgent()
	a.AgentID, a.Version, a.Cert = "agent-1", "2.25.10.2026", writeCA(t, ts)
	for _, tc := range []struct{ path, want string }{
		{"/flipped", "sha256 of the download is"},
		{"/signed", `the downloaded agent is version "-version", the server announced "2.26.10.2026"`},
		{"/down", ""},
	} {
		link := ts.URL + tc.path
		a.events = nil
		a.rpcAgentUpdate(&rpcReq{a: a, msg: &nats.Msg{}, p: &NatsMsg{Func: "agentupdate", Data: payloadMap{
			"url": link, "version": "2.26.10.2026", "sha256": sha,
			"sig": updateSig(key, "url", link, "version", "2.26.10.2026", "sha256", sha)}}})
		if updateRunning.Load() {
			t.Fatalf("%s: update still marked running", tc.path)
		}
		if tc.want == "" && len(a.events) != 0 {
			t.Fatalf("%s: a failed download was reported: %+v", tc.path, a.events)
		}
		if tc.want != "" && (len(a.events) != 1 || a.events[0].Kind != "update_refused" || !strings.Contains(a.events[0].Detail, tc.want)) {
			t.Fatalf("%s: events %+v", tc.path, a.events)
		}
	}
}

func TestSecurityEventQueue(t *testing.T) {
	a := testUpdateAgent()
	a.queueSecurityEvent("pin_mismatch", "a")
	a.queueSecurityEvent("pin_mismatch", "a")
	if len(a.events) != 1 {
		t.Fatalf("duplicate queued: %+v", a.events)
	}
	for i := 0; i < maxSecurityEvents+5; i++ {
		a.queueSecurityEvent("tls_failure", fmt.Sprint(i))
	}
	if len(a.events) != maxSecurityEvents || a.events[0].Detail != "5" {
		t.Fatalf("queue %d, first %+v", len(a.events), a.events[0])
	}
	a.queueSecurityEvent("tls_failure", strings.Repeat("ä", maxEventDetail))
	if d := a.events[len(a.events)-1].Detail; len(d) > maxEventDetail || !strings.HasPrefix(d, "ää") || strings.ToValidUTF8(d, "") != d {
		t.Fatalf("long detail: %d bytes", len(d))
	}
}

// Events go out after a REST answer got through; a 400 drops one, a 5xx
// keeps the rest.
func TestSecurityEventsSent(t *testing.T) {
	var mu sync.Mutex
	var got []securityEvent
	status := map[string]int{"bad": 400, "later": 503}
	a := apiAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/agent1/security-event/" {
			w.Write([]byte("{}"))
			return
		}
		var ev securityEvent
		json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		if s := status[ev.Detail]; s != 0 {
			w.WriteHeader(s)
		}
	})
	for _, d := range []string{"one", "bad", "two", "later", "three"} {
		a.queueSecurityEvent("pin_mismatch", d)
	}
	a.rClient.R().Get("/api/v3/agent1/config/")
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 4 && !a.sendingEvents.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sent %d", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// the next answer within the retry period sends nothing
	a.rClient.R().Get("/api/v3/agent1/config/")
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	a.eventsMu.Lock()
	defer a.eventsMu.Unlock()
	if len(got) != 4 || len(a.events) != 2 || a.events[0].Detail != "later" || got[0].Kind != "pin_mismatch" {
		t.Fatalf("left %+v, sent %+v", a.events, got)
	}
}

func TestEnvDenied(t *testing.T) {
	for _, n := range []string{"LD_PRELOAD", "dyld_insert_libraries", "PYTHONPATH", "PSModulePath", "DENO_DIR", "COR_PROFILER_PATH",
		"DOTNET_STARTUP_HOOKS", "PATH", "Path", "BASH_ENV", "ENV", "HOME", "NODE_OPTIONS", "SystemRoot", "PERL5OPT", "PERL5LIB",
		"PERLLIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "OPENSSL_CONF", "OPENSSL_MODULES",
		"GCONV_PATH", "XDG_CONFIG_HOME", "xdg_data_home", "GIT_SSH_COMMAND", "SSLKEYLOGFILE", "LocalAppData"} {
		if !envDenied.MatchString(n) {
			t.Errorf("%s allowed", n)
		}
	}
	for _, n := range []string{"MY_PATH", "PATHS", "SITE", "HOMEDIR", "XDG_RUNTIME_DIR", "GIT_DIR", "RUBY", "PERL", "OPENSSL_X", "JAVA_HOME"} {
		if envDenied.MatchString(n) {
			t.Errorf("%s denied", n)
		}
	}
	var log strings.Builder
	a := testUpdateAgent()
	a.Logger.SetOutput(&log)
	if got := a.dropDeniedEnv([]string{"A=1", "LD_PRELOAD=/tmp/evil.so", "B=x=y"}); strings.Join(got, " ") != "A=1 B=x=y" {
		t.Fatalf("kept %v", got)
	}
	if !strings.Contains(log.String(), "LD_PRELOAD") || strings.Contains(log.String(), "evil") {
		t.Fatalf("log: %s", log.String())
	}
}

// fakeNats accepts one client and hands every PUB line it sends to pubs.
func fakeNats(t *testing.T, pubs chan<- string) string {
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
		io.WriteString(c, `INFO {"server_id":"t","version":"2.10.0","proto":1,"max_payload":1048576,"headers":true}`+"\r\n")
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "PING"):
				io.WriteString(c, "PONG\r\n")
			case strings.HasPrefix(line, "PUB "):
				var n int
				f := strings.Fields(line)
				fmt.Sscan(f[len(f)-1], &n)
				io.CopyN(io.Discard, r, int64(n)+2)
				pubs <- strings.Join(f[:len(f)-1], " ")
			}
		}
	}()
	return "nats://" + l.Addr().String()
}

func TestCheckinSubject(t *testing.T) {
	pubs := make(chan string, 4)
	nc, err := nats.Connect(fakeNats(t, pubs))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	a := testUpdateAgent()
	a.AgentID, a.Version = "agent-1", "2.25.10.2026"
	a.NatsMessage(nc, "agent-hello")
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := <-pubs; got != "PUB agent-1.checkin agent-hello" {
		t.Fatalf("published %q", got)
	}
}

func TestReadAuthFileRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "token")
	if err := os.WriteFile(target, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here:", err)
	}
	if _, err := ReadAuthFile(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("link: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("the link target was removed")
	}
	if _, err := ReadAuthFile(dir); err == nil {
		t.Fatal("a directory was read")
	}
}
