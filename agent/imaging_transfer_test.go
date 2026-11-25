// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/nats-io/nats.go"
)

func TestImagingPollRPCCoalescesWakeRequests(t *testing.T) {
	req := rpcReq{a: &Agent{}, msg: &nats.Msg{}, p: &NatsMsg{Func: "imagingpoll"}}
	req.run()
	req.run()
	select {
	case <-imagingWake:
	default:
		t.Fatal("agent did not receive the poll request")
	}
	select {
	case <-imagingWake:
		t.Fatal("duplicate RPC queued another poll")
	default:
	}
}

func TestImagingFetchRetainsVerifiedFileIfAcknowledgmentFails(t *testing.T) {
	content := []byte("test restore material")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/data/") {
			_, _ = w.Write(content)
			return
		}
		http.Error(w, "grant expired", http.StatusForbidden)
	}))
	defer server.Close()
	transfer := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "disposable-test-token"}, client: server.Client()}
	path := filepath.Join(t.TempDir(), "verified")
	manifest := imagingManifest{Status: "verified", Size: int64(len(content)), Hash: fmt.Sprintf("%x", sha256.Sum256(content))}
	err := transfer.fetch(context.Background(), manifest, path)
	if err == nil || !strings.Contains(err.Error(), manifest.Hash) {
		t.Fatalf("missing receipt diagnostic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(content) {
		t.Fatalf("recovery artifact %q: %v", got, err)
	}
}

func TestImagingFetchPublishesOnlyAfterReadback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image")
	first := []byte("first")
	rest := []byte("second")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "0" {
			w.Write(first)
			return
		}
		if r.URL.Query().Has("offset") {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("final filename exists while transfer is incomplete: %v", err)
			}
			w.Write(rest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	transfer := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test-receipt"}, client: server.Client()}
	all := append(first, rest...)
	m := imagingManifest{Status: "verified", Size: int64(len(all)), Hash: fmt.Sprintf("%x", sha256.Sum256(all))}
	if err := transfer.fetch(context.Background(), m, path); err != nil {
		t.Fatal(err)
	}
	if err := transfer.fetch(context.Background(), m, path); !os.IsExist(err) {
		t.Fatalf("replaced existing output: %v", err)
	}
}

func TestImagingReconcilesSealWithServer(t *testing.T) {
	raw := "one source block"
	m := imagingManifest{Image: "point", Agent: "agent", Disk: "disk", Direction: "capture", Mode: "internet", Codec: "none", Status: "verifying", Hash: fmt.Sprintf("%x", sha256.Sum256([]byte(raw))), Offset: int64(len(raw)), Native: ImagingCapability{Method: "native"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seal/":
			http.Error(w, "simulated lost acknowledgment", http.StatusBadGateway)
		case "/":
			json.NewEncoder(w).Encode(m)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	tr := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test", Mode: "internet", Image: "point"}, client: server.Client()}
	if err := tr.upload(context.Background(), m, strings.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	m.Hash = strings.Repeat("0", 64)
	if err := tr.upload(context.Background(), m, strings.NewReader(raw)); err == nil {
		t.Fatal("accepted a different sealed hash")
	}
}

func TestImagingUploadRecoversLostBlockAnswers(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, imagingBlock), bytes.Repeat([]byte{2}, imagingBlock)
	raw := append(append(append(append([]byte{}, a...), b...), a...), "tail"...)
	m := imagingManifest{Image: "point", Agent: "agent", Disk: "disk", Direction: "capture", Mode: "internet", Codec: "gzip", Level: 1, Native: ImagingCapability{Method: "native"}}
	var mu sync.Mutex
	known := map[string]bool{}
	var offset int64
	var refused, lost bool
	var sealed []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		q := r.URL.Query()
		switch r.URL.Path {
		case "/":
			current := m
			current.Offset = offset
			json.NewEncoder(w).Encode(current)
		case "/begin/":
			offset = 0
			w.WriteHeader(http.StatusNoContent)
		case "/part/":
			size, _ := strconv.ParseInt(q.Get("size"), 10, 64)
			digest := q.Get("sha256")
			if q.Get("i") != fmt.Sprint(offset/imagingBlock) {
				w.WriteHeader(http.StatusConflict)
				return
			}
			if r.Method == "POST" && !known[digest] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == "PUT" {
				if !refused {
					refused = true
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				z, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				data, err := io.ReadAll(z)
				if err != nil || int64(len(data)) != size || fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
					t.Errorf("block %s: %d bytes, %v", q.Get("i"), len(data), err)
				}
				known[digest] = true
			}
			offset += size
			if q.Get("i") == "1" && !lost {
				lost = true
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/seal/":
			var seal struct {
				Size   int64
				SHA256 string
			}
			if json.NewDecoder(r.Body).Decode(&seal) != nil || seal.Size != offset {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sealed = append(sealed, seal.SHA256)
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()
	tr := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test", Mode: "internet", Image: "point"}, client: server.Client()}
	if err := tr.upload(context.Background(), m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(sealed) != 1 || sealed[0] != fmt.Sprintf("%x", sha256.Sum256(raw)) || offset != int64(len(raw)) || len(known) != 3 {
		t.Fatalf("sealed %v at %d with %d stored blocks", sealed, offset, len(known))
	}
	mu.Unlock()
	broken := errors.New("source read failed")
	if err := tr.upload(context.Background(), m, io.MultiReader(bytes.NewReader(a), iotest.ErrReader(broken))); !errors.Is(err, broken) {
		t.Fatalf("source error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sealed) != 1 {
		t.Fatal("sealed a capture whose source failed")
	}
}

func TestImagingFetchResumesInterruptedDownload(t *testing.T) {
	content := []byte("first--second-third--")
	var mu sync.Mutex
	interrupted, transient := true, true
	var offsets []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/data/" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		offsets = append(offsets, strconv.Itoa(offset))
		switch {
		case offset == 7 && transient:
			transient = false
			w.WriteHeader(http.StatusServiceUnavailable)
		case offset == 14 && interrupted:
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"detail": "Restore access expired."}`))
		default:
			w.Write(content[offset:min(offset+7, len(content))])
		}
	}))
	defer server.Close()
	tr := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test"}, client: server.Client()}
	path := filepath.Join(t.TempDir(), "image")
	m := imagingManifest{Status: "verified", Size: int64(len(content)), Hash: fmt.Sprintf("%x", sha256.Sum256(content))}
	// A refusal is not a network error: the operator needs the reason, not a retry.
	if err := tr.fetch(context.Background(), m, path); err == nil || !strings.Contains(err.Error(), "Restore access expired.") || strings.Contains(err.Error(), "same command") {
		t.Fatalf("refused download reported as %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("published an incomplete download: %v", err)
	}
	mu.Lock()
	interrupted, offsets = false, nil
	mu.Unlock()
	if err := tr.fetch(context.Background(), m, path); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(offsets, ",") != "14" {
		t.Fatalf("resumed at offsets %v", offsets)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("restored %q: %v", got, err)
	}
	if left, _ := filepath.Glob(path + ".*.partial"); len(left) != 0 {
		t.Fatalf("partial download left behind: %v", left)
	}
}

func TestImagingPriorFinished(t *testing.T) {
	for _, tc := range []struct {
		code   int
		status string
		done   bool
	}{{200, "verified", true}, {200, "failed", true}, {404, "", true}, {200, "waiting", false}, {200, "uploading", false}, {200, "verifying", false}} {
		if done, err := imagingPriorFinished(tc.code, tc.status); err != nil || done != tc.done {
			t.Errorf("%d %q: %v %v", tc.code, tc.status, done, err)
		}
	}
	if done, err := imagingPriorFinished(502, ""); err == nil || done {
		t.Error("cleared staging after a server error")
	}
}

func TestImagingBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{0: 5 * time.Minute, 1: 10 * time.Minute, 6: 320 * time.Minute, 7: 6 * time.Hour, 100: 6 * time.Hour} {
		if got := imagingBackoff(failures); got != want {
			t.Errorf("%d failures: %v, want %v", failures, got, want)
		}
	}
}

func TestAgentUpdateWaitsForNativeImaging(t *testing.T) {
	a := testUpdateAgent()
	imagingBusy.Store(true)
	a.rpcAgentUpdate(&rpcReq{a: a, msg: &nats.Msg{}, p: &NatsMsg{Func: "agentupdate", Data: payloadMap{
		"url": "https://rmm.example/a", "version": "2.26.10.2026", "inno": "setup.exe", "sha256": strings.Repeat("ab", 32)}}})
	imagingBusy.Store(false)
	if len(a.events) != 0 || updateRunning.Load() {
		t.Fatalf("update went ahead during a capture: %+v", a.events)
	}
	var mu sync.Mutex
	var polledBusy bool
	var released any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report map[string]any
		json.NewDecoder(r.Body).Decode(&report)
		mu.Lock()
		defer mu.Unlock()
		polledBusy = polledBusy || imagingBusy.Load()
		if report["failure"] != nil {
			released = report["claim"]
			w.WriteHeader(http.StatusNoContent)
			return
		}
		json.NewEncoder(w).Encode(imagingGrant{Claim: "claim", Image: "point"})
	}))
	defer server.Close()
	a.BaseURL, a.AgentID, a.rClient = "https://rmm.example", "agent", resty.New().SetBaseURL(server.URL)
	updateRunning.Store(true)
	defer updateRunning.Store(false)
	if err := a.imagingPoll(context.Background(), ImagingCapability{}); err == nil || !strings.Contains(err.Error(), "agent update") {
		t.Fatalf("capture started during an update: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if polledBusy || imagingBusy.Load() || released != "claim" {
		t.Fatalf("busy while polling %v, busy after %v, released claim %v", polledBusy, imagingBusy.Load(), released)
	}
}

type sealedSource struct{ io.Reader }

func (sealedSource) SealFields() map[string]any {
	return map[string]any{"index": map[string]int{"offset": 7, "size": 9}, "sha256": "not this"}
}

func TestImagingSealsLinuxFilesWithBlockListDigest(t *testing.T) {
	raw := append(append(bytes.Repeat([]byte{1}, imagingBlock), bytes.Repeat([]byte{2}, imagingBlock)...), "tail"...)
	var mu sync.Mutex
	var seal map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/part/" && r.Method == "POST":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/seal/":
			json.NewDecoder(r.Body).Decode(&seal)
			w.WriteHeader(http.StatusAccepted)
		default:
			// read the block like the server does; the client reuses its buffer
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	tr := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test", Mode: "internet", Image: "point"}, client: server.Client()}
	list := sha256.New()
	for i := 0; i < len(raw); i += imagingBlock {
		block := sha256.Sum256(raw[i:min(i+imagingBlock, len(raw))])
		list.Write(block[:])
	}
	for method, want := range map[string]string{linuxFilesMethod: fmt.Sprintf("%x", list.Sum(nil)), "linux-offline-disk-v1": fmt.Sprintf("%x", sha256.Sum256(raw))} {
		m := imagingManifest{Image: "point", Agent: "agent", Disk: "disk", Direction: "capture", Mode: "internet", Codec: "none", Native: ImagingCapability{Method: method}}
		if err := tr.upload(context.Background(), m, sealedSource{bytes.NewReader(raw)}); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		index, _ := seal["index"].(map[string]any)
		if seal["sha256"] != want || seal["size"] != float64(len(raw)) || index["offset"] != float64(7) {
			t.Fatalf("%s sealed %v", method, seal)
		}
		mu.Unlock()
	}
}

func TestImagingFetchRefusesLinuxFilesPoints(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fetch sent %s %s", r.Method, r.URL)
	}))
	defer server.Close()
	tr := imagingTransfer{grant: imagingGrant{URL: server.URL + "/", Token: "test"}, client: server.Client()}
	m := imagingManifest{Status: "verified", Size: 10, Hash: strings.Repeat("ab", 32), Native: ImagingCapability{Method: linuxFilesMethod}}
	path := filepath.Join(t.TempDir(), "disk")
	if err := tr.fetch(context.Background(), m, path); err == nil || err.Error() != "restore this point with the ULRMM recovery helper" {
		t.Fatalf("fetch of a files point: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("fetch created output")
	}
}

// blocks is a stream of n full blocks whose content repeats every three.
func blocks(n int) (io.Reader, [][]byte) {
	kinds := [][]byte{bytes.Repeat([]byte{0}, imagingBlock), bytes.Repeat([]byte{1}, imagingBlock), bytes.Repeat([]byte{2}, imagingBlock)}
	var parts []io.Reader
	for i := range n {
		parts = append(parts, bytes.NewReader(kinds[i%3]))
	}
	return io.MultiReader(parts...), kinds
}

func blockID(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

func TestPartsWindowUploadsFirstMissing(t *testing.T) {
	f := newRunFake(t)
	source, kinds := blocks(17)
	f.known[blockID(kinds[0])] = true
	tr := f.transfer()
	tr.run = bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	if err := tr.upload(context.Background(), f.manifest, source); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !reflect.DeepEqual(f.batches, []int{16, 14, 13, 1}) || !reflect.DeepEqual(f.puts, []string{"1", "2"}) || f.offset != 17*imagingBlock {
		t.Fatalf("batches %v, puts %v, offset %d", f.batches, f.puts, f.offset)
	}
	body, _ := tr.run.body(nil, false)
	c := body["counters"].(map[string]any)
	if c["blocks_read"] != int64(17) || c["blocks_new"] != int64(2) || c["bytes_read"] != int64(17*imagingBlock) || c["dedup_permille"] != int64(882) ||
		c["compression_permille"] != int64(1000) || !tr.run.sealed {
		t.Fatalf("counters %v, sealed %v", c, tr.run.sealed)
	}
	// without a run the single part requests stay
	f.batches, f.puts = nil, nil
	f.mu.Unlock()
	source, _ = blocks(2)
	err := f.transfer().upload(context.Background(), f.manifest, source)
	f.mu.Lock()
	if err != nil || len(f.batches) != 0 || !slices.Contains(f.requests, "POST /part/") {
		t.Fatalf("legacy upload: %v, batches %v", err, f.batches)
	}
}

func TestPartsOffset409ContinuesInWindow(t *testing.T) {
	f := newRunFake(t)
	source, kinds := blocks(17)
	for _, k := range kinds {
		f.known[blockID(k)] = true
	}
	f.loseParts = 1
	tr := f.transfer()
	tr.run = bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	if err := tr.upload(context.Background(), f.manifest, source); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.conflicts != 1 || !reflect.DeepEqual(f.batches, []int{16, 16, 1}) || f.offset != 17*imagingBlock {
		t.Fatalf("conflicts %d, batches %v, offset %d", f.conflicts, f.batches, f.offset)
	}
	// a lost answer on the window with the short last block: the offset is
	// no block multiple and still ends the window
	f.batches, f.conflicts, f.loseParts = nil, 0, 1
	f.known[blockID([]byte("tail"))] = true
	f.mu.Unlock()
	source, _ = blocks(1)
	if err := tr.upload(context.Background(), f.manifest, io.MultiReader(source, strings.NewReader("tail"))); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.conflicts != 1 || !reflect.DeepEqual(f.batches, []int{2, 2}) || f.offset != imagingBlock+4 {
		t.Fatalf("short last block: conflicts %d, batches %v, offset %d", f.conflicts, f.batches, f.offset)
	}
	f.conflictOffset = 3
	f.mu.Unlock()
	source, _ = blocks(2)
	err := tr.upload(context.Background(), f.manifest, source)
	if final := imagingFinalFor(err, "upload"); final == nil || final.Reason != "The server refused the upload: 409 Batch entries must continue at the committed block." {
		t.Fatalf("offset outside the window: %v", err)
	}
}

func TestPauseMaxZeroInterruptsAtOnce(t *testing.T) {
	f := newRunFake(t)
	f.failParts = 100
	tr := f.transfer()
	tr.run = bareRun(testUpdateAgent(), imagingClaim{Run: "r"})
	err := tr.upload(context.Background(), f.manifest, strings.NewReader("block"))
	f.mu.Lock()
	defer f.mu.Unlock()
	if final := imagingFinalFor(err, "upload"); final == nil || final.Status != "interrupted" || final.Reason != "The network was lost." || len(f.batches) != 5 {
		t.Fatalf("%v after %d tries", err, len(f.batches))
	}
}

func TestOpenImagingUsesTLSFor(t *testing.T) {
	a := testUpdateAgent()
	a.ApiURL, a.Proxy = "rmm.example", "http://proxy.example:3128"
	grant := imagingGrant{URL: "https://rmm.example/imaging/transfers/x/", Token: "t", Mode: "internet"}
	tr, err := openImaging(grant, "", a)
	if err != nil {
		t.Fatal(err)
	}
	h := tr.client.Transport.(*http.Transport)
	proxy, _ := h.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "rmm.example"}})
	if h.TLSClientConfig.GetClientCertificate == nil || h.TLSClientConfig.MinVersion != tls.VersionTLS13 || proxy == nil || proxy.Host != "proxy.example:3128" {
		t.Fatalf("RMM transfer: TLS %+v, proxy %v", h.TLSClientConfig, proxy)
	}
	grant.URL = "https://nas.example/imaging/transfers/x/"
	if tr, err = openImaging(grant, "", a); err != nil || tr.client.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate != nil {
		t.Fatalf("another host got the client certificate: %v", err)
	}
	a.Cert = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := openImaging(grant, "", a); err == nil || err.Error() != "invalid imaging CA bundle" {
		t.Fatalf("missing CA file: %v", err)
	}
}
