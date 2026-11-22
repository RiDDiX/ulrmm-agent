// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
