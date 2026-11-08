// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

// cutServe answers data from the asked offset and breaks the connection
// after chunk bytes.
func cutServe(w http.ResponseWriter, r *http.Request, data []byte, chunk int) {
	var start int
	fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &start)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)-start))
	if start > 0 {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
		w.WriteHeader(http.StatusPartialContent)
	}
	end := min(start+chunk, len(data))
	w.Write(data[start:end])
	if end < len(data) {
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
}

// A download that moves on with every try is not given up after pkgTries.
func TestPkgDownloadKeepsGoingWhileItAdvances(t *testing.T) {
	fastPkg(t)
	body := randBytes(t, 10000)
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		cutServe(w, r, body, 1000)
	}))
	defer srv.Close()
	a := pkgTestAgent(t, &pkgAPI{})
	dest := filepath.Join(t.TempDir(), "setup.bin")
	if err := a.pkgDownload(pkgTestJob, pkgTestPlan(srv.URL+"/dl/a", body), dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, body) || hits.Load() <= pkgTries {
		t.Fatalf("download differs or took %d tries", hits.Load())
	}
}

// The same for a driver pack: every try verifies at least one more piece.
func TestSdioDownloadKeepsGoingWhileItVerifies(t *testing.T) {
	fastSdio(t)
	const plen = 16384
	files := []sdioTestFile{{"a.7z", randBytes(t, 1000)}, {"p.7z", randBytes(t, 100000)}}
	m := newSdioMirror(t, files)
	p := sdioLayout(m.URL, files, 1, plen)
	m.hook = func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path != "/p.7z" {
			return false
		}
		cutServe(w, r, files[1].data, plen+100)
		return true
	}
	got, err := sdioFetch(t, sdioTestAgent(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, files[1].data) || m.count("p.7z") <= 3 {
		t.Fatalf("pack differs or took %d tries", m.count("p.7z"))
	}
}
