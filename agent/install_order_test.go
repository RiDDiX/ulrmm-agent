// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows
// +build !windows

package agent

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// An expired token keeps the earlier install; it goes once the server took
// the token, before the new agent is registered.
func TestInstallRemovesOldInstallAfterTokenCheck(t *testing.T) {
	old := removeExisting
	t.Cleanup(func() { removeExisting = old })
	var removed, removedFirst atomic.Bool
	removeExisting = func(*Agent, bool) { removed.Store(true) }

	var status atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/installer/":
			if r.Method == http.MethodGet {
				w.WriteHeader(int(status.Load()))
			}
		case "/api/v3/newagent/":
			removedFirst.Store(removed.Load())
			http.Error(w, "stop here", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	ca := writeCA(t, ts)
	install := func() (exited bool) {
		a := testUpdateAgent()
		a.Logger.ExitFunc = func(int) { exited = true }
		a.Install(&Installer{RMM: ts.URL, Cert: ca, NoMesh: true, Silent: true, Timeout: time.Minute})
		return exited
	}

	status.Store(http.StatusUnauthorized)
	if !install() || removed.Load() {
		t.Fatal("an expired token removed the old install")
	}
	status.Store(http.StatusOK)
	if !install() || !removedFirst.Load() {
		t.Fatal("the old install was not removed before newagent")
	}
}
