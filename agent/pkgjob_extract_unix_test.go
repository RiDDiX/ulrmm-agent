// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package agent

import (
	"testing"
	"time"
)

// A panic in the unpack must not leave the "extracting" reports running
// after the failed result.
func TestPkgExtractPanicStopsTheBeat(t *testing.T) {
	fastPkg(t)
	every, extract := pkgBeatEvery, pkgExtract
	t.Cleanup(func() { pkgBeatEvery, pkgExtract = every, extract })
	pkgBeatEvery = 10 * time.Millisecond
	pkgExtract = func(string, string, string, int64) error { panic("broken archive") }
	body := []byte("archive bytes")
	srv := newPkgServer(t, body)
	api := &pkgAPI{plan: func(int) *pkgPlan {
		p := pkgTestPlan(srv.URL+"/packages/download/t1/", body)
		p.Filename, p.Extract = "app.7z", "7z"
		return p
	}}
	a := pkgTestAgent(t, api)
	a.UnixTmpDir = t.TempDir()
	a.runPkgJob(pkgTestJob)

	patches, _ := api.got()
	if last := patches[len(patches)-1]; last["state"] != "failed" {
		t.Fatalf("patches %v", patches)
	}
	time.Sleep(80 * time.Millisecond)
	if after, _ := api.got(); len(after) != len(patches) {
		t.Fatalf("reports after the result: %v", after[len(patches):])
	}
}

func TestPkgExtractLimit(t *testing.T) {
	// 3 GiB free before a 1 GiB download: 2 GiB left, 512 MiB of it kept
	if got := pkgExtractLimit(3<<30, 1<<30); got != 1536<<20 {
		t.Fatalf("limit %d", got)
	}
	if got := pkgExtractLimit(1<<50, 1<<20); got != pkgExtractMax {
		t.Fatalf("limit %d on a large disk", got)
	}
}
