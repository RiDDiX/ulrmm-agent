// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/bodgit/sevenzip"
)

// Package jobs: the server sends a job id, the agent fetches the plan,
// downloads the package from the RMM server (resuming after breaks),
// unpacks archives and runs the install script or command. One job at a
// time.

const (
	pkgJobURL     = "/api/v4/%s/pkgjob/%s/"
	pkgOutputMax  = 64 << 10
	pkgExtractMax = int64(64) << 30
	pkgSizeMax    = int64(1) << 40
	pkgTries      = 5
)

var (
	pkgMu     sync.Mutex
	pkgJobRe  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	pkgDirRe  = regexp.MustCompile(`^pkg-[0-9]+$`)
	pkgNameRe = regexp.MustCompile(`^[^/\\:*?"<>|\x00-\x1f]{1,200}$`)
	pkgEnvRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// first pause between download tries, doubled after each; tests shorten it
	pkgRetryWait = 5 * time.Second
)

type pkgRun struct {
	Type    string            `json:"type"`
	Shell   string            `json:"shell"`
	Body    string            `json:"body"`
	Env     map[string]string `json:"env"`
	Exe     string            `json:"exe"`
	Args    string            `json:"args"`
	Argv    []string          `json:"argv"`
	Timeout int               `json:"timeout"`
}

type pkgPlan struct {
	Job          int64   `json:"job"`
	URL          string  `json:"url"`
	Sha256       string  `json:"sha256"`
	Size         int64   `json:"size"`
	Filename     string  `json:"filename"`
	Extract      string  `json:"extract"`
	Run          pkgRun  `json:"run"`
	SuccessCodes []int64 `json:"success_codes"`
	RebootCodes  []int64 `json:"reboot_codes"`
	// seconds for the download, 0 lets the agent work it out
	Deadline int `json:"deadline"`
}

// deadline allows 64 KiB/s plus the run timeout, at most a day, when the
// plan has none.
func (p *pkgPlan) deadline() int {
	if p.Deadline > 0 {
		return p.Deadline
	}
	if s := p.Size/(64<<10) + int64(p.Run.Timeout); s < 86400 {
		return int(s)
	}
	return 86400
}

type pkgResult struct {
	State    string `json:"state"`
	ExitCode *int64 `json:"exit_code"`
	Output   string `json:"output"`
	Detail   string `json:"detail"`
}

// pkgAnswer is the reply to pkgjob. On "ok" pkgMu is held and the caller
// runs the job and unlocks.
func pkgAnswer(job string) string {
	switch {
	case !pkgJobRe.MatchString(job):
		return "invalid job id"
	case !pkgMu.TryLock():
		return "busy"
	}
	return "ok"
}

func (p *pkgPlan) check(job string) error {
	u, err := url.Parse(p.URL)
	p.Sha256 = strings.ToLower(p.Sha256)
	sum, herr := hex.DecodeString(p.Sha256)
	switch {
	case strconv.FormatInt(p.Job, 10) != job:
		return errors.New("the plan is for another job")
	case err != nil || u.Scheme != "https" || u.Host == "":
		return errors.New("the plan has no https download link")
	case herr != nil || len(sum) != sha256.Size:
		return errors.New("the plan has no valid sha256")
	case p.Size <= 0 || p.Size > pkgSizeMax:
		return fmt.Errorf("the plan has a file size of %d bytes", p.Size)
	case !pkgNameRe.MatchString(p.Filename) || p.Filename == "." || p.Filename == "..":
		return fmt.Errorf("invalid file name %q", p.Filename)
	case p.Extract != "none" && p.Extract != "zip" && p.Extract != "7z" && p.Extract != "tar.gz":
		return fmt.Errorf("unknown archive type %q", p.Extract)
	case p.Extract != "none" && strings.EqualFold(p.Filename, "files"):
		return errors.New("the file name is the name of the extract folder")
	case p.Run.Timeout <= 0 || p.Run.Timeout > 86400:
		return fmt.Errorf("the plan has a run timeout of %d s", p.Run.Timeout)
	case p.Deadline < 0 || p.Deadline > 86400:
		return fmt.Errorf("the plan has a deadline of %d s", p.Deadline)
	}
	switch p.Run.Type {
	case "script":
		if p.Run.Shell != pkgShell || p.Run.Body == "" {
			return fmt.Errorf("the plan has no %s script", pkgShell)
		}
		for k := range p.Run.Env {
			if !pkgEnvRe.MatchString(k) {
				return fmt.Errorf("invalid environment name %q", k)
			}
		}
	case "command":
		if p.Run.Exe == "" {
			return errors.New("the plan names no program")
		}
		// each OS reads only its own form of the arguments
		if runtime.GOOS == "windows" && p.Run.Args == "" && len(p.Run.Argv) > 0 ||
			runtime.GOOS != "windows" && len(p.Run.Argv) == 0 && p.Run.Args != "" {
			return fmt.Errorf("the plan has no arguments for %s", runtime.GOOS)
		}
	default:
		return fmt.Errorf("unknown run type %q", p.Run.Type)
	}
	if len(p.SuccessCodes) == 0 {
		p.SuccessCodes = []int64{0}
	}
	return nil
}

// archives need room for the file and for what it unpacks to
func pkgSpace(free uint64, p *pkgPlan) error {
	factor := 1.1
	if p.Extract != "none" {
		factor = 2.2
	}
	need := uint64(float64(p.Size)*factor) + 512<<20
	if free < need {
		return fmt.Errorf("not enough disk space: need %s, free %s", ByteCountSI(need), ByteCountSI(free))
	}
	return nil
}

// pkgFatal: another download try would not help.
type pkgFatal struct{ error }

// pkgFile is the download as it is written: the bytes so far and their hash.
type pkgFile struct {
	f        *os.File
	h        hash.Hash
	pos      int64
	size     int64
	progress func(int64)
}

// openPkgFile opens dest and hashes what an earlier try left in it.
func openPkgFile(dest string, size int64) (*pkgFile, error) {
	f, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	w := &pkgFile{f: f, h: sha256.New(), size: size}
	if w.pos, err = io.Copy(w.h, f); err == nil && w.pos > size {
		err = w.restart()
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

func (w *pkgFile) Write(b []byte) (int, error) {
	if w.pos+int64(len(b)) > w.size {
		return 0, pkgFatal{errors.New("the download is larger than the plan says")}
	}
	n, err := w.f.Write(b)
	w.h.Write(b[:n])
	w.pos += int64(n)
	if err != nil {
		return n, pkgFatal{err}
	}
	if w.progress != nil {
		w.progress(w.pos)
	}
	return n, nil
}

// restart drops what was downloaded so far.
func (w *pkgFile) restart() error {
	w.pos = 0
	w.h.Reset()
	if err := w.f.Truncate(0); err != nil {
		return pkgFatal{err}
	}
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return pkgFatal{err}
	}
	return nil
}

// Downloads come from the RMM server: the client of fetchFile, but no
// overall timeout (a stall ends a try instead).
func (a *Agent) pkgClient(link string) (*http.Client, error) {
	return a.httpClient(link, 0)
}

// pkgGet asks for the bytes w does not have yet and appends them. The
// status is the server's answer, 0 when there was none.
func (a *Agent) pkgGet(ctx context.Context, c *http.Client, link string, w *pkgFile) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	t := time.AfterFunc(sdioStall, func() { stalled.Store(true); cancel() })
	defer t.Stop()
	stall := func(err error) error {
		if err != nil && stalled.Load() {
			return fmt.Errorf("no data from the server for %s", sdioStall)
		}
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return 0, errors.New("the download link cannot be used")
	}
	req.Header.Set("User-Agent", a.AgentHeader)
	if w.pos > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", w.pos))
	}
	resp, err := c.Do(req)
	if err != nil {
		// the link holds a download token
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, stall(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusPartialContent && w.pos > 0:
		if !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-", w.pos)) {
			return resp.StatusCode, errors.New("the server sent another range than asked for")
		}
	case resp.StatusCode == http.StatusOK:
		// the whole file again
		if err := w.restart(); err != nil {
			return resp.StatusCode, err
		}
	default:
		return resp.StatusCode, fmt.Errorf("the server answered %d", resp.StatusCode)
	}
	_, err = io.Copy(w, &stallReader{r: resp.Body, t: t})
	if err == nil && w.pos < w.size {
		err = fmt.Errorf("the download ended after %d of %d bytes", w.pos, w.size)
	}
	return resp.StatusCode, stall(err)
}

// pkgDownload fetches the plan's file to dest and checks its size and
// sha256. A break resumes where the file ends, five tries counted from the
// last one that brought new data, within the job's deadline; a link the
// server refuses (401, 403, 404, 410) is replaced from a new plan.
func (a *Agent) pkgDownload(job string, plan *pkgPlan, dest string) error {
	c, err := a.pkgClient(plan.URL)
	if err != nil {
		return err
	}
	w, err := openPkgFile(dest, plan.Size)
	if err != nil {
		return err
	}
	defer w.f.Close()
	m := a.newPkgMeter(job, w.pos, plan.Size)
	w.progress = m.report
	defer m.stop()

	secs := plan.deadline()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	late := fmt.Errorf("the job did not finish within %d s", secs)

	link, wait := plan.URL, pkgRetryWait
	for try := 1; w.pos < plan.Size; try++ {
		from := w.pos
		code, err := a.pkgGet(ctx, c, link, w)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return late
		}
		// a try that brought new data starts the count again
		if w.pos > from {
			try, wait = 1, pkgRetryWait
		}
		var fatal pkgFatal
		if try == pkgTries || errors.As(err, &fatal) {
			return err
		}
		a.Logger.Debugln("pkgjob:", job, "try", try, "stopped at", w.pos, err)
		select {
		case <-ctx.Done():
			return late
		case <-time.After(wait):
		}
		wait *= 2
		switch code {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
			fresh, err := a.pkgPlan(job)
			if err != nil {
				a.Logger.Debugln("pkgjob:", err)
				continue
			}
			if fresh.Sha256 != plan.Sha256 || fresh.Size != plan.Size {
				return errors.New("the package changed during the download")
			}
			link = fresh.URL
		}
	}
	if got := hex.EncodeToString(w.h.Sum(nil)); got != plan.Sha256 {
		return fmt.Errorf("sha256 of the download is %s, the plan expects %s", got, plan.Sha256)
	}
	return w.f.Close()
}

// pkgUnpack writes archive members below dest: plain files and folders
// only, paths that stay inside, at most limit bytes in all.
type pkgUnpack struct {
	dest        string
	room, limit int64
}

func (x *pkgUnpack) add(name string, mode fs.FileMode, size int64, open func() (io.ReadCloser, error)) error {
	rel := strings.ReplaceAll(name, `\`, "/")
	if err := sdioPathOK(rel); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	target, err := safeJoin(x.dest, filepath.FromSlash(path.Clean(rel)))
	if err != nil {
		return err
	}
	switch mode.Type() {
	case fs.ModeDir:
		return os.MkdirAll(target, 0o700)
	case 0:
	default:
		return fmt.Errorf("%s is a link or a special file", name)
	}
	tooBig := fmt.Errorf("the archive unpacks to more than %s", ByteCountSI(uint64(x.limit)))
	if size > x.room {
		return tooBig
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	r, err := open()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer r.Close()
	perm := fs.FileMode(0o600)
	if mode.Perm()&0o111 != 0 {
		perm = 0o700
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, x.room+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if x.room -= n; err == nil && x.room < 0 {
		err = tooBig
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// pkgExtract unpacks a zip, 7z or tar.gz archive into the new folder dest.
func pkgExtract(kind, archive, dest string, limit int64) error {
	if err := os.Mkdir(dest, 0o700); err != nil {
		return err
	}
	x := &pkgUnpack{dest: dest, room: limit, limit: limit}
	switch kind {
	case "zip":
		z, err := zip.OpenReader(archive)
		if err != nil {
			return err
		}
		defer z.Close()
		for _, f := range z.File {
			if err := x.add(f.Name, f.Mode(), int64(f.UncompressedSize64), f.Open); err != nil {
				return err
			}
		}
	case "7z":
		z, err := sevenzip.OpenReader(archive)
		if err != nil {
			return err
		}
		defer z.Close()
		for _, f := range z.File {
			mode := f.Mode()
			if f.Attributes&0x400 != 0 {
				// reparse point
				mode = fs.ModeSymlink
			}
			if err := x.add(f.Name, mode, int64(f.UncompressedSize), f.Open); err != nil {
				return err
			}
		}
	case "tar.gz":
		f, err := os.Open(archive)
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		tr := tar.NewReader(gz)
		open := func() (io.ReadCloser, error) { return io.NopCloser(tr), nil }
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			// FileInfo would pass hard links as plain files
			mode := fs.ModeIrregular
			switch hdr.Typeflag {
			case tar.TypeReg:
				mode = fs.FileMode(hdr.Mode).Perm()
			case tar.TypeDir:
				mode = fs.ModeDir
			case tar.TypeXGlobalHeader:
				continue
			}
			if err := x.add(hdr.Name, mode, hdr.Size, open); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown archive type %q", kind)
	}
	return nil
}

// pkgExe finds the program of a command: a file of the package (a relative
// path that stays inside dir) or a system program named without a path.
func pkgExe(dir, exe string) (string, error) {
	if p, ok := pkgSystemExe(exe); ok {
		if p == "" || !rmm.FileExists(p) {
			return "", fmt.Errorf("%s is not installed", exe)
		}
		return p, nil
	}
	rel := strings.ReplaceAll(exe, `\`, "/")
	if err := sdioPathOK(rel); err != nil {
		return "", fmt.Errorf("program %q: %w", exe, err)
	}
	p, err := safeJoin(dir, filepath.FromSlash(rel))
	if err != nil {
		return "", err
	}
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("program %q is not a file of the package", exe)
	}
	// unix runs it only with the exec bit
	return p, os.Chmod(p, 0o700)
}

// pkgTail keeps the last max bytes written to it.
type pkgTail struct {
	b   []byte
	max int
}

func (t *pkgTail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

// exit codes compare as Windows sees them
func pkgCodeIn(code int64, codes []int64) bool {
	for _, c := range codes {
		if uint32(c) == uint32(code) {
			return true
		}
	}
	return false
}

// pkgInstall runs the plan's script or command. PKG_FILE is the download,
// PKG_DIR the folder with the package's files (the command runs there).
func (a *Agent) pkgInstall(p *pkgPlan, file, dir string) pkgResult {
	env := []string{"PKG_FILE=" + file, "PKG_DIR=" + dir}
	timedOut := fmt.Sprintf("the installer did not finish within %d s", p.Run.Timeout)
	var code int64
	var out string
	if p.Run.Type == "script" {
		vars := make([]string, 0, len(p.Run.Env)+len(env))
		for k, v := range p.Run.Env {
			vars = append(vars, k+"="+v)
		}
		start := time.Now()
		stdout, stderr, c, err := a.RunScript(p.Run.Body, p.Run.Shell, nil, p.Run.Timeout, false, append(vars, env...), false, "")
		// stdout last: its final line holds the script's result
		out = outputTail(strings.TrimSpace(stderr+"\n"+stdout), pkgOutputMax)
		switch {
		case err != nil:
			return pkgResult{State: "failed", Output: out, Detail: sdioCut(err.Error(), sdioDetailMax)}
		case c == cmdTimeoutExit && time.Since(start) >= time.Duration(p.Run.Timeout)*time.Second:
			return pkgResult{State: "failed", Output: out, Detail: timedOut}
		}
		code = pkgExit(c)
	} else {
		exe, err := pkgExe(dir, p.Run.Exe)
		if err != nil {
			return pkgResult{State: "failed", Detail: sdioCut(err.Error(), sdioDetailMax)}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.Run.Timeout)*time.Second)
		defer cancel()
		tail := &pkgTail{max: pkgOutputMax}
		c, late, err := a.pkgCommand(ctx, exe, &p.Run, dir, env, tail)
		out = outputTail(CleanString(string(tail.b)), pkgOutputMax)
		switch {
		case late:
			return pkgResult{State: "failed", Output: out, Detail: timedOut}
		case err != nil:
			return pkgResult{State: "failed", Output: out, Detail: sdioCut(err.Error(), sdioDetailMax)}
		}
		code = pkgExit(c)
	}
	res := pkgResult{State: "done", ExitCode: &code, Output: out}
	if !pkgCodeIn(code, p.SuccessCodes) && !pkgCodeIn(code, p.RebootCodes) {
		res.State, res.Detail = "failed", fmt.Sprintf("exit code %d", code)
	}
	return res
}

// status code and error; 0 when the server was not reached
func (a *Agent) pkgPatch(ctx context.Context, job string, body interface{}) (int, error) {
	r, err := a.rClient.R().SetContext(ctx).SetBody(body).Patch(fmt.Sprintf(pkgJobURL, a.AgentID, job))
	if err != nil {
		return 0, err
	}
	if r.IsError() {
		return r.StatusCode(), fmt.Errorf("server answered %d", r.StatusCode())
	}
	return r.StatusCode(), nil
}

// patchWithRetry sends a final result: four tries, wait apart, none more
// after a 4xx.
func (a *Agent) patchWithRetry(path string, body interface{}, wait time.Duration) error {
	for try := 1; ; try++ {
		code := 0
		r, err := a.rClient.R().SetBody(body).Patch(path)
		if err == nil {
			if code = r.StatusCode(); r.IsError() {
				err = fmt.Errorf("server answered %d", code)
			}
		}
		if err == nil || try == 4 || (code >= 400 && code < 500) {
			return err
		}
		a.Logger.Debugln("PATCH", path, err)
		time.Sleep(wait)
	}
}

func (a *Agent) pkgProgress(job, state string, done, total int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.pkgPatch(ctx, job, map[string]interface{}{"state": state, "done": done, "total": total}); err != nil {
		a.Logger.Debugln("pkgjob progress:", err)
	}
}

// newPkgMeter sends done at once, then whatever report passes on, from its
// own goroutine (see sdioMeter).
func (a *Agent) newPkgMeter(job string, done, total int64) *sdioMeter {
	m := &sdioMeter{ch: make(chan int64), quit: make(chan struct{}), last: time.Now()}
	go func() {
		defer close(m.quit)
		a.pkgProgress(job, "downloading", done, total)
		for d := range m.ch {
			a.pkgProgress(job, "downloading", d, total)
		}
	}()
	return m
}

func (a *Agent) pkgPlan(job string) (*pkgPlan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := a.rClient.R().SetContext(ctx).Get(fmt.Sprintf(pkgJobURL, a.AgentID, job))
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the plan: %w", err)
	}
	if r.IsError() {
		return nil, fmt.Errorf("cannot fetch the plan: server answered %d", r.StatusCode())
	}
	var p pkgPlan
	if err := json.Unmarshal(r.Body(), &p); err != nil {
		return nil, fmt.Errorf("cannot read the plan: %w", err)
	}
	return &p, p.check(job)
}

// pkgRemoveStale removes the work dirs earlier jobs left in root.
func (a *Agent) pkgRemoveStale(root string) {
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		if !pkgDirRe.MatchString(e.Name()) || ownDir(p) != nil {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			a.Logger.Debugln("pkgjob: leftover", p, err)
		}
	}
}

// pkgCleanup runs at service start; a job that already runs has cleaned up.
func (a *Agent) pkgCleanup() {
	if !pkgMu.TryLock() {
		return
	}
	defer pkgMu.Unlock()
	if root, err := a.pkgRoot(); err == nil {
		a.pkgRemoveStale(root)
	}
}

// runPkgJob runs one job, sends the result and removes the work dir; the
// caller holds pkgMu.
func (a *Agent) runPkgJob(job string) {
	var work string
	res := func() (res pkgResult) {
		defer func() {
			if v := recover(); v != nil {
				a.Logger.Errorf("pkgjob: recovered from panic: %v\n%s", v, debug.Stack())
				res = pkgResult{State: "failed", Detail: "the agent failed to run this job"}
			}
		}()
		res, work = a.pkgJob(job)
		return res
	}()
	if err := a.patchWithRetry(fmt.Sprintf(pkgJobURL, a.AgentID, job), res, pkgRetryWait); err != nil {
		a.Logger.Errorln("pkgjob: the result of job", job, "did not reach the server:", err)
	}
	if work != "" {
		if err := os.RemoveAll(work); err != nil {
			a.Logger.Debugln("pkgjob:", err)
		}
	}
}

// pkgJob gives the result and the work dir it made.
func (a *Agent) pkgJob(job string) (pkgResult, string) {
	fail := func(err error) pkgResult {
		return pkgResult{State: "failed", Detail: sdioCut(err.Error(), sdioDetailMax)}
	}
	root, err := a.pkgRoot()
	if err != nil {
		return fail(err), ""
	}
	a.pkgRemoveStale(root)
	plan, err := a.pkgPlan(job)
	if err != nil {
		return fail(err), ""
	}
	free, err := pkgFree(root)
	if err != nil {
		return fail(fmt.Errorf("free disk space: %w", err)), ""
	}
	if err := pkgSpace(free, plan); err != nil {
		return fail(err), ""
	}
	work := filepath.Join(root, "pkg-"+job)
	if err := os.Mkdir(work, 0o700); err != nil {
		return fail(err), ""
	}
	file := filepath.Join(work, plan.Filename)
	if err := a.pkgDownload(job, plan, file); err != nil {
		return fail(err), work
	}
	dir := work
	if plan.Extract != "none" {
		stop := a.pkgBeat(job, "extracting", plan.Size)
		dir = filepath.Join(work, "files")
		err := pkgExtract(plan.Extract, file, dir, pkgExtractMax)
		stop()
		if err != nil {
			return fail(err), work
		}
	}
	stop := a.pkgBeat(job, "installing", plan.Size)
	defer stop()
	return a.pkgInstall(plan, file, dir), work
}

// pkgBeatEvery: how often a long unpack or install repeats its step, so the
// server does not take the quiet job for a lost one.
var pkgBeatEvery = 5 * time.Minute

// pkgBeat reports step now and again every pkgBeatEvery until stop is called.
func (a *Agent) pkgBeat(job, step string, size int64) (stop func()) {
	a.pkgProgress(job, step, size, size)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(pkgBeatEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				a.pkgProgress(job, step, size, size)
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}
