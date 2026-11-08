// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
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
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bodgit/sevenzip"
)

// SDIO driver packs: the server sends a job id, the agent fetches the plan,
// downloads each pack from the mirror, checks it against the torrent's piece
// hashes, unpacks only the approved folders and installs them with the
// server's install script. One job at a time.

const (
	sdioURL        = "/api/v4/%s/sdio/%s/"
	sdioMarkerLine = "ULRMM-PKG "
	sdioOutputMax  = 64 << 10
	sdioExtractMax = int64(4) << 30
	sdioDetailMax  = 500
)

var (
	sdioMu     sync.Mutex
	sdioJobRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sdioPackRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,120}\.7z$`)

	// vars so tests can shorten them
	sdioStall     = 120 * time.Second
	sdioRetryWait = 10 * time.Second
	// at most one progress PATCH per interval while a pack downloads
	sdioProgressEvery = 5 * time.Second
	// set by tests for their local mirror; nil = system roots
	sdioTestRoots *x509.CertPool
)

type sdioRange struct {
	URL    string `json:"url"`
	Start  int64  `json:"start"`
	Length int64  `json:"length"`
}

type sdioPack struct {
	Name        string      `json:"name"`
	URL         string      `json:"url"`
	Size        int64       `json:"size"`
	PieceLength int64       `json:"piece_length"`
	Head        []sdioRange `json:"head"`
	Tail        []sdioRange `json:"tail"`
	Hashes      []string    `json:"hashes"`
	Folders     []string    `json:"folders"`
	// false when the mirror lacks the neighbor file: that end piece is
	// not compared. Missing means true.
	HeadCheck *bool `json:"head_check"`
	TailCheck *bool `json:"tail_check"`

	sums    [][sha1.Size]byte
	headLen int64
}

type sdioPlan struct {
	Job           string     `json:"job"`
	Deadline      int        `json:"deadline"`
	Script        string     `json:"script"`
	ScriptTimeout int        `json:"script_timeout"`
	Packs         []sdioPack `json:"packs"`
}

type sdioResult struct {
	Pack   string `json:"pack"`
	Result string `json:"result"`
	Exit   *int64 `json:"exit"`
	Sig    string `json:"sig"`
	Signer string `json:"signer"`
	Msg    string `json:"msg"`
}

// What the job needs from the OS (sdio_windows.go).
type sdioHost struct {
	root    func() (string, error)
	free    func(dir string) (uint64, error)
	install func(script, dir string, timeout int) (stdout, stderr string)
}

// sdioAnswer is the reply to sdiodriver. On "ok" sdioMu is held and the
// caller runs the job and unlocks.
func sdioAnswer(job string, supported bool) string {
	switch {
	case !supported:
		return "not supported on this OS"
	case !sdioJobRe.MatchString(job):
		return "invalid job id"
	case !sdioMu.TryLock():
		return "busy"
	}
	return "ok"
}

func (p *sdioPlan) check(job string) error {
	switch {
	case p.Job != job:
		return errors.New("the plan is for another job")
	case p.Deadline <= 0 || p.Deadline > 86400:
		return fmt.Errorf("the plan has a deadline of %d s", p.Deadline)
	case p.Script == "" || p.ScriptTimeout <= 60 || p.ScriptTimeout > p.Deadline:
		return errors.New("the plan has no usable install script")
	case len(p.Packs) == 0:
		return errors.New("the plan has no packs")
	}
	for i := range p.Packs {
		if err := p.Packs[i].check(); err != nil {
			return err
		}
	}
	return nil
}

func sdioHTTPS(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Host != ""
}

// check refuses http links, bad folders and piece lists that do not cover
// the file, and decodes the hashes.
func (p *sdioPack) check() error {
	if !sdioPackRe.MatchString(p.Name) {
		return fmt.Errorf("invalid pack name %q", p.Name)
	}
	if !sdioHTTPS(p.URL) {
		return fmt.Errorf("%s: the plan uses a link that is not https", p.Name)
	}
	misfit := fmt.Errorf("%s: the plan does not fit the torrent", p.Name)
	if p.Size <= 0 || p.PieceLength < 16<<10 || p.PieceLength > 32<<20 {
		return misfit
	}
	sum := func(rs []sdioRange) (int64, error) {
		var n int64
		for _, r := range rs {
			if !sdioHTTPS(r.URL) {
				return 0, fmt.Errorf("%s: the plan uses a link that is not https", p.Name)
			}
			if r.Start < 0 || r.Length <= 0 || r.Length > p.PieceLength {
				return 0, misfit
			}
			n += r.Length
		}
		if n >= p.PieceLength {
			return 0, misfit
		}
		return n, nil
	}
	head, err := sum(p.Head)
	if err != nil {
		return err
	}
	tail, err := sum(p.Tail)
	if err != nil {
		return err
	}
	pieces := (head+p.Size-1)/p.PieceLength + 1
	if int64(len(p.Hashes)) != pieces || head+p.Size+tail > pieces*p.PieceLength {
		return misfit
	}
	p.headLen = head
	p.sums = make([][sha1.Size]byte, len(p.Hashes))
	for i, h := range p.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha1.Size {
			return misfit
		}
		copy(p.sums[i][:], b)
	}
	if len(p.Folders) == 0 {
		return fmt.Errorf("%s: the plan names no folder", p.Name)
	}
	for i, f := range p.Folders {
		f = strings.TrimSuffix(strings.ReplaceAll(f, `\`, "/"), "/")
		if err := sdioPathOK(f); err != nil {
			return fmt.Errorf("%s: folder %q: %w", p.Name, p.Folders[i], err)
		}
		for _, e := range strings.Split(f, "/") {
			if e == "" || e == "." {
				return fmt.Errorf("%s: folder %q is not a plain path", p.Name, p.Folders[i])
			}
		}
		p.Folders[i] = f + "/"
	}
	return nil
}

func sdioPathOK(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case strings.HasPrefix(p, "/"):
		return errors.New("absolute path")
	case strings.ContainsAny(p, ":\x00"):
		return errors.New("drive letter or stream name in the path")
	}
	for _, e := range strings.Split(p, "/") {
		if e == ".." {
			return errors.New("the path leaves its folder")
		}
	}
	return nil
}

// sdioEntry gives the slash path of an archive entry and the index of the
// folder it is in, -1 for entries outside the wanted folders. Folders end
// with a slash and match without regard to case.
func sdioEntry(name string, folders []string) (string, int, error) {
	n := strings.ReplaceAll(name, `\`, "/")
	for i, f := range folders {
		if len(n) < len(f) || !strings.EqualFold(n[:len(f)], f) {
			continue
		}
		if err := sdioPathOK(n); err != nil {
			return "", i, fmt.Errorf("%s: %w", name, err)
		}
		return path.Clean(n), i, nil
	}
	return "", -1, nil
}

// sdioExtract writes the files of the wanted folders below dest, at most
// limit bytes. Links and special files are refused.
func sdioExtract(pack, name string, folders []string, dest string, limit int64) error {
	z, err := sevenzip.OpenReader(pack)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer z.Close()
	found := make([]bool, len(folders))
	var written int64
	for _, f := range z.File {
		rel, i, err := sdioEntry(f.Name, folders)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if i < 0 {
			continue
		}
		mode := f.Mode().Type()
		if f.Attributes&0x400 != 0 || (mode != 0 && mode != fs.ModeDir) {
			return fmt.Errorf("%s: %s is a link or a special file", name, f.Name)
		}
		target, err := safeJoin(dest, filepath.FromSlash(rel))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if mode == fs.ModeDir {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if written+int64(f.UncompressedSize) > limit {
			return fmt.Errorf("%s: the files to extract are larger than %s", name, ByteCountSI(uint64(limit)))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		n, err := sdioWriteEntry(f, target, limit-written)
		written += n
		if err != nil {
			return fmt.Errorf("%s: %s: %w", name, f.Name, err)
		}
		found[i] = true
	}
	for i, ok := range found {
		if !ok {
			return fmt.Errorf("%s is not in %s", folders[i], name)
		}
	}
	return nil
}

func sdioWriteEntry(f *sevenzip.File, target string, room int64) (int64, error) {
	r, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer r.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(r, room+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > room {
		err = errors.New("larger than its header says")
	}
	return n, err
}

// sdioBadData: what the mirror sent is not the torrent's file, another
// try would not help.
type sdioBadData struct{ msg string }

func (e *sdioBadData) Error() string { return e.msg }

// sdioCheck hashes the pack as it is written. Piece 0 starts with the head
// bytes, the last piece ends with the tail bytes; verified is the pack
// offset up to which every piece matched (or is not compared), where a
// resumed download starts.
type sdioCheck struct {
	p        *sdioPack
	head     []byte
	h        hash.Hash
	piece    int
	pos      int64
	verified int64
	progress func(pos int64)
}

func newSdioCheck(p *sdioPack, head []byte) *sdioCheck {
	c := &sdioCheck{p: p, head: head}
	c.reset()
	return c
}

// compared reports whether piece k is checked against its hash.
func (c *sdioCheck) compared(k int) bool {
	return (k != 0 || sdioOn(c.p.HeadCheck)) && (k != len(c.p.sums)-1 || sdioOn(c.p.TailCheck))
}

func sdioOn(b *bool) bool { return b == nil || *b }

// pack offset where piece k ends, without the tail
func (c *sdioCheck) end(k int) int64 {
	if e := int64(k+1)*c.p.PieceLength - c.p.headLen; e < c.p.Size {
		return e
	}
	return c.p.Size
}

func (c *sdioCheck) reset() {
	c.pos, c.piece = c.verified, 0
	if c.pos > 0 {
		c.piece = int((c.pos + c.p.headLen) / c.p.PieceLength)
	}
	c.h = sha1.New()
	if c.piece == 0 {
		c.h.Write(c.head)
	}
}

func (c *sdioCheck) verify() error {
	if c.compared(c.piece) && !bytes.Equal(c.h.Sum(nil), c.p.sums[c.piece][:]) {
		return &sdioBadData{fmt.Sprintf("piece %d of %s does not match the torrent", c.piece, c.p.Name)}
	}
	return nil
}

func (c *sdioCheck) Write(b []byte) (int, error) {
	n := len(b)
	if c.pos+int64(n) > c.p.Size {
		return 0, &sdioBadData{c.p.Name + " is larger than the torrent says"}
	}
	last := len(c.p.sums) - 1
	for len(b) > 0 {
		e := c.end(c.piece)
		k := e - c.pos
		if int64(len(b)) < k {
			k = int64(len(b))
		}
		if c.compared(c.piece) {
			c.h.Write(b[:k])
		}
		c.pos += k
		b = b[k:]
		if c.pos == e && c.piece < last {
			if err := c.verify(); err != nil {
				return 0, err
			}
			c.verified = c.pos
			c.piece++
			c.h.Reset()
		}
	}
	if c.progress != nil {
		c.progress(c.pos)
	}
	return n, nil
}

func (c *sdioCheck) finish(tail []byte) error {
	if c.pos != c.p.Size {
		return fmt.Errorf("%s has %d bytes, the torrent says %d", c.p.Name, c.pos, c.p.Size)
	}
	if c.compared(c.piece) {
		c.h.Write(tail)
	}
	if err := c.verify(); err != nil {
		return err
	}
	c.verified = c.pos
	return nil
}

// Proxy as in fetchFile, but no overall timeout (packs reach gigabytes,
// sdioGet stops a download that stalls instead) and not the RMM's TLS
// settings: -insecure and the --cert CA are for the RMM server, the mirror
// is checked against the system roots.
func (a *Agent) sdioClient() (*http.Client, error) {
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: sdioTestRoots},
		DisableKeepAlives: true,
	}
	if a.Proxy != "" {
		p, err := parseProxyURL(a.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(p)
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("the mirror redirected away from https")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}}, nil
}

type stallReader struct {
	r io.Reader
	t *time.Timer
}

func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.t.Reset(sdioStall)
	}
	return n, err
}

// sdioGet copies the file at u from start to w: length bytes, or to its
// end when length < 0. No data for sdioStall ends it.
func (a *Agent) sdioGet(ctx context.Context, c *http.Client, u string, start, length int64, w io.Writer) error {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	t := time.AfterFunc(sdioStall, func() { stalled.Store(true); cancel() })
	defer t.Stop()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", a.AgentHeader)
	switch {
	case length >= 0:
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+length-1))
	case start > 0:
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
	}
	err = func() error {
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusPartialContent:
			if !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-", start)) {
				return fmt.Errorf("the mirror sent another range than asked for (%s)", resp.Header.Get("Content-Range"))
			}
		case resp.StatusCode == http.StatusOK && start == 0:
		case resp.StatusCode == http.StatusOK:
			return errors.New("the mirror does not resume downloads")
		default:
			return fmt.Errorf("the mirror answered %d", resp.StatusCode)
		}
		body := &stallReader{r: resp.Body, t: t}
		if length < 0 {
			_, err = io.Copy(w, body)
			return err
		}
		if _, err = io.CopyN(w, body, length); errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return err
	}()
	if err != nil && stalled.Load() {
		err = fmt.Errorf("no data from the mirror for %s", sdioStall)
	}
	return err
}

func sdioPause(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(sdioRetryWait):
	}
}

// sdioRanges reads the neighbor bytes of a pack, three tries per range.
func (a *Agent) sdioRanges(ctx context.Context, c *http.Client, rs []sdioRange) ([]byte, error) {
	var buf bytes.Buffer
	for _, r := range rs {
		mark := buf.Len()
		var err error
		for try := 1; try <= 3; try++ {
			buf.Truncate(mark)
			if err = a.sdioGet(ctx, c, r.URL, r.Start, r.Length, &buf); err == nil || ctx.Err() != nil {
				break
			}
			sdioPause(ctx)
		}
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// sdioDownload fetches a pack to dest and checks every piece it touches. A
// broken download resumes at the last verified piece, three tries counted
// from the last one that verified a new piece; data that does not match the
// torrent is not tried again.
func (a *Agent) sdioDownload(ctx context.Context, c *http.Client, p *sdioPack, dest string, progress func(int64)) error {
	var head, tail []byte
	var err error
	if sdioOn(p.HeadCheck) {
		if head, err = a.sdioRanges(ctx, c, p.Head); err != nil {
			return fmt.Errorf("%s: the bytes before it: %w", p.Name, err)
		}
	}
	f, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	chk := newSdioCheck(p, head)
	chk.progress = progress
	var bad *sdioBadData
	for try := 1; ; try++ {
		from := chk.verified
		if err = f.Truncate(chk.verified); err != nil {
			return err
		}
		if _, err = f.Seek(chk.verified, io.SeekStart); err != nil {
			return err
		}
		chk.reset()
		err = a.sdioGet(ctx, c, p.URL, chk.pos, -1, io.MultiWriter(f, chk))
		if err == nil && chk.pos < p.Size {
			err = fmt.Errorf("the download ended after %d of %d bytes", chk.pos, p.Size)
		}
		// a try that verified new pieces starts the count again
		if chk.verified > from {
			try = 1
		}
		if err == nil || try == 3 || ctx.Err() != nil || errors.As(err, &bad) {
			break
		}
		a.Logger.Debugln("sdio:", p.Name, "try", try, "resumes at", chk.verified, err)
		sdioPause(ctx)
	}
	if err != nil {
		if bad == nil {
			err = fmt.Errorf("%s: %w", p.Name, err)
		}
		return err
	}
	if sdioOn(p.TailCheck) {
		if tail, err = a.sdioRanges(ctx, c, p.Tail); err != nil {
			return fmt.Errorf("%s: the bytes after it: %w", p.Name, err)
		}
	}
	if err := chk.finish(tail); err != nil {
		return err
	}
	return f.Close()
}

func sdioSpace(free uint64, size int64) error {
	need := 2*uint64(size) + 1<<30
	if free < need {
		return fmt.Errorf("not enough disk space: need %s, free %s", ByteCountSI(need), ByteCountSI(free))
	}
	return nil
}

// sdioMarker reads the result from the last ULRMM-PKG line of the script.
func sdioMarker(pack, stdout string) sdioResult {
	lines := strings.Split(stdout, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(l, sdioMarkerLine) {
			continue
		}
		var r sdioResult
		if json.Unmarshal([]byte(l[len(sdioMarkerLine):]), &r) == nil && (r.Result == "ok" || r.Result == "reboot" || r.Result == "fail" || r.Result == "refused") {
			r.Pack = pack
			return r
		}
		break
	}
	return sdioResult{Pack: pack, Result: "fail", Msg: "the install script stopped early"}
}

// status code and error; 0 when the server was not reached
func (a *Agent) sdioPatch(ctx context.Context, job string, body map[string]interface{}) (int, error) {
	r, err := a.rClient.R().SetContext(ctx).SetBody(body).Patch(fmt.Sprintf(sdioURL, a.AgentID, job))
	if err != nil {
		return 0, err
	}
	if r.IsError() {
		return r.StatusCode(), fmt.Errorf("server answered %d", r.StatusCode())
	}
	return r.StatusCode(), nil
}

func (a *Agent) sdioProgress(ctx context.Context, job string, body map[string]interface{}) {
	if _, err := a.sdioPatch(ctx, job, body); err != nil {
		a.Logger.Debugln("sdio progress:", err)
	}
}

// sdioMeter sends download progress from its own goroutine. An update that
// comes while a PATCH is still out is dropped, so a slow server never holds
// up the download.
type sdioMeter struct {
	ch   chan int64
	quit chan struct{}
	last time.Time
}

// newSdioMeter sends done 0 at once, then whatever report passes on.
func (a *Agent) newSdioMeter(ctx context.Context, job, detail string, total int64) *sdioMeter {
	m := &sdioMeter{ch: make(chan int64), quit: make(chan struct{}), last: time.Now()}
	send := func(done int64) {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		a.sdioProgress(pctx, job, map[string]interface{}{"state": "downloading", "detail": detail, "done": done, "total": total})
	}
	go func() {
		defer close(m.quit)
		send(0)
		for done := range m.ch {
			send(done)
		}
	}()
	return m
}

func (m *sdioMeter) report(done int64) {
	if time.Since(m.last) < sdioProgressEvery {
		return
	}
	select {
	case m.ch <- done:
		m.last = time.Now()
	default:
	}
}

// stop waits for the PATCH in flight, so it reaches the server before the
// next state does.
func (m *sdioMeter) stop() {
	close(m.ch)
	<-m.quit
}

func (a *Agent) sdioPlan(job string) (*sdioPlan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := a.rClient.R().SetContext(ctx).Get(fmt.Sprintf(sdioURL, a.AgentID, job))
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the plan: %w", err)
	}
	if r.IsError() {
		return nil, fmt.Errorf("cannot fetch the plan: server answered %d", r.StatusCode())
	}
	var p sdioPlan
	if err := json.Unmarshal(r.Body(), &p); err != nil {
		return nil, fmt.Errorf("cannot read the plan: %w", err)
	}
	return &p, p.check(job)
}

func sdioCut(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// runSdioJob runs one job and always sends the final state; the caller
// holds sdioMu.
func (a *Agent) runSdioJob(job string, h sdioHost) {
	results, output, err := func() (res []sdioResult, out string, err error) {
		defer func() {
			if v := recover(); v != nil {
				a.Logger.Errorf("sdio: recovered from panic: %v\n%s", v, debug.Stack())
				err = errors.New("the agent failed to run this job")
			}
		}()
		return a.sdioJob(job, h)
	}()
	body := map[string]interface{}{"state": "done", "detail": "", "results": results, "output": output}
	if results == nil {
		body["results"] = []sdioResult{}
	}
	if err != nil {
		body["state"], body["detail"] = "failed", sdioCut(err.Error(), sdioDetailMax)
	} else {
		for _, r := range results {
			if r.Result == "fail" || r.Result == "refused" {
				body["state"], body["detail"] = "failed", sdioCut(r.Pack+": "+r.Msg, sdioDetailMax)
				break
			}
		}
	}
	if err := a.patchWithRetry(fmt.Sprintf(sdioURL, a.AgentID, job), body, sdioRetryWait); err != nil {
		a.Logger.Errorln("sdio: the result of job", job, "did not reach the server:", err)
	}
	a.SendDrivers(true)
}

func (a *Agent) sdioJob(job string, h sdioHost) ([]sdioResult, string, error) {
	root, err := h.root()
	if err != nil {
		return nil, "", err
	}
	old, _ := filepath.Glob(filepath.Join(root, "sdio-*"))
	for _, d := range old {
		if err := os.RemoveAll(d); err != nil {
			a.Logger.Debugln("sdio: leftover", d, err)
		}
	}
	plan, err := a.sdioPlan(job)
	if err != nil {
		return nil, "", err
	}
	dir := filepath.Join(root, "sdio-"+job)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	c, err := a.sdioClient()
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(plan.Deadline)*time.Second)
	defer cancel()

	var out strings.Builder
	results := make([]sdioResult, 0, len(plan.Packs))
	for i := range plan.Packs {
		results = append(results, a.sdioOnePack(ctx, c, job, plan, &plan.Packs[i], dir, h, &out))
	}
	return results, outputTail(out.String(), sdioOutputMax), nil
}

func (a *Agent) sdioOnePack(ctx context.Context, c *http.Client, job string, plan *sdioPlan, p *sdioPack, dir string, h sdioHost, out *strings.Builder) sdioResult {
	fail := func(err error) sdioResult {
		if ctx.Err() != nil {
			err = fmt.Errorf("the job did not finish within %d s", plan.Deadline)
		}
		return sdioResult{Pack: p.Name, Result: "fail", Msg: err.Error()}
	}
	free, err := h.free(dir)
	if err != nil {
		return fail(fmt.Errorf("free disk space: %w", err))
	}
	if err := sdioSpace(free, p.Size); err != nil {
		return fail(err)
	}
	file := filepath.Join(dir, p.Name)
	defer os.Remove(file)
	m := a.newSdioMeter(ctx, job, fmt.Sprintf("%s (%s)", p.Name, ByteCountSI(uint64(p.Size))), p.Size)
	err = a.sdioDownload(ctx, c, p, file, m.report)
	m.stop()
	if err != nil {
		return fail(err)
	}
	files := filepath.Join(dir, "files")
	defer os.RemoveAll(files)
	if err := sdioExtract(file, p.Name, p.Folders, files, sdioExtractMax); err != nil {
		return fail(err)
	}
	os.Remove(file)
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	a.sdioProgress(ctx, job, map[string]interface{}{"state": "installing"})
	stdout, stderr := h.install(plan.Script, files, plan.ScriptTimeout)
	fmt.Fprintf(out, "%s\n%s\n%s\n", p.Name, stdout, stderr)
	return sdioMarker(p.Name, stdout)
}
