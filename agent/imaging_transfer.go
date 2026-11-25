// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

const imagingBlock = 2 << 20

type imagingGrant struct {
	Claim string `json:"claim"`
	URL   string `json:"url"`
	Token string `json:"token"`
	Image string `json:"image_id"`
	Mode  string `json:"network_mode"`
}
type imagingManifest struct {
	Native    ImagingCapability `json:"native"`
	Image     string            `json:"image_id"`
	Agent     string            `json:"agent_id"`
	Disk      string            `json:"disk_id"`
	UUID      string            `json:"device_uuid"`
	Direction string            `json:"direction"`
	Mode      string            `json:"network_mode"`
	Codec     string            `json:"compression"`
	Level     int               `json:"compression_level"`
	Size      int64             `json:"raw_size"`
	Hash      string            `json:"raw_sha256"`
	Status    string            `json:"status"`
	Offset    int64             `json:"offset"`
}

type imagingTransfer struct {
	grant  imagingGrant
	client *http.Client
	retry  time.Duration
	// set for a protocol-2 run: batch parts, throttle, network pause
	run *imagingRun
}

// openImaging uses the agent's TLS setup (pins and client certificate for the
// RMM host, the custom CA) and, in internet mode, its proxy.
func openImaging(g imagingGrant, iface string, a *Agent) (*imagingTransfer, error) {
	u, e := url.Parse(g.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/imaging/transfers/") || !strings.HasSuffix(u.Path, "/") || g.Token == "" {
		return nil, errors.New("invalid HTTPS imaging grant")
	}
	if a.Cert != "" && a.rmmRoots() == nil {
		return nil, errors.New("invalid imaging CA bundle")
	}
	// Internal connections stay bound to the verified tunnel interface, so a
	// reused connection cannot move to another route.
	tr := &http.Transport{TLSClientConfig: a.tlsFor(u.Hostname()), DisableCompression: true, IdleConnTimeout: 90 * time.Second}
	switch g.Mode {
	case "internal":
		tr.DialContext, e = imagingDialContext(iface)
		if e != nil {
			return nil, e
		}
	case "internet":
		if a.Proxy != "" {
			// as the API client: a proxy that does not parse is logged, not used
			if p, err := parseProxyURL(a.Proxy); err != nil {
				a.Logger.Errorln("Imaging transfer:", err)
			} else {
				tr.Proxy = http.ProxyURL(p)
			}
		}
	default:
		return nil, errors.New("unknown imaging network mode")
	}
	return &imagingTransfer{grant: g, client: &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, retry: 2 * time.Second}, nil
}

// imagingStatusError is a transfer answer outside 2xx.
type imagingStatusError struct {
	path   string
	status int
	detail string
}

func (e *imagingStatusError) Error() string {
	return fmt.Sprintf("imaging server answered %d %s", e.status, e.detail)
}

func (t *imagingTransfer) request(ctx context.Context, method, path string, body []byte, content string) ([]byte, int, error) {
	req, e := http.NewRequestWithContext(ctx, method, t.grant.URL+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, e
	}
	req.Header.Set("Authorization", "Bearer "+t.grant.Token)
	if content != "" {
		req.Header.Set("Content-Type", content)
	}
	r, e := t.client.Do(req)
	if e != nil {
		return nil, 0, e
	}
	defer r.Body.Close()
	data, e := io.ReadAll(io.LimitReader(r.Body, imagingBlock+65537))
	if e != nil {
		// An answer cut off in transit counts as no answer.
		return nil, 0, e
	}
	if len(data) > imagingBlock+65536 {
		e = errors.New("oversized imaging response")
	}
	if e == nil && (r.StatusCode < 200 || r.StatusCode >= 300) {
		var problem struct{ Detail string }
		var list []string
		// some refusals are a JSON list of messages
		if json.Unmarshal(data, &problem) != nil && json.Unmarshal(data, &list) == nil && len(list) > 0 {
			problem.Detail = list[0]
		}
		e = &imagingStatusError{path, r.StatusCode, problem.Detail}
	}
	return data, r.StatusCode, e
}

// imagingTemporary reports no answer or a server error that a later attempt can pass.
func imagingTemporary(status int) bool {
	return status == 0 || status == http.StatusTooManyRequests || (status >= 500 && status != http.StatusInsufficientStorage)
}

// requestRetry repeats a request that got no answer or a temporary server
// error. After the tries a run waits in its network pause and tries again.
func (t *imagingTransfer) requestRetry(ctx context.Context, method, path string, body []byte, content string) ([]byte, int, error) {
	for attempt := 0; ; attempt++ {
		data, status, err := t.request(ctx, method, path, body, content)
		if err == nil || !imagingTemporary(status) {
			t.run.netBack()
			return data, status, err
		}
		if ctx.Err() != nil || attempt >= 4 && t.run == nil {
			return data, status, err
		}
		if attempt >= 4 {
			if e := t.run.netLost(ctx); e != nil {
				return data, status, e
			}
			continue
		}
		select {
		case <-ctx.Done():
			return data, status, err
		case <-time.After(t.retry << attempt):
		}
	}
}
func (t *imagingTransfer) manifest(ctx context.Context, agent, disk, direction string) (imagingManifest, error) {
	var m imagingManifest
	data, _, e := t.requestRetry(ctx, "GET", "", nil, "")
	if e != nil {
		return m, e
	}
	if e = json.Unmarshal(data, &m); e != nil {
		return m, e
	}
	if m.Image != t.grant.Image || m.Agent != agent || m.Disk != disk || m.Direction != direction || m.Mode != t.grant.Mode || m.Native.Method == "" {
		return m, errors.New("grant does not match selected native image, device, disk or route")
	}
	return m, nil
}

// imagingPartsWindow is the number of blocks a run names in one parts/ request.
const imagingPartsWindow = 16

type imagingPart struct {
	i   int
	raw []byte
	sum [32]byte
	// stream offset after the block
	end int64
}

func (p imagingPart) path() string {
	return fmt.Sprintf("part/?i=%d&size=%d&sha256=%x", p.i, len(p.raw), p.sum)
}

func (t *imagingTransfer) upload(ctx context.Context, m imagingManifest, source io.Reader) error {
	if _, _, e := t.requestRetry(ctx, "POST", "begin/", nil, ""); e != nil {
		return e
	}
	sum := sha256.New()
	var size int64
	window := 1
	if t.run != nil {
		window = imagingPartsWindow
	}
	bufs := make([][]byte, window)
	for index, eof := 0, false; !eof; {
		var parts []imagingPart
		for len(parts) < window {
			if e := t.run.gate(); e != nil {
				return e
			}
			if bufs[len(parts)] == nil {
				bufs[len(parts)] = make([]byte, imagingBlock)
			}
			n, e := io.ReadFull(source, bufs[len(parts)])
			if e == io.EOF {
				eof = true
				break
			}
			if e != nil && e != io.ErrUnexpectedEOF {
				return e
			}
			raw := bufs[len(parts)][:n]
			h := sha256.Sum256(raw)
			if m.Native.Method == linuxFilesMethod {
				sum.Write(h[:])
			} else {
				sum.Write(raw)
			}
			size += int64(n)
			parts = append(parts, imagingPart{index, raw, h, size})
			index++
			t.run.read(n)
		}
		if len(parts) == 0 {
			break
		}
		var err error
		if t.run != nil {
			err = t.parts(ctx, m, parts)
		} else {
			err = t.part(ctx, m, parts[0])
		}
		if err != nil {
			return err
		}
	}
	digest := hex.EncodeToString(sum.Sum(nil))
	fields := map[string]any{}
	if s, ok := source.(interface{ SealFields() map[string]any }); ok {
		maps.Copy(fields, s.SealFields())
	}
	fields["sha256"], fields["size"] = digest, size
	seal, _ := json.Marshal(fields)
	_, _, err := t.requestRetry(ctx, "POST", "seal/", seal, "application/json")
	if err != nil {
		// A connection can disappear after the server commits the manifest.
		committed, e := t.manifest(ctx, m.Agent, m.Disk, "capture")
		if e == nil && (committed.Status == "verifying" || committed.Status == "verified") && committed.Offset == size && committed.Hash == digest {
			err = nil
		}
	}
	if err == nil {
		t.run.sealedNow()
	}
	return err
}

// part sends one block the way agents before the batch request do.
func (t *imagingTransfer) part(ctx context.Context, m imagingManifest, p imagingPart) error {
	_, status, err := t.requestRetry(ctx, "POST", p.path(), nil, "")
	if status == http.StatusNotFound {
		status, err = t.put(ctx, m, p)
	}
	return t.committed(ctx, m, p, status, err)
}

// committed: a retry after a lost answer finds its block already committed.
func (t *imagingTransfer) committed(ctx context.Context, m imagingManifest, p imagingPart, status int, err error) error {
	if status == http.StatusConflict {
		if c, e := t.manifest(ctx, m.Agent, m.Disk, "capture"); e == nil && c.Offset == p.end {
			return nil
		}
	}
	return err
}

func (t *imagingTransfer) put(ctx context.Context, m imagingManifest, p imagingPart) (int, error) {
	var b bytes.Buffer
	payload := p.raw
	if m.Codec == "gzip" {
		z, err := gzip.NewWriterLevel(&b, m.Level)
		if err != nil {
			return 0, err
		}
		if _, err = z.Write(p.raw); err != nil {
			return 0, err
		}
		if err = z.Close(); err != nil {
			return 0, err
		}
		payload = b.Bytes()
	} else if m.Codec != "none" {
		return 0, errors.New("unsupported imaging compression")
	}
	if err := t.run.charge(ctx, len(payload)); err != nil {
		return 0, err
	}
	_, status, err := t.requestRetry(ctx, "PUT", p.path(), payload, "application/octet-stream")
	if err == nil {
		t.run.uploaded(len(p.raw), len(payload))
	}
	return status, err
}

// parts attaches the known blocks of a window with batch requests and sends
// the first one the server lacks with PUT part/, until the window is done.
func (t *imagingTransfer) parts(ctx context.Context, m imagingManifest, parts []imagingPart) error {
	for len(parts) > 0 {
		entries := make([]map[string]any, len(parts))
		for k, p := range parts {
			entries[k] = map[string]any{"i": p.i, "size": len(p.raw), "id": hex.EncodeToString(p.sum[:])}
		}
		body, _ := json.Marshal(map[string]any{"parts": entries})
		if err := t.run.charge(ctx, len(body)); err != nil {
			return err
		}
		data, status, err := t.requestRetry(ctx, "POST", "parts/", body, "application/json")
		t.run.uploaded(0, len(body))
		var answer struct {
			Missing []int `json:"missing"`
			Offset  int64 `json:"offset"`
		}
		if status == http.StatusConflict {
			// the server is further on within this window: a lost answer
			k := 0
			if json.Unmarshal(data, &answer) == nil {
				k = slices.IndexFunc(parts, func(p imagingPart) bool { return p.end == answer.Offset }) + 1
			}
			if k == 0 {
				return err
			}
			parts = parts[k:]
			continue
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &answer); err != nil {
			return err
		}
		if len(answer.Missing) == 0 {
			if end := parts[len(parts)-1].end; answer.Offset != end {
				return fmt.Errorf("the server attached the batch to offset %d instead of %d", answer.Offset, end)
			}
			return nil
		}
		k := answer.Missing[0] - parts[0].i
		if k < 0 || k >= len(parts) {
			return errors.New("the server named a block outside the batch")
		}
		if err := t.run.gate(); err != nil {
			return err
		}
		status, err = t.put(ctx, m, parts[k])
		if err := t.committed(ctx, m, parts[k], status, err); err != nil {
			return err
		}
		parts = parts[k+1:]
	}
	return nil
}

func (t *imagingTransfer) fetch(ctx context.Context, m imagingManifest, path string) error {
	// Its digest covers block digests, not the stream this would write.
	if m.Native.Method == linuxFilesMethod {
		return errors.New("restore this point with the ULRMM recovery helper")
	}
	// The digest also names the partial file, so it must be plain hex.
	if _, err := hex.DecodeString(m.Hash); m.Status != "verified" || m.Size <= 0 || len(m.Hash) != 64 || err != nil {
		return errors.New("the selected recovery point has no verified manifest")
	}
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	// A rerun for the same output continues from these bytes. The digest in
	// the name keeps another recovery point from resuming them.
	partial := path + "." + m.Hash[:16] + ".partial"
	out, err := openImagingPartial(partial)
	if err != nil {
		return err
	}
	defer out.Close()
	discard := func(reason string) error {
		out.Close()
		os.Remove(partial)
		return errors.New(reason)
	}
	sum := sha256.New()
	offset, err := io.Copy(sum, out)
	if err != nil {
		return err
	}
	resumed := offset
	for offset < m.Size {
		data, status, e := t.requestRetry(ctx, "GET", fmt.Sprintf("data/?offset=%d", offset), nil, "")
		if e != nil && imagingTemporary(status) {
			return fmt.Errorf("%w; run the same command again to continue from %d bytes", e, offset)
		} else if e != nil {
			return e
		}
		if len(data) == 0 || int64(len(data)) > m.Size-offset {
			return errors.New("invalid recovery stream length")
		}
		if _, err = out.Write(data); err != nil {
			return err
		}
		sum.Write(data)
		offset += int64(len(data))
	}
	if hex.EncodeToString(sum.Sum(nil)) != m.Hash {
		// Bytes kept from an earlier run can be damaged locally. Only a stream
		// fetched in one run points at the server copy.
		if resumed == 0 {
			t.request(ctx, "POST", "integrity-failed/", nil, "")
		}
		return discard("recovery stream SHA-256 mismatch; the partial download was removed")
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if _, err = out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	sum.Reset()
	n, err := io.Copy(sum, out)
	if err != nil {
		return err
	}
	if n != m.Size || hex.EncodeToString(sum.Sum(nil)) != m.Hash {
		return discard("staged recovery artifact failed readback; the partial download was removed")
	}
	if err = out.Close(); err != nil {
		return err
	}
	// Link only a complete file. A concurrent creator or an existing disk,
	// symlink or artifact at the destination must never be overwritten.
	if err = os.Link(partial, path); err != nil {
		return fmt.Errorf("publish verified artifact without overwrite, the verified data stays at %s: %w", partial, err)
	}
	os.Remove(partial)
	body, _ := json.Marshal(map[string]string{"raw_sha256": m.Hash})
	_, _, err = t.requestRetry(ctx, "POST", "complete/", body, "application/json")
	if err != nil {
		return fmt.Errorf("verified artifact saved at %s (%d bytes, SHA-256 %s); server did not acknowledge completion: %w", path, m.Size, m.Hash, err)
	}
	return nil
}

// openImagingPartial opens the resumable download without following a link,
// opening a device or reusing a file that another user put at that name.
func openImagingPartial(name string) (*os.File, error) {
	out, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if !errors.Is(err, os.ErrExist) {
		return out, err
	}
	link, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !link.Mode().IsRegular() || !imagingPartialPrivate(link) {
		return nil, fmt.Errorf("%s is not a private regular partial download; remove it and run the command again", name)
	}
	if out, err = os.OpenFile(name, os.O_RDWR, 0); err != nil {
		return nil, err
	}
	if info, err := out.Stat(); err != nil || !os.SameFile(link, info) {
		out.Close()
		return nil, fmt.Errorf("%s changed while it was opened", name)
	}
	return out, nil
}
