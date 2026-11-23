// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
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
}

func openImaging(g imagingGrant, iface, ca string) (*imagingTransfer, error) {
	u, e := url.Parse(g.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/imaging/transfers/") || !strings.HasSuffix(u.Path, "/") || g.Token == "" {
		return nil, errors.New("invalid HTTPS imaging grant")
	}
	// Internal connections stay bound to the verified tunnel interface, so a
	// reused connection cannot move to another route.
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableCompression: true, IdleConnTimeout: 90 * time.Second}
	if ca != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid imaging CA bundle")
		}
		tr.TLSClientConfig.RootCAs = roots
	}
	switch g.Mode {
	case "internal":
		tr.DialContext, e = imagingDialContext(iface)
		if e != nil {
			return nil, e
		}
	case "internet":
	default:
		return nil, errors.New("unknown imaging network mode")
	}
	return &imagingTransfer{g, &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, 2 * time.Second}, nil
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
		json.Unmarshal(data, &problem)
		e = fmt.Errorf("imaging server answered %d %s", r.StatusCode, problem.Detail)
	}
	return data, r.StatusCode, e
}

// imagingTemporary reports no answer or a server error that a later attempt can pass.
func imagingTemporary(status int) bool {
	return status == 0 || status == http.StatusTooManyRequests || (status >= 500 && status != http.StatusInsufficientStorage)
}

// requestRetry repeats a request that got no answer or a temporary server error.
func (t *imagingTransfer) requestRetry(ctx context.Context, method, path string, body []byte, content string) ([]byte, int, error) {
	for attempt := 0; ; attempt++ {
		data, status, err := t.request(ctx, method, path, body, content)
		if err == nil || !imagingTemporary(status) || attempt == 4 || ctx.Err() != nil {
			return data, status, err
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
func (t *imagingTransfer) upload(ctx context.Context, m imagingManifest, source io.Reader) error {
	if _, _, e := t.requestRetry(ctx, "POST", "begin/", nil, ""); e != nil {
		return e
	}
	sum := sha256.New()
	var size int64
	buf := make([]byte, imagingBlock)
	for index := 0; ; index++ {
		n, e := io.ReadFull(source, buf)
		if e == io.EOF {
			break
		}
		if e != nil && e != io.ErrUnexpectedEOF {
			return e
		}
		raw := buf[:n]
		h := sha256.Sum256(raw)
		if m.Native.Method == linuxFilesMethod {
			sum.Write(h[:])
		} else {
			sum.Write(raw)
		}
		path := fmt.Sprintf("part/?i=%d&size=%d&sha256=%x", index, n, h)
		_, status, err := t.requestRetry(ctx, "POST", path, nil, "")
		if status == http.StatusNotFound {
			var b bytes.Buffer
			payload := raw
			if m.Codec == "gzip" {
				z, err := gzip.NewWriterLevel(&b, m.Level)
				if err != nil {
					return err
				}
				if _, err = z.Write(raw); err != nil {
					return err
				}
				if err = z.Close(); err != nil {
					return err
				}
				payload = b.Bytes()
			} else if m.Codec != "none" {
				return errors.New("unsupported imaging compression")
			}
			_, status, err = t.requestRetry(ctx, "PUT", path, payload, "application/octet-stream")
		}
		if status == http.StatusConflict {
			// A retry after a lost answer finds its block already committed.
			if committed, e := t.manifest(ctx, m.Agent, m.Disk, "capture"); e == nil && committed.Offset == size+int64(n) {
				err = nil
			}
		}
		if err != nil {
			return err
		}
		size += int64(n)
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
			return nil
		}
	}
	return err
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
