// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const healthPath = "/core/health/"

// ErrTransient marks a selftest failure the next run may not see: the RMM
// or the network, not this build or its identity. An update aborts on it
// without refusing the download.
var ErrTransient = errors.New("transient failure")

// transient wraps what happened on the wire (dial, DNS, timeout, reset,
// dropped connection) with ErrTransient. A TLS alert from the server and
// everything the handshake itself rejects (unknown CA, pin, client
// certificate) stay permanent.
func transient(err error) error {
	var alert tls.AlertError
	var ne net.Error
	var op *net.OpError
	if errors.As(err, &alert) || (errors.As(err, &op) && op.Op == "remote error") {
		return err
	}
	if op != nil || (errors.As(err, &ne) && ne.Timeout()) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrTransient, err)
	}
	return err
}

// SelfTest proves this build can take over: the config opens (New loaded
// it, identity included), the RMM accepts a TLS 1.3 handshake with the
// pinned trust and the client certificate, and the health endpoint answers.
// A 401 or 403 still means the handshake went through. The text is the
// line -selftest prints. Errors wrap ErrTransient when the RMM was not
// reachable rather than refusing this build.
func (a *Agent) SelfTest(timeout time.Duration) (string, error) {
	if why := a.notRunnable(); why != "" {
		return "", errors.New(why)
	}
	u, err := url.Parse(a.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", errors.New("the config has no https server URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	host := u.Hostname()
	cert := "client certificate sent"
	if a.clientCert.Load() == nil {
		cert = "no client certificate in the config"
	}
	// the direct dial shows a handshake failure on its own; behind a proxy
	// the request below makes the same handshake through the tunnel
	if a.Proxy == "" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: a.tlsFor(host)}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return "", transient(fmt.Errorf("tls handshake with %s: %w", host, err))
		}
		conn.Close()
	}
	c, err := a.httpClient(a.BaseURL, timeout)
	if err != nil {
		return "", err
	}
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.BaseURL, "/")+healthPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", transient(fmt.Errorf("health: %w", err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		cert += fmt.Sprintf(", health answered %d after the handshake", resp.StatusCode)
	default:
		if resp.StatusCode >= 500 {
			return "", fmt.Errorf("%w: health answered %d", ErrTransient, resp.StatusCode)
		}
		return "", fmt.Errorf("health answered %d", resp.StatusCode)
	}
	return fmt.Sprintf("selftest ok %s (%s)", a.Version, cert), nil
}
