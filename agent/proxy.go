// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

const proxyDialTimeout = 10 * time.Second

// httpConnectDialer reaches NATS through an HTTP proxy with CONNECT. The
// proxy is spoken to in plain TCP, also for an https:// proxy URL.
type httpConnectDialer struct {
	proxy  *url.URL
	dialer net.Dialer
}

// refuseDialer stands in for a proxy the agent cannot use: going around
// the proxy the operator set would be worse than not connecting.
type refuseDialer struct{ err error }

func (d refuseDialer) Dial(_, _ string) (net.Conn, error) { return nil, d.err }

func newHTTPConnectDialer(proxy *url.URL) *httpConnectDialer {
	return &httpConnectDialer{
		proxy:  proxy,
		dialer: net.Dialer{Timeout: proxyDialTimeout, KeepAlive: 30 * time.Second},
	}
}

func (d *httpConnectDialer) Dial(_, address string) (net.Conn, error) {
	conn, err := d.dialer.Dial("tcp", proxyAddr(d.proxy))
	if err != nil {
		return nil, err
	}
	// a proxy that never answers must not hang the reconnect loop
	_ = conn.SetDeadline(time.Now().Add(proxyDialTimeout))
	br, err := d.connect(conn, address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// proxyAddr is host:port of the proxy; without a port the scheme's default,
// as http.ProxyURL does for REST.
func proxyAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// connect sends CONNECT for address over conn and checks the answer. The
// reader may hold bytes the proxy sent past its answer.
func (d *httpConnectDialer) connect(conn net.Conn, address string) (*bufio.Reader, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if u := d.proxy.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	br := bufio.NewReader(conn)
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	answer, err := http.ReadResponse(br, req)
	if err == nil {
		answer.Body.Close()
		if answer.StatusCode != http.StatusOK {
			err = fmt.Errorf("newHTTPConnectDialer(): proxy rejected connection: %s", answer.Status)
		}
	}
	return br, err
}

// Bytes the proxy already sent past its CONNECT answer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
