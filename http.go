package proxyclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HttpProxyClient struct {
	baseProxyClient
	proxyURL *url.URL
}

func NewHttpProxyClient(proxyURL string) (*HttpProxyClient, error) {
	proxyURL2, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	return NewHttpProxyClientFromURL(proxyURL2)
}

func NewHttpProxyClientFromURL(proxyURL *url.URL) (*HttpProxyClient, error) {
	if proxyURL.Scheme != "http" {
		return nil, fmt.Errorf("proxy url scheme must be http")
	}
	return &HttpProxyClient{
		proxyURL: proxyURL,
	}, nil
}

type ProxyConn struct {
	net.Conn
	proxyURL        *url.URL
	targetAddr      *url.URL
	tlsState        *tls.ConnectionState
	ExtraHeaderFunc func(h http.Header)
}

func (c *HttpProxyClient) DialTCPContext(ctx context.Context, address string) (*ProxyConn, error) {
	targetAddr, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("parse target addr: %w", err)
	}
	if targetAddr.Scheme != "http" && targetAddr.Scheme != "https" {
		return nil, fmt.Errorf("unsupported target url scheme: %s", targetAddr.Scheme)
	}
	wrapErr := func(err error) error {
		// Return a typed error, per Issue 16997
		return &net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}
	}
	addr := canonicalAddr(c.proxyURL)
	dialContext := c.DialContext
	if dialContext == nil {
		dialContext = zeroDialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, wrapErr(err)
	}
	// tcpConn, ok := conn.(*net.TCPConn)
	// if !ok {
	// 	return nil, wrapErr(fmt.Errorf("internal error: invalid connection type: %T", conn))
	// }
	return c.handleConnect(ctx, conn, c.proxyURL, targetAddr)
}

func (c *baseProxyClient) handleConnect(ctx context.Context, conn net.Conn, proxyURL, targetAddr *url.URL) (*ProxyConn, error) {
	var err error
	if targetAddr.Scheme == "http" {
		return &ProxyConn{
			Conn:       conn,
			proxyURL:   proxyURL,
			targetAddr: targetAddr,
			ExtraHeaderFunc: func(h http.Header) {
				h.Set("Proxy-Authorization", proxyAuth(proxyURL))
			},
		}, nil
	}

	var hdr http.Header
	if c.GetProxyConnectHeader != nil {
		hdr, err = c.GetProxyConnectHeader(ctx, proxyURL, targetAddr.Host)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	} else {
		hdr = c.ProxyConnectHeader
	}
	if hdr == nil {
		hdr = make(http.Header)
	}
	targetAddrCanonical := canonicalAddr(targetAddr)
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddrCanonical},
		Host:   targetAddrCanonical,
		Header: hdr,
	}
	// Set a (long) timeout here to make sure we don't block forever
	// and leak a goroutine if the connection stops replying after
	// the TCP connect.
	connectCtx, cancel := testHookProxyConnectTimeout(ctx, 1*time.Minute)
	defer cancel()
	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	var (
		resp *http.Response
		err2 error // write or read error
	)
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err2 = connectReq.Write(conn)
		if err2 != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err2 = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		_ = conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err2 != nil {
		_ = conn.Close()
		return nil, err2
	}
	if c.OnProxyConnectResponse != nil {
		err = c.OnProxyConnectResponse(ctx, proxyURL, connectReq, resp)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	if resp.StatusCode != 200 {
		_, text, ok := strings.Cut(resp.Status, " ")
		_ = conn.Close()
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}
	return &ProxyConn{
		Conn:       conn,
		proxyURL:   proxyURL,
		targetAddr: targetAddr,
	}, nil
}
