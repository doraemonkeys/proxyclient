package proxyclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"
)

type HttpsProxyClient struct {
	baseProxyClient
	proxyURL *url.URL
}

func NewHttpsProxyClient(proxyURL string) (*HttpsProxyClient, error) {
	proxyURL2, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	return NewHttpsProxyClientFromURL(proxyURL2)
}

func NewHttpsProxyClientFromURL(proxyURL *url.URL) (*HttpsProxyClient, error) {
	if proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("proxy url scheme must be https")
	}
	return &HttpsProxyClient{
		proxyURL: proxyURL,
	}, nil
}

func (c *HttpsProxyClient) DialTCPContext(ctx context.Context, address string) (*ProxyConn, error) {
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
	canonicalProxyAddr := canonicalAddr(c.proxyURL)
	var (
		conn     net.Conn
		tlsState tls.ConnectionState
	)
	if c.hasCustomTLSDialer() {
		conn, err = c.DialTLSContext(ctx, "tcp", canonicalProxyAddr)
		if err != nil {
			return nil, wrapErr(err)
		}

		if tc, ok := conn.(*tls.Conn); ok {
			// Handshake here, in case DialTLS didn't. TLSNextProto below
			// depends on it for knowing the connection state.
			if err := tc.HandshakeContext(ctx); err != nil {
				go conn.Close()
				return nil, err
			}
			tlsState = tc.ConnectionState()
		}
	} else {
		var dialContext = c.DialTLSContext
		if dialContext == nil {
			dialContext = zeroDialer.DialContext
		}
		originConn, err := dialContext(ctx, "tcp", canonicalProxyAddr)
		if err != nil {
			return nil, wrapErr(err)
		}
		// if err := originConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		// 	return nil, wrapErr(err)
		// }
		var firstTLSHost string
		if firstTLSHost, _, err = net.SplitHostPort(canonicalProxyAddr); err != nil {
			return nil, wrapErr(err)
		}
		tlsConn, err := c.addTLS(ctx, originConn, firstTLSHost, false)
		if err != nil {
			return nil, wrapErr(err)
		}
		tlsState = tlsConn.ConnectionState()
		conn = tlsConn
	}
	// fmt.Printf("tlsState: %#v\n", tlsState)
	pconn, err := c.handleConnect(ctx, conn, c.proxyURL, targetAddr)
	if err != nil {
		return nil, wrapErr(err)
	}
	pconn.tlsState = &tlsState
	return pconn, nil
}

func (b *baseProxyClient) hasCustomTLSDialer() bool {
	return b.DialTLSContext != nil
}

func (b *baseProxyClient) addTLS(ctx context.Context, plainConn net.Conn, name string, onlyH1 bool) (*tls.Conn, error) {
	// Initiate TLS and check remote host name against certificate.
	tlsConfig := cloneTLSConfig(b.TLSClientConfig)
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = name
	}
	if onlyH1 {
		tlsConfig.NextProtos = nil
	}
	tlsConn := tls.Client(plainConn, tlsConfig)
	errc := make(chan error, 2)
	var timer *time.Timer // for canceling TLS handshake
	if d := b.TLSHandshakeTimeout; d != 0 {
		timer = time.AfterFunc(d, func() {
			errc <- tlsHandshakeTimeoutError{}
		})
	}
	go func() {
		err := tlsConn.HandshakeContext(ctx)
		if timer != nil {
			timer.Stop()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		_ = plainConn.Close()
		if err == (tlsHandshakeTimeoutError{}) {
			// Now that we have closed the connection,
			// wait for the call to HandshakeContext to return.
			<-errc
		}
		return nil, err
	}
	return tlsConn, nil
}
