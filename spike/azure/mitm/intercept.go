package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

type tokenKey struct{}

func withToken(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, tokenKey{}, value)
}

// intercept terminates the guest's TLS for host with a leaf of the spike CA
// and serves the decrypted HTTP requests through the token injector.
func (p *proxy) intercept(conn net.Conn, host, resource string) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && hello.ServerName != host {
				return nil, fmt.Errorf("SNI %q does not match CONNECT host %q", hello.ServerName, host)
			}
			return p.ca.leaf(host)
		},
	}
	srv := &http.Server{
		Handler:  p.injector(host, resource),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	_ = srv.Serve(newOneConnListener(tls.Server(conn, cfg)))
}

// oneConnListener hands out a single connection and then blocks until that
// connection is closed, so http.Server serves exactly the hijacked stream.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{closed: make(chan struct{})}
	l.conn = &notifyConn{Conn: c, onClose: func() { l.Close() }}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// notifyConn reports its Close so the listener can stop.
type notifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}
