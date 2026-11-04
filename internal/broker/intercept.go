package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sovyn-eu/skiff/internal/grant"
)

// tlsHandshakeRecord is the first byte of every TLS connection; plain HTTP
// starts with a method name, never with it.
const tlsHandshakeRecord = 0x16

// peekTimeout bounds how long a new connection may stay silent before the
// broker drops it, handshakeTimeout how long a TLS handshake may take. Both
// are variables for tests.
var (
	peekTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
)

// maxAcceptDelay caps the back-off after temporary accept errors.
const maxAcceptDelay = time.Second

// Listener lets ln carry both the broker's plain HTTP and TLS for intercept
// routes: each connection is classified by its first byte, and TLS ones are
// handed to the HTTP server as *tls.Conn, so one server, one handler and one
// tunnel serve both. Without a CA, ln is returned unchanged.
func (b *Broker) Listener(ln net.Listener) net.Listener {
	if b.CA == nil {
		return ln
	}
	l := &muxListener{
		Listener: ln,
		tls: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"http/1.1"},
			GetCertificate: b.certificate,
			// A resumed session skips GetCertificate and with it the route
			// and grant check; every connection must take the full path.
			SessionTicketsDisabled: true,
		},
		peekTimeout:      peekTimeout,
		handshakeTimeout: handshakeTimeout,
		conns:            make(chan net.Conn),
		errc:             make(chan error, 1),
		done:             make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

// certificate picks the leaf for the requested server name, refusing the
// handshake unless the name belongs to an intercept route of a granted cap.
func (b *Broker) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(hello.ServerName)
	name, reason := b.interceptGrant(host)
	if reason == "" {
		leaf, err := b.leaf(host)
		if err == nil {
			return leaf, nil
		}
		b.detail("cap %s: %v", name, err)
		reason = "no certificate from the VM's intercept CA; re-run skiff grant"
	}
	b.auditTLS(name, host, reason)
	// %q: the server name is the guest's text and ends up in logs.
	return nil, fmt.Errorf("skiff broker: %q: %s", host, reason)
}

func (b *Broker) leaf(host string) (*tls.Certificate, error) {
	ca, err := b.CA.Current()
	if err != nil {
		return nil, err
	}
	if ca == nil {
		return nil, errors.New("the VM has no intercept CA")
	}
	return ca.Leaf(host)
}

// interceptGrant names the capability that intercepts host, or why none may.
func (b *Broker) interceptGrant(host string) (capName, reason string) {
	if host == "" {
		return "", "no server name"
	}
	c, rt, ok := b.Caps.RouteFor(host)
	if !ok || !rt.Intercept {
		return "", "not intercepted"
	}
	grants, err := b.Grants()
	if err != nil {
		b.detail("grants of %s unreadable: %v", b.VM, err)
		return c.Name, "grants unreadable"
	}
	if !grants.Contains(grant.Grant{Cap: c.Name}) {
		return c.Name, "not granted; " + grant.Hint(b.VM, c.Name)
	}
	return c.Name, ""
}

// locateIntercepted resolves a request that arrived over TLS. The handshake
// already checked the server name; the Host header must name the same host,
// so a request can never borrow another route's credential.
func (b *Broker) locateIntercepted(w http.ResponseWriter, r *http.Request) (target, decision, bool) {
	sni := strings.ToLower(r.TLS.ServerName)
	if requestHost(r) != sni {
		writeError(w, http.StatusMisdirectedRequest, "the Host header does not match the TLS server name", "")
		return target{}, decision{status: http.StatusMisdirectedRequest, reason: "host mismatch"}, false
	}
	c, rt, ok := b.Caps.RouteFor(sni)
	if !ok || !rt.Intercept {
		writeError(w, http.StatusMisdirectedRequest, sni+" is not intercepted", "")
		return target{}, decision{status: http.StatusMisdirectedRequest, reason: "not intercepted"}, false
	}
	return target{cap: c, route: &rt, rest: r.URL.Path, rawPath: r.URL.RawPath}, decision{}, true
}

// auditTLS records a refused handshake; there is no HTTP request to log.
func (b *Broker) auditTLS(capName, host, reason string) {
	log := b.logger()
	if log == nil {
		return
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	_, err := fmt.Fprintf(log, "%s vm=%s cap=%s deny TLS %q %q\n",
		now().UTC().Format(time.RFC3339), b.VM, orDash(capName), host, reason)
	b.auditFailed(err)
}

// muxListener classifies connections off the accept path, so a client that
// connects and stays silent never holds up the next one.
type muxListener struct {
	net.Listener
	tls              *tls.Config
	peekTimeout      time.Duration
	handshakeTimeout time.Duration
	conns            chan net.Conn
	errc             chan error
	done             chan struct{}
	once             sync.Once
}

// acceptLoop retries temporary errors (out of file descriptors, aborted
// connections) with back-off, as net/http does; giving up would leave the
// HTTP server waiting on a listener nobody feeds.
func (l *muxListener) acceptLoop() {
	var delay time.Duration
	for {
		c, err := l.Listener.Accept()
		if err == nil {
			delay = 0
			go l.classify(c)
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Temporary() { //nolint:staticcheck // the same check net/http's Serve uses
			delay = min(max(2*delay, 5*time.Millisecond), maxAcceptDelay)
			select {
			case <-time.After(delay):
				continue
			case <-l.done:
				return
			}
		}
		select {
		case l.errc <- err:
		case <-l.done:
		}
		return
	}
}

// classify sorts a connection by its first byte. TLS connections complete
// their handshake here, under a deadline, so a guest that stops halfway
// cannot hold a connection open; http.Server would wait forever.
func (l *muxListener) classify(c net.Conn) {
	pc := &peekedConn{Conn: c, r: bufio.NewReader(c)}
	_ = c.SetReadDeadline(time.Now().Add(l.peekTimeout))
	first, err := pc.r.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}
	var out net.Conn = pc
	if first[0] == tlsHandshakeRecord {
		tc := tls.Server(pc, l.tls)
		ctx, cancel := context.WithTimeout(context.Background(), l.handshakeTimeout)
		_ = c.SetDeadline(time.Now().Add(l.handshakeTimeout))
		err := tc.HandshakeContext(ctx)
		cancel()
		_ = c.SetDeadline(time.Time{})
		if err != nil {
			_ = tc.Close()
			return
		}
		out = tc
	}
	select {
	case l.conns <- out:
	case <-l.done:
		_ = out.Close()
	}
}

func (l *muxListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errc:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *muxListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// peekedConn reads through the buffer that holds the classified first byte.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
