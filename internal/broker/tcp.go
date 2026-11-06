package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
)

// tcpDialTimeout bounds how long the upstream of a tcp capability may take
// to accept a connection.
const tcpDialTimeout = 10 * time.Second

// grantsUnreadable is the reason given when the VM's grants cannot be read,
// which denies like a missing grant.
const grantsUnreadable = "grants unreadable"

// tcpGrantCheck is how often open connections of a tcp capability are
// checked against the grants, so a revoke also ends connections that were
// established before it; a database pool would otherwise keep its access for
// as long as it runs. maxTCPConns bounds the connections one capability holds
// open on the Mac. Both are variables for tests.
var (
	tcpGrantCheck = 2 * time.Second
	maxTCPConns   = 256
)

// dialUpstream connects to the upstream of a tcp capability; a variable for
// tests.
var dialUpstream = func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// ServeTCP relays every connection accepted on ln to the upstream of the tcp
// capability c until the broker is closed. ln is the socket a session
// forwards the capability's guest port to. The grant is checked per
// connection, so a listener may exist for a capability that is revoked later.
// ServeTCP owns ln from the call on and closes it when it refuses.
func (b *Broker) ServeTCP(c cap.Cap, ln net.Listener) error {
	if c.Kind() != cap.KindTCP {
		_ = ln.Close()
		return fmt.Errorf("capability %q is not a tcp capability", c.Name)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &tcpRelay{b: b, cap: c, ln: ln, pairs: map[*tcpPair]struct{}{},
		slots: make(chan struct{}, maxTCPConns), ctx: ctx, cancel: cancel}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		_ = ln.Close()
		return errors.New("broker is closed")
	}
	// Counted before Close can see the relay, so its stop waits for both.
	r.wg.Add(2)
	b.relays = append(b.relays, r)
	b.mu.Unlock()
	go r.acceptLoop()
	go r.watchGrant()
	return nil
}

// tcpRelay serves one tcp capability.
type tcpRelay struct {
	b   *Broker
	cap cap.Cap
	ln  net.Listener

	mu    sync.Mutex
	pairs map[*tcpPair]struct{}
	// slots holds one token per connection being dialled or relayed.
	slots chan struct{}
	// ctx ends when the relay stops; it also aborts dials in progress.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// tcpPair is one relayed connection: the guest's side and the upstream's.
type tcpPair struct {
	guest, upstream net.Conn
	// reason says why the relay ended the pair itself; empty when one of the
	// two sides closed it. Guarded by the relay's mu.
	reason string
}

func (p *tcpPair) close() {
	_ = p.guest.Close()
	_ = p.upstream.Close()
}

// stop closes the listener and every open connection and waits for their
// goroutines, so nothing writes to the audit log after Broker.Close.
func (r *tcpRelay) stop() {
	r.cancel()
	_ = r.ln.Close()
	r.closeAll("broker closed")
	r.wg.Wait()
}

func (r *tcpRelay) acceptLoop() {
	defer r.wg.Done()
	var delay time.Duration
	for {
		c, err := r.ln.Accept()
		if err == nil {
			delay = 0
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.handle(c)
			}()
			continue
		}
		if r.ctx.Err() != nil {
			return
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Temporary() { //nolint:staticcheck // the same check net/http's Serve uses
			r.b.detail("cap %s: accept: %v", r.cap.Name, err)
			// Closed, so the guest's connections are refused instead of
			// hanging on a socket nobody accepts from any more.
			_ = r.ln.Close()
			return
		}
		delay = min(max(2*delay, 5*time.Millisecond), maxAcceptDelay)
		select {
		case <-time.After(delay):
		case <-r.ctx.Done():
			return
		}
	}
}

// watchGrant ends the open connections once the capability is no longer
// granted.
func (r *tcpRelay) watchGrant() {
	defer r.wg.Done()
	t := time.NewTicker(tcpGrantCheck)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
		}
		if r.open() == 0 {
			continue
		}
		switch reason := r.b.tcpDenied(r.cap.Name); reason {
		case "":
		case grantsUnreadable:
			// Closed like a revoke, because nothing says the grant still
			// holds, but named for what it is.
			r.closeAll(grantsUnreadable)
		default:
			r.closeAll("revoked")
		}
	}
}

func (r *tcpRelay) open() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pairs)
}

func (r *tcpRelay) closeAll(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p := range r.pairs {
		if p.reason == "" {
			p.reason = reason
		}
		p.close()
	}
}

// track registers an established pair. It refuses once the relay has
// stopped, so no pair can slip past the stop that would have closed it.
func (r *tcpRelay) track(p *tcpPair) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return false
	}
	r.pairs[p] = struct{}{}
	return true
}

func (r *tcpRelay) untrack(p *tcpPair) (reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pairs, p)
	return p.reason
}

// handle serves one connection from the guest. A refusal just closes it:
// there is no protocol to answer in, the reason goes to the audit log.
func (r *tcpRelay) handle(guest net.Conn) {
	defer guest.Close()
	name, upstream := r.cap.Name, r.cap.TCP.Upstream
	if reason := r.b.tcpDenied(name); reason != "" {
		r.b.auditTCP(name, "deny", fmt.Sprintf("%q %q", upstream, reason))
		return
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		r.b.auditTCP(name, "deny", fmt.Sprintf("%q %q", upstream, "too many connections"))
		return
	}
	network, address := r.cap.TCP.Dial()
	ctx, cancel := context.WithTimeout(r.ctx, tcpDialTimeout)
	up, err := dialUpstream(ctx, network, address)
	cancel()
	if err != nil {
		r.b.auditTCP(name, "fail", fmt.Sprintf("%q %q", upstream, err.Error()))
		return
	}
	defer up.Close()
	pair := &tcpPair{guest: guest, upstream: up}
	if !r.track(pair) {
		return
	}
	// Checked again now that the pair is watched. The dial may have taken
	// seconds, and a revoke during it is seen neither by the check above nor
	// by the watcher, which only knows tracked pairs.
	if reason := r.b.tcpDenied(name); reason != "" {
		r.untrack(pair)
		r.b.auditTCP(name, "deny", fmt.Sprintf("%q %q", upstream, reason))
		return
	}
	r.b.auditTCP(name, "allow", fmt.Sprintf("%q", upstream))
	sent, received := pipe(guest, up)
	line := fmt.Sprintf("%q sent=%d received=%d", upstream, sent, received)
	if reason := r.untrack(pair); reason != "" {
		line += fmt.Sprintf(" reason=%q", reason)
	}
	r.b.auditTCP(name, "close", line)
}

// tcpDenied says why the VM may not use the tcp capability name right now,
// or "" when it may.
func (b *Broker) tcpDenied(name string) string {
	grants, err := b.Grants()
	if err != nil {
		b.detail("grants of %s unreadable: %v", b.VM, err)
		return grantsUnreadable
	}
	if !grants.Contains(grant.Grant{Cap: name}) {
		return "not granted; " + grant.Hint(b.VM, name)
	}
	return ""
}

// auditTCP records what happened to a connection of a tcp capability; there
// is no HTTP request to log.
func (b *Broker) auditTCP(capName, event, rest string) {
	log := b.logger()
	if log == nil {
		return
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	_, err := fmt.Fprintf(log, "%s vm=%s cap=%s %s TCP %s\n",
		now().UTC().Format(time.RFC3339), b.VM, capName, event, rest)
	b.auditFailed(err)
}

// pipe copies both directions until each side has finished and reports the
// bytes the guest sent and received. A side that stops sending is half-closed
// towards the other, which may still answer; an error ends both.
func pipe(guest, upstream net.Conn) (sent, received int64) {
	done := make(chan int64, 1)
	go func() { done <- copyHalf(upstream, guest) }()
	received = copyHalf(guest, upstream)
	return <-done, received
}

func copyHalf(dst, src net.Conn) int64 {
	n, err := io.Copy(dst, src)
	if hc, ok := dst.(interface{ CloseWrite() error }); err == nil && ok && hc.CloseWrite() == nil {
		return n
	}
	// No clean end of stream to pass on: end the other direction too, or it
	// would wait for a peer that is gone.
	_ = dst.Close()
	_ = src.Close()
	return n
}

// tcpOverHTTP answers an HTTP request for a tcp capability, which is not
// served under the broker URL. It names the guest's side only.
func tcpOverHTTP(c cap.Cap) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%s is a tcp capability; connect to 127.0.0.1:%d instead of the broker URL", c.Name, c.TCP.Port), "")
	})
}
