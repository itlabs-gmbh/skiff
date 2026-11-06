package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
)

// tcpUpstream is a TCP server standing in for a database proxy on the Mac.
// serve handles each accepted connection; accepted counts them.
type tcpUpstream struct {
	ln       net.Listener
	accepted atomic.Int32
}

func newTCPUpstream(t *testing.T, ln net.Listener, serve func(net.Conn)) *tcpUpstream {
	t.Helper()
	u := &tcpUpstream{ln: ln}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.accepted.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return u
}

func loopbackListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// echo answers every byte until the client stops sending.
func echo(c net.Conn) { _, _ = io.Copy(c, c) }

// hold keeps the connection open until the other side closes it.
func hold(c net.Conn) { _, _ = io.Copy(io.Discard, c) }

func tcpCap(name, upstream string) cap.Cap {
	return cap.Cap{Name: name, TCP: &cap.TCP{Upstream: upstream, Port: 27017}}
}

// tcpEnv is a broker relaying one tcp capability from a loopback listener,
// which stands in for the socket ssh forwards the guest port to.
type tcpEnv struct {
	b     *Broker
	audit *safeBuffer
	addr  string
}

func newTCPEnv(t *testing.T, upstream string, grants GrantSource) *tcpEnv {
	t.Helper()
	c := tcpCap("mongo", upstream)
	b, audit := newBroker(t, cap.Set{"mongo": c}, nil)
	b.Grants = grants
	ln := loopbackListener(t)
	if err := b.ServeTCP(c, ln); err != nil {
		t.Fatalf("ServeTCP: %v", err)
	}
	return &tcpEnv{b: b, audit: audit, addr: ln.Addr().String()}
}

func granted(caps ...string) GrantSource {
	set, err := grant.ParseSet(caps)
	if err != nil {
		panic(err)
	}
	return func() (grant.Set, error) { return set, nil }
}

func (e *tcpEnv) dial(t *testing.T) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatalf("dial the relay: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c.(*net.TCPConn)
}

// expectClosed reads until the relay closes the connection and returns what
// arrived before that.
func expectClosed(t *testing.T, c net.Conn) string {
	t.Helper()
	data, err := io.ReadAll(c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the connection stayed open (read %q)", data)
	}
	return string(data)
}

func TestTCPRelaysGrantedConnection(t *testing.T) {
	up := newTCPUpstream(t, loopbackListener(t), echo)
	env := newTCPEnv(t, up.ln.Addr().String(), granted("mongo"))

	c := env.dial(t)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	// Half-close: the upstream must still be able to answer.
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := expectClosed(t, c); got != "ping" {
		t.Errorf("echoed %q, want %q", got, "ping")
	}
	allow := fmt.Sprintf("1970-01-01T00:00:00Z vm=agent1 cap=mongo allow TCP %q\n", up.ln.Addr().String())
	closed := fmt.Sprintf("vm=agent1 cap=mongo close TCP %q sent=4 received=4\n", up.ln.Addr().String())
	waitFor(t, "the audit lines", func() bool {
		log := env.audit.String()
		return strings.Contains(log, allow) && strings.Contains(log, closed)
	})
	if t.Failed() {
		t.Logf("audit log:\n%s", env.audit.String())
	}
}

func TestTCPUpstreamMaySpeakFirst(t *testing.T) {
	// MySQL and SMTP servers greet before the client sends a byte.
	up := newTCPUpstream(t, loopbackListener(t), func(c net.Conn) { _, _ = c.Write([]byte("greeting")) })
	env := newTCPEnv(t, up.ln.Addr().String(), granted("mongo"))

	if got := expectClosed(t, env.dial(t)); got != "greeting" {
		t.Errorf("read %q, want %q", got, "greeting")
	}
}

func TestTCPUnixUpstream(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "skiff-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "db.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	newTCPUpstream(t, ln, func(c net.Conn) { _, _ = c.Write([]byte("from the socket")) })
	env := newTCPEnv(t, "unix:"+socket, granted("mongo"))

	if got := expectClosed(t, env.dial(t)); got != "from the socket" {
		t.Errorf("read %q", got)
	}
}

func TestTCPRefusesUngrantedConnection(t *testing.T) {
	cases := map[string]struct {
		grants GrantSource
		reason string
	}{
		"not granted":       {granted("claude"), "not granted; skiff grant agent1 mongo"},
		"grants unreadable": {func() (grant.Set, error) { return nil, errors.New("disk on fire") }, "grants unreadable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			up := newTCPUpstream(t, loopbackListener(t), echo)
			env := newTCPEnv(t, up.ln.Addr().String(), tc.grants)

			if got := expectClosed(t, env.dial(t)); got != "" {
				t.Errorf("an ungranted connection read %q", got)
			}
			want := fmt.Sprintf("vm=agent1 cap=mongo deny TCP %q %q\n", up.ln.Addr().String(), tc.reason)
			waitFor(t, "the deny line", func() bool { return strings.Contains(env.audit.String(), want) })
			if n := up.accepted.Load(); n != 0 {
				t.Errorf("the upstream saw %d connections, want none", n)
			}
			if t.Failed() {
				t.Logf("audit log:\n%s", env.audit.String())
			}
		})
	}
}

func TestTCPRevokeClosesOpenConnections(t *testing.T) {
	old := tcpGrantCheck
	tcpGrantCheck = 10 * time.Millisecond
	t.Cleanup(func() { tcpGrantCheck = old })

	var revoked atomic.Bool
	grants := func() (grant.Set, error) {
		if revoked.Load() {
			return nil, nil
		}
		return grant.Set{{Cap: "mongo"}}, nil
	}
	up := newTCPUpstream(t, loopbackListener(t), hold)
	env := newTCPEnv(t, up.ln.Addr().String(), grants)

	c := env.dial(t)
	waitFor(t, "the connection to reach the upstream", func() bool { return up.accepted.Load() == 1 })
	revoked.Store(true)
	expectClosed(t, c)
	waitFor(t, "the close line", func() bool {
		return strings.Contains(env.audit.String(), `close TCP "`+up.ln.Addr().String()+`" sent=0 received=0 reason="revoked"`)
	})
	if t.Failed() {
		t.Logf("audit log:\n%s", env.audit.String())
	}
}

func TestTCPRevokeDuringDialCarriesNothing(t *testing.T) {
	// A dial may take seconds. A revoke in that time must not be missed
	// just because the connection was not established yet.
	dialing, release := make(chan struct{}), make(chan struct{})
	old := dialUpstream
	dialUpstream = func(ctx context.Context, network, address string) (net.Conn, error) {
		close(dialing)
		<-release
		return old(ctx, network, address)
	}
	t.Cleanup(func() { dialUpstream = old })

	var revoked atomic.Bool
	grants := func() (grant.Set, error) {
		if revoked.Load() {
			return nil, nil
		}
		return grant.Set{{Cap: "mongo"}}, nil
	}
	up := newTCPUpstream(t, loopbackListener(t), func(c net.Conn) { _, _ = c.Write([]byte("data")) })
	env := newTCPEnv(t, up.ln.Addr().String(), grants)

	c := env.dial(t)
	<-dialing
	revoked.Store(true)
	close(release)
	if got := expectClosed(t, c); got != "" {
		t.Errorf("the guest read %q after the revoke", got)
	}
	waitFor(t, "the deny line", func() bool {
		return strings.Contains(env.audit.String(), `deny TCP "`+up.ln.Addr().String()+`" "not granted; skiff grant agent1 mongo"`)
	})
	if strings.Contains(env.audit.String(), "allow TCP") {
		t.Errorf("a revoked connection must not be allowed:\n%s", env.audit.String())
	}
}

func TestTCPUpstreamDown(t *testing.T) {
	ln := loopbackListener(t)
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there any more
	env := newTCPEnv(t, addr, granted("mongo"))

	if got := expectClosed(t, env.dial(t)); got != "" {
		t.Errorf("read %q from a dead upstream", got)
	}
	want := fmt.Sprintf("vm=agent1 cap=mongo fail TCP %q", addr)
	waitFor(t, "the fail line", func() bool { return strings.Contains(env.audit.String(), want) })
}

func TestTCPLimitsConnections(t *testing.T) {
	old := maxTCPConns
	maxTCPConns = 1
	t.Cleanup(func() { maxTCPConns = old })

	up := newTCPUpstream(t, loopbackListener(t), hold)
	env := newTCPEnv(t, up.ln.Addr().String(), granted("mongo"))

	first := env.dial(t)
	waitFor(t, "the first connection", func() bool { return up.accepted.Load() == 1 })
	expectClosed(t, env.dial(t))
	waitFor(t, "the deny line", func() bool {
		return strings.Contains(env.audit.String(), `deny TCP "`+up.ln.Addr().String()+`" "too many connections"`)
	})
	if n := up.accepted.Load(); n != 1 {
		t.Errorf("the upstream saw %d connections, want 1", n)
	}
	_ = first.Close()
}

func TestBrokerCloseEndsTCPRelay(t *testing.T) {
	up := newTCPUpstream(t, loopbackListener(t), hold)
	env := newTCPEnv(t, up.ln.Addr().String(), granted("mongo"))

	c := env.dial(t)
	waitFor(t, "the connection to reach the upstream", func() bool { return up.accepted.Load() == 1 })
	env.b.Close()
	expectClosed(t, c)
	if again, err := net.DialTimeout("tcp", env.addr, time.Second); err == nil {
		_ = again.Close()
		t.Error("the relay still accepts connections after Close")
	}
	if err := env.b.ServeTCP(tcpCap("mongo", up.ln.Addr().String()), loopbackListener(t)); err == nil {
		t.Error("ServeTCP on a closed broker should fail")
	}
}

func TestServeTCPRacingWithClose(t *testing.T) {
	// Close must wait for a relay that ServeTCP registered just before it;
	// run with -race.
	for i := 0; i < 50; i++ {
		b, _ := newBroker(t, cap.Set{}, []string{"mongo"})
		ln := loopbackListener(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = b.ServeTCP(tcpCap("mongo", "127.0.0.1:1"), ln)
		}()
		b.Close()
		<-done
		b.Close()
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
			_ = c.Close()
			t.Fatal("a relay outlived the broker's Close")
		}
	}
}

// brokenListener fails for good on its first Accept.
type brokenListener struct {
	net.Listener
}

func (brokenListener) Accept() (net.Conn, error) { return nil, errors.New("accept: broken") }

func TestTCPRelayClosesListenerWhenAcceptFails(t *testing.T) {
	b, audit := newBroker(t, cap.Set{}, []string{"mongo"})
	ln := loopbackListener(t)
	if err := b.ServeTCP(tcpCap("mongo", "127.0.0.1:1"), brokenListener{ln}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the listener to be closed", func() bool {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
	if !strings.Contains(audit.String(), "cap mongo: accept: accept: broken") {
		t.Errorf("the failure should be in the audit log:\n%s", audit.String())
	}
}

func TestTCPUnreadableGrantsCloseOpenConnections(t *testing.T) {
	old := tcpGrantCheck
	tcpGrantCheck = 10 * time.Millisecond
	t.Cleanup(func() { tcpGrantCheck = old })

	var broken atomic.Bool
	grants := func() (grant.Set, error) {
		if broken.Load() {
			return nil, errors.New("disk on fire")
		}
		return grant.Set{{Cap: "mongo"}}, nil
	}
	up := newTCPUpstream(t, loopbackListener(t), hold)
	env := newTCPEnv(t, up.ln.Addr().String(), grants)

	c := env.dial(t)
	waitFor(t, "the connection to reach the upstream", func() bool { return up.accepted.Load() == 1 })
	broken.Store(true)
	expectClosed(t, c)
	waitFor(t, "the close line", func() bool {
		return strings.Contains(env.audit.String(), `reason="grants unreadable"`)
	})
	if strings.Contains(env.audit.String(), `reason="revoked"`) {
		t.Errorf("nothing was revoked:\n%s", env.audit.String())
	}
}

func TestServeTCPRejectsOtherKinds(t *testing.T) {
	b, _ := newBroker(t, cap.Set{}, nil)
	ln := loopbackListener(t)
	if err := b.ServeTCP(proxyCap("claude", "https://api.anthropic.com"), ln); err == nil {
		t.Fatal("ServeTCP accepted a proxy capability")
	}
	// The listener is the caller's to hand over; a refusal must not leak it.
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Error("the listener of a refused capability stays open")
	}
}

func TestHTTPRequestForTCPCapIsExplained(t *testing.T) {
	b, _ := newBroker(t, cap.Set{"mongo": tcpCap("mongo", "127.0.0.1:27016")}, []string{"mongo"})
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mongo/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(string(body), "127.0.0.1:27017") {
		t.Errorf("the answer should name the guest port, got %s", body)
	}
	if strings.Contains(string(body), "27016") {
		t.Errorf("the answer must not reveal the upstream, got %s", body)
	}
}
