package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/intercept"
)

const interceptHost = "management.cloud.example"

// seen records what the upstream received.
type seen struct {
	mu                    sync.Mutex
	auth, path, host, raw string
}

func (s *seen) rawPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.raw
}

func (s *seen) get() (auth, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth, s.path
}

type interceptEnv struct {
	broker *Broker
	audit  *safeBuffer
	client *http.Client
	addr   string
	seen   *seen
}

// newInterceptEnv runs a broker with one intercept route on a TCP listener
// and returns a client that trusts the broker's CA, as the guest would.
func newInterceptEnv(t *testing.T, grants []string) *interceptEnv {
	t.Helper()
	s := &seen{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.auth, s.path, s.host, s.raw = r.Header.Get("Authorization"), r.URL.Path, r.Host, r.URL.EscapedPath()
		s.mu.Unlock()
		io.WriteString(w, "upstream")
	}))
	t.Cleanup(upstream.Close)

	c := proxyCap("cloud", "https://api.cloud.example")
	c.Proxy.Routes = []cap.Route{
		{Host: interceptHost, Upstream: upstream.URL, Intercept: true,
			Headers: map[string]string{"Authorization": `Bearer {{ secret "env:TOKEN" }}`}},
		{Host: "plain.cloud.example", Upstream: upstream.URL,
			Headers: map[string]string{"Authorization": `Bearer {{ secret "env:TOKEN" }}`}},
	}
	b, audit := newBroker(t, cap.Set{"cloud": c}, grants)
	b.Transport = upstream.Client().Transport
	dir := t.TempDir()
	ca, _, err := intercept.LoadOrCreate(dir, []string{interceptHost, "plain.cloud.example"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	b.CA = &intercept.Watcher{Dir: dir}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return startInterceptEnv(t, b, audit, ln, ca, s)
}

func startInterceptEnv(t *testing.T, b *Broker, audit *safeBuffer, ln net.Listener, ca *intercept.Authority, s *seen) *interceptEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = Serve(ctx, b.Listener(ln), b.Handler()) }()
	t.Cleanup(func() { cancel(); <-done })

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM())
	addr := ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	t.Cleanup(client.CloseIdleConnections)
	return &interceptEnv{broker: b, audit: audit, client: client, addr: addr, seen: s}
}

func (e *interceptEnv) get(t *testing.T, url, host string) (*http.Response, string, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	req.Header.Set("Authorization", "Bearer placeholder")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

func TestInterceptInjectsCredential(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	resp, body, err := e.get(t, "https://"+interceptHost+"/subscriptions", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || body != "upstream" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	auth, path := e.seen.get()
	if auth != "Bearer real-secret" || path != "/subscriptions" {
		t.Errorf("upstream saw auth=%q path=%q", auth, path)
	}
	// The line is written after the response has gone out.
	waitFor(t, "the audit line", func() bool {
		return strings.Contains(e.audit.String(), `cap=cloud allow GET "/subscriptions" 200 host="`+interceptHost+`"`)
	})
	if t.Failed() {
		t.Logf("audit = %q", e.audit.String())
	}
}

func TestInterceptRefusesHandshake(t *testing.T) {
	tests := []struct {
		name, grant, host string
	}{
		{"cap not granted", "", interceptHost},
		{"unknown host", "cloud", "other.cloud.example"},
		{"plain route is not intercepted", "cloud", "plain.cloud.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var grants []string
			if tt.grant != "" {
				grants = []string{tt.grant}
			}
			e := newInterceptEnv(t, grants)
			if _, _, err := e.get(t, "https://"+tt.host+"/", ""); err == nil {
				t.Fatal("TLS handshake succeeded")
			}
			if log := e.audit.String(); !strings.Contains(log, "deny TLS") || !strings.Contains(log, tt.host) {
				t.Errorf("audit = %q", log)
			}
			if auth, _ := e.seen.get(); auth != "" {
				t.Errorf("upstream was reached with %q", auth)
			}
		})
	}
}

func TestInterceptRejectsHostOtherThanSNI(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	resp, _, err := e.get(t, "https://"+interceptHost+"/", "plain.cloud.example")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status %d, want 421", resp.StatusCode)
	}
	if auth, _ := e.seen.get(); auth != "" {
		t.Errorf("upstream was reached with %q", auth)
	}
}

func TestInterceptRevokeAppliesToOpenConnection(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	var revoked atomic.Bool
	granted, err := grant.ParseSet([]string{"cloud"})
	if err != nil {
		t.Fatal(err)
	}
	e.broker.Grants = func() (grant.Set, error) {
		if revoked.Load() {
			return grant.Set{}, nil
		}
		return granted, nil
	}
	if resp, _, err := e.get(t, "https://"+interceptHost+"/", ""); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("before revoke: %v %v", resp, err)
	}
	revoked.Store(true)
	resp, _, err := e.get(t, "https://"+interceptHost+"/", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after revoke on the kept-alive connection: status %d, want 403", resp.StatusCode)
	}
}

func TestMuxListenerStillServesPlainHTTP(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	resp, body, err := e.get(t, "http://"+e.addr+"/subscriptions", interceptHost)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || body != "upstream" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

// A connection that never sends a byte must not hold up the next client.
func TestMuxListenerDoesNotBlockOnSilentClient(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	silent, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	if resp, _, err := e.get(t, "https://"+interceptHost+"/", ""); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request behind a silent client: %v %v", resp, err)
	}
}

func TestListenerWithoutCAIsUnchanged(t *testing.T) {
	b, _ := newBroker(t, cap.Set{}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := b.Listener(ln); got != ln {
		t.Fatal("a broker without CA wrapped its listener")
	}
}

// tempErr is what Accept returns when, say, the process runs out of file
// descriptors for a moment.
type tempErr struct{}

func (tempErr) Error() string   { return "too many open files" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

type flakyListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, tempErr{}
	}
	return l.Listener.Accept()
}

func TestMuxListenerSurvivesTemporaryAcceptError(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := e.broker.Listener(&flakyListener{Listener: inner})
	defer mux.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := mux.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()
	client, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept after a temporary error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener stopped accepting after a temporary error")
	}
}

func TestMuxListenerDropsStalledHandshake(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = old })
	e := newInterceptEnv(t, []string{"cloud"})
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{tlsHandshakeRecord}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the broker to close a stalled handshake")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("a stalled handshake was kept open")
	}
}

// A first intercept grant while the tunnel is up creates the CA after the
// broker started; the broker must use it without a restart.
func TestInterceptPicksUpCACreatedLater(t *testing.T) {
	c := proxyCap("cloud", "https://api.cloud.example")
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "upstream") }))
	t.Cleanup(upstream.Close)
	c.Proxy.Routes = []cap.Route{{Host: interceptHost, Upstream: upstream.URL, Intercept: true,
		Headers: map[string]string{"Authorization": `Bearer {{ secret "env:TOKEN" }}`}}}
	b, audit := newBroker(t, cap.Set{"cloud": c}, []string{"cloud"})
	b.Transport = upstream.Client().Transport
	dir := t.TempDir()
	b.CA = &intercept.Watcher{Dir: dir}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := intercept.LoadOrCreate(dir, []string{interceptHost}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	e := startInterceptEnv(t, b, audit, ln, ca, &seen{})
	if resp, _, err := e.get(t, "https://"+interceptHost+"/", ""); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request with a CA created after start: %v %v", resp, err)
	}
}

func TestInterceptWithoutCAOnDiskRefusesHandshake(t *testing.T) {
	c := proxyCap("cloud", "https://api.cloud.example")
	c.Proxy.Routes = []cap.Route{{Host: interceptHost, Upstream: "https://127.0.0.1:1", Intercept: true,
		Headers: map[string]string{"Authorization": `Bearer {{ secret "env:TOKEN" }}`}}}
	b, audit := newBroker(t, cap.Set{"cloud": c}, []string{"cloud"})
	b.CA = &intercept.Watcher{Dir: t.TempDir()} // never gets a CA
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The client trusts some CA; the broker has none to present.
	other, _, err := intercept.LoadOrCreate(t.TempDir(), []string{interceptHost}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	e := startInterceptEnv(t, b, audit, ln, other, &seen{})
	if _, _, err := e.get(t, "https://"+interceptHost+"/", ""); err == nil {
		t.Fatal("TLS handshake succeeded without a CA")
	}
	if log := e.audit.String(); !strings.Contains(log, "deny TLS") {
		t.Errorf("audit = %q", log)
	}
}

// Intercepted requests keep their exact path: Graph addresses users by
// UPN (%40) and the broker neither strips a cap name nor adds a base path.
func TestInterceptForwardsEncodedPathVerbatim(t *testing.T) {
	for _, p := range []string{"/v1.0/users/a%40b.example", "/x/a%2Fb/c"} {
		t.Run(p, func(t *testing.T) {
			e := newInterceptEnv(t, []string{"cloud"})
			resp, body, err := e.get(t, "https://"+interceptHost+p, "")
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			if got := e.seen.rawPath(); got != p {
				t.Errorf("upstream saw %q, want %q", got, p)
			}
		})
	}
}

func TestInterceptStillRejectsDotSegments(t *testing.T) {
	e := newInterceptEnv(t, []string{"cloud"})
	conn, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: interceptHost, RootCAs: e.client.Transport.(*http.Transport).TLSClientConfig.RootCAs})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /a/../b HTTP/1.1\r\nHost: "+interceptHost+"\r\nConnection: close\r\n\r\n")
	reply, _ := io.ReadAll(conn)
	if !strings.HasPrefix(string(reply), "HTTP/1.1 400") {
		t.Fatalf("reply = %q", reply)
	}
}

// The server name is the guest's text; it must not be able to forge audit
// lines, e.g. through a resumed session that skips the certificate check.
func TestAuditQuotesServerName(t *testing.T) {
	b, audit := newBroker(t, cap.Set{}, nil)
	r := httptest.NewRequest(http.MethodGet, "https://x/", nil)
	r.TLS = &tls.ConnectionState{ServerName: "evil\n2026-01-01T00:00:00Z vm=agent1 cap=cloud allow"}
	b.audit(r, decision{cap: "cloud", reason: "allow"}, 200)
	if lines := strings.Count(audit.String(), "\n"); lines != 1 {
		t.Fatalf("one request wrote %d audit lines:\n%s", lines, audit.String())
	}
}
