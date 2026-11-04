// Package broker is the one controlled hole in a microVM's isolation. It
// listens on a per-VM Unix socket on the Mac (tunnelled into the guest by
// `skiff ssh -R`), checks the VM's grants and hands out connections,
// never secrets. It knows three primitives; everything else is a cap file.
package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/intercept"
)

// SecretResolver resolves cap secret references.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// CASource yields the VM's current intercept CA, or nil when it has none.
// It is consulted per handshake, so a CA that a grant creates or re-issues
// while the tunnel is up applies without a restart.
type CASource interface {
	Current() (*intercept.Authority, error)
}

// GrantSource returns the VM's current grants; it is consulted per request so
// a `skiff grant` or `revoke` in another terminal applies to the next
// request of an already running broker.
type GrantSource func() (grant.Set, error)

// Broker serves one microVM.
type Broker struct {
	VM      string
	Caps    cap.Set
	Grants  GrantSource
	Secrets SecretResolver
	// Audit receives one line per request.
	Audit io.Writer
	// Data is the template data the guest was provisioned with.
	Data cap.TemplateData
	// Warn receives host-side problems that must not go unnoticed but have
	// no better channel, such as a failing audit log. Nil discards them.
	Warn func(string)
	// Transport overrides the upstream transport (tests).
	Transport http.RoundTripper
	// CA yields the VM's intercept CA for TLS on intercept routes; nil
	// disables interception and leaves the listener untouched.
	CA CASource
	// Now is the audit clock.
	Now func() time.Time

	mu       sync.Mutex
	handlers map[string]http.Handler
	bridges  []*mcpBridge
	log      *syncWriter
	closed   bool
	warnOnce sync.Once
}

// syncWriter serialises writes from request handlers and MCP child stderr
// copiers onto one audit writer.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// logger returns the shared audit writer, or nil when auditing is off.
func (b *Broker) logger() io.Writer {
	if b.Audit == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.log == nil {
		b.log = &syncWriter{w: b.Audit}
	}
	return b.log
}

// Handler returns the HTTP handler for the socket.
func (b *Broker) Handler() http.Handler {
	return http.HandlerFunc(b.serve)
}

// Close stops child processes started for MCP caps.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for _, br := range b.bridges {
		br.stop()
	}
	b.bridges = nil
	b.handlers = nil
}

// detail writes a host-side diagnostic to the audit log. Guests only ever see
// generic messages, so paths, commands and item names stay on the Mac.
func (b *Broker) detail(format string, args ...any) {
	if log := b.logger(); log != nil {
		fmt.Fprintf(log, "  "+format+"\n", args...)
	}
}

type decision struct {
	cap    string
	status int
	reason string
}

func (b *Broker) serve(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	d := b.dispatch(rec, r)
	b.audit(r, d, rec.status)
}

// dispatch routes /<cap>/<rest>, or a request for a host a proxy route
// claims, and enforces grants.
func (b *Broker) dispatch(w http.ResponseWriter, r *http.Request) decision {
	if reason := unsafePath(r.URL); reason != "" {
		writeError(w, http.StatusBadRequest, reason, "")
		return decision{status: http.StatusBadRequest, reason: "unsafe path"}
	}
	t, d, ok := b.locate(w, r)
	if !ok {
		return d
	}
	name := t.cap.Name
	grants, err := b.Grants()
	if err != nil {
		b.detail("grants of %s unreadable: %v", b.VM, err)
		writeError(w, http.StatusInternalServerError, "the broker could not read this VM's grants; see the audit log on the host", "")
		return decision{cap: name, status: http.StatusInternalServerError, reason: "grants"}
	}
	if !grants.Contains(grant.Grant{Cap: name}) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("%s is not granted to %s", name, b.VM), grant.Hint(b.VM, name))
		return decision{cap: name, status: http.StatusForbidden, reason: "denied"}
	}
	h, err := b.handlerFor(t.cap, t.route)
	if err != nil {
		b.detail("cap %s: %v", name, err)
		writeError(w, http.StatusInternalServerError, "the broker could not set up this capability; see the audit log on the host", "")
		return decision{cap: name, status: http.StatusInternalServerError, reason: "setup"}
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = t.rest
	r2.URL.RawPath = ""
	h.ServeHTTP(w, r2)
	return decision{cap: name, reason: "allow"}
}

// target is where a request goes: a capability, the route it came in by (nil
// for /<cap>/ requests) and the path to forward.
type target struct {
	cap   cap.Cap
	route *cap.Route
	rest  string
}

// locate resolves the request's target, answering it itself when there is none.
func (b *Broker) locate(w http.ResponseWriter, r *http.Request) (target, decision, bool) {
	if r.TLS != nil {
		return b.locateIntercepted(w, r)
	}
	if c, rt, ok := b.Caps.RouteFor(requestHost(r)); ok {
		return target{cap: c, route: &rt, rest: r.URL.Path}, decision{}, true
	}
	name, rest := splitCap(r.URL.Path)
	if name == "" {
		writeError(w, http.StatusNotFound, "no capability in path; the broker serves /<cap>/...", "skiff cap ls")
		return target{}, decision{status: http.StatusNotFound, reason: "no cap"}, false
	}
	c, ok := b.Caps[name]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown capability %q", name), "skiff cap ls")
		return target{}, decision{cap: name, status: http.StatusNotFound, reason: "unknown cap"}, false
	}
	return target{cap: c, rest: rest}, decision{}, true
}

// requestHost is the Host header without port, lowercased.
func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

func (b *Broker) handlerFor(c cap.Cap, route *cap.Route) (http.Handler, error) {
	key := c.Name
	if route != nil {
		key += "@" + route.Host
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, fmt.Errorf("broker is closed")
	}
	if h, ok := b.handlers[key]; ok {
		return h, nil
	}
	var h http.Handler
	var err error
	switch c.Kind() {
	case cap.KindProxy:
		h, err = b.newProxy(c, route)
	case cap.KindMCP:
		br := newMCPBridge(c, b.childLog())
		b.bridges = append(b.bridges, br)
		h = br
	case cap.KindExec:
		h = b.newExec(c)
	default:
		err = fmt.Errorf("capability %q has no primitive", c.Name)
	}
	if err != nil {
		return nil, err
	}
	if b.handlers == nil {
		b.handlers = map[string]http.Handler{}
	}
	b.handlers[key] = h
	return h, nil
}

// unsafePath rejects every path on which the broker and an upstream could
// disagree. The capability is taken from the decoded path and the rest is
// appended to the upstream's base path, so the path must have exactly one
// reading: no percent-encoding at all (upstreams decode %2F, %2E or double
// encoding differently), no backslashes (some servers treat them as
// separators) or NUL, no dot segments that could climb out of the base path,
// no empty segments, and no difference from its cleaned form.
func unsafePath(u *url.URL) string {
	if strings.Contains(u.EscapedPath(), "%") || strings.Contains(u.RawPath, "%") {
		return "percent-encoded characters are not allowed in capability paths"
	}
	if strings.ContainsAny(u.Path, "\\\x00") {
		return "backslashes and NUL are not allowed in capability paths"
	}
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for i, seg := range segments {
		if seg == "." || seg == ".." {
			return "dot segments are not allowed in capability paths"
		}
		if seg == "" && i < len(segments)-1 {
			return "empty path segments are not allowed in capability paths"
		}
	}
	if cleaned := path.Clean(u.Path); cleaned != u.Path && cleaned+"/" != u.Path {
		return "path is not in canonical form"
	}
	return ""
}

// splitCap separates the capability name from the rest of the path.
func splitCap(path string) (name, rest string) {
	trimmed := strings.TrimPrefix(path, "/")
	name, rest, _ = strings.Cut(trimmed, "/")
	if err := cap.ValidateName(name); err != nil {
		return "", ""
	}
	return name, "/" + rest
}

func (b *Broker) audit(r *http.Request, d decision, status int) {
	log := b.logger()
	if log == nil {
		return
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	// %q keeps a decoded newline in the path from forging a log line.
	host := ""
	if r.TLS != nil {
		host = " host=" + strings.ToLower(r.TLS.ServerName)
	}
	_, err := fmt.Fprintf(log, "%s vm=%s cap=%s %s %s %q %d%s\n",
		now().UTC().Format(time.RFC3339), b.VM, orDash(d.cap), d.reason, r.Method, r.URL.Path, status, host)
	b.auditFailed(err)
}

// auditFailed warns once that the audit log is no longer written.
func (b *Broker) auditFailed(err error) {
	if err != nil {
		b.warnOnce.Do(func() {
			if b.Warn != nil {
				b.Warn(fmt.Sprintf("audit log for %s is not being written (%v); decisions since are unrecorded", b.VM, err))
			}
		})
	}
}

// childLog is the writer MCP children's stderr goes to. handlerFor holds mu,
// so the shared writer is created without taking it again.
func (b *Broker) childLog() io.Writer {
	if b.Audit == nil {
		return nil
	}
	if b.log == nil {
		b.log = &syncWriter{w: b.Audit}
	}
	return b.log
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming responses (SSE) flowing through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeError(w http.ResponseWriter, status int, message, hint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{"error": message}
	if hint != "" {
		body["hint"] = hint
	}
	_ = json.NewEncoder(w).Encode(body)
}
