// Command mitm is a spike for skiff: a credential-injecting HTTPS proxy for
// the Azure CLI. The guest's az only ever holds a placeholder token. This
// program on the Mac terminates TLS for allow-listed Azure hosts with a
// name-constrained CA, replaces the placeholder with a real token from the
// Mac's az and forwards the request. See ../README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// route maps an intercepted host (exact, or "*.suffix") to the resource the
// injected token is minted for.
type route struct{ host, resource string }

var routes = []route{
	{"management.azure.com", "https://management.core.windows.net/"},
	{"graph.microsoft.com", "https://graph.microsoft.com/"},
	{"*.vault.azure.net", "https://vault.azure.net"},
	{"*.blob.core.windows.net", "https://storage.azure.com/"},
}

const dialTimeout = 10 * time.Second

func main() {
	sock := flag.String("listen", "", "unix socket to listen on")
	caOut := flag.String("ca-out", "", "file to write the CA certificate to")
	flag.Parse()
	if *sock == "" || *caOut == "" {
		log.Fatal("usage: mitm -listen SOCKET -ca-out FILE")
	}
	ca, err := newAuthority(permittedDomains())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caOut, ca.pem, 0o644); err != nil {
		log.Fatal(err)
	}
	_ = os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*sock, 0o600); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s, CA in %s", *sock, *caOut)
	p := &proxy{ca: ca, tokens: &tokens{}}
	log.Fatal(http.Serve(ln, p))
}

func permittedDomains() []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, strings.TrimPrefix(r.host, "*."))
	}
	return out
}

// resourceFor returns the token resource of an intercepted host.
func resourceFor(host string) (string, bool) {
	for _, r := range routes {
		if suffix, ok := strings.CutPrefix(r.host, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return r.resource, true
			}
		} else if host == r.host {
			return r.resource, true
		}
	}
	return "", false
}

func resourceAllowed(resource string) bool {
	for _, r := range routes {
		if strings.TrimSuffix(r.resource, "/") == strings.TrimSuffix(resource, "/") {
			return true
		}
	}
	return false
}

type proxy struct {
	ca     *authority
	tokens *tokens
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.connect(w, r)
	case r.URL.Path == "/mi":
		p.managedIdentity(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// managedIdentity answers az's App Service token request with a placeholder.
func (p *proxy) managedIdentity(w http.ResponseWriter, r *http.Request) {
	resource := r.URL.Query().Get("resource")
	if !resourceAllowed(resource) {
		log.Printf("mi    refuse resource=%q", resource)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": 400, "message": fmt.Sprintf("skiff: resource %q is not allowed", resource)})
		return
	}
	tok, err := p.tokens.get(r.Context(), resource)
	var ph string
	if err == nil {
		ph, err = placeholder(tok.value)
	}
	if err != nil {
		log.Printf("mi    error resource=%s: %v", resource, err)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"statusCode": 502, "message": "skiff: no token on the host; see the proxy log there"})
		return
	}
	log.Printf("mi    placeholder resource=%s", resource)
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": ph,
		"expires_on":   strconv.FormatInt(tok.expires.Unix(), 10),
		"resource":     resource,
		"token_type":   "Bearer",
	})
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != "443" {
		http.Error(w, "only host:443 is supported", http.StatusBadRequest)
		return
	}
	resource, intercept := resourceFor(strings.ToLower(host))
	var upstream net.Conn
	if !intercept {
		if upstream, err = dialPublic(r, host, port); err != nil {
			log.Printf("pass  refuse %s: %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		log.Printf("hijack %s: %v", r.Host, err)
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		conn.Close()
		return
	}
	if intercept {
		p.intercept(conn, strings.ToLower(host), resource)
		return
	}
	log.Printf("pass  %s", r.Host)
	pipe(conn, upstream)
}

// dialPublic connects to host only when it resolves to public addresses, so
// the guest cannot use the Mac to reach its loopback or LAN.
func dialPublic(r *http.Request, host, port string) (net.Conn, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(r.Context(), host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s failed", host)
	}
	for _, a := range addrs {
		if !isPublic(a.IP) {
			return nil, fmt.Errorf("%s resolves to non-public %s", host, a.IP)
		}
	}
	return net.DialTimeout("tcp", net.JoinHostPort(addrs[0].IP.String(), port), dialTimeout)
}

func isPublic(ip net.IP) bool {
	cgnat := &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || cgnat.Contains(ip))
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); a.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); b.Close() }()
	wg.Wait()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// injector forwards a decrypted request to host with the real token.
func (p *proxy) injector(host, resource string) http.Handler {
	upstream := &url.URL{Scheme: "https", Host: host}
	rp := &httputil.ReverseProxy{
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = host
			r.Out.Header.Set("Authorization", "Bearer "+r.In.Context().Value(tokenKey{}).(string))
		},
		ModifyResponse: func(resp *http.Response) error {
			log.Printf("proxy %s %s%s -> %d", resp.Request.Method, host, resp.Request.URL.Path, resp.StatusCode)
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := p.tokens.get(r.Context(), resource)
		if err != nil {
			log.Printf("proxy %s %s%s: %v", r.Method, host, r.URL.Path, err)
			http.Error(w, "skiff: no token on the host", http.StatusBadGateway)
			return
		}
		rp.ServeHTTP(w, r.WithContext(withToken(r.Context(), tok.value)))
	})
}
