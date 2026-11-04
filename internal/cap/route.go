package cap

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Route forwards requests that reach the broker for Host instead of under
// /<cap>/ to a second upstream of the same capability. It serves clients that
// can be pointed at a Unix socket but not at a base URL, such as gh with
// http_unix_socket: they keep their real host name and path, and the broker
// picks the route by the Host header. strip_headers and allow_headers of the
// proxy apply to routes as well.
//
// An intercept route also serves clients that insist on https:// to Host:
// the guest resolves Host to the broker, which terminates TLS with the VM's
// intercept CA (see docs/design/credential-intercept.md).
type Route struct {
	// Host is the host name the client sends, without a port.
	Host string `toml:"host"`
	// Upstream is the base URL requests for Host are forwarded to. Intercept
	// routes may leave it empty to mean https://<Host>.
	Upstream string `toml:"upstream"`
	// Headers are set on every upstream request, like proxy.headers.
	Headers map[string]string `toml:"headers"`
	// Intercept makes the broker terminate TLS for Host.
	Intercept bool `toml:"intercept"`
}

// UpstreamURL is where requests for the route go.
func (r Route) UpstreamURL() string {
	if r.Upstream == "" && r.Intercept {
		return "https://" + r.Host
	}
	return r.Upstream
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// routableHost accepts public DNS names only. The guest reaches the broker as
// 127.0.0.1, so a route for a loopback, IP or single-label name would catch
// the requests of every other capability, granted or not.
func routableHost(host string) bool {
	if !hostRe.MatchString(host) || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	return host != "localhost" && !strings.HasSuffix(host, ".localhost")
}

func (p Proxy) validateRoutes() []string {
	var problems []string
	seen := map[string]bool{}
	for i, r := range p.Routes {
		at := fmt.Sprintf("proxy.routes[%d]", i)
		if !routableHost(r.Host) {
			problems = append(problems, at+".host must be a lowercase DNS name with a dot, without port; IPs and localhost are not allowed")
		} else if seen[r.Host] {
			problems = append(problems, fmt.Sprintf("%s: host %s is routed twice", at, r.Host))
		}
		seen[r.Host] = true
		if err := validateUpstream(r.UpstreamURL()); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", at, err))
		}
		problems = append(problems, validateHeaders(at+".headers", r.Headers)...)
		// Without a credential an intercept route only widens what the
		// guest trusts the VM's CA for.
		if r.Intercept && len(r.Headers) == 0 {
			problems = append(problems, at+": an intercept route must inject at least one header")
		}
		// The broker forwards intercepted paths verbatim, which is only
		// safe without a base path to climb out of.
		if u, err := url.Parse(r.UpstreamURL()); r.Intercept && err == nil && u.Path != "" && u.Path != "/" {
			problems = append(problems, at+": an intercept route's upstream must not have a path")
		}
	}
	return problems
}

// validateHeaders checks broker-side header templates.
func validateHeaders(at string, headers map[string]string) []string {
	var problems []string
	for _, k := range sortedKeys(headers) {
		if err := checkTemplate(headers[k], true); err != nil {
			problems = append(problems, fmt.Sprintf("%s.%s: %v", at, k, err))
			continue
		}
		if _, err := SecretRefs(headers[k]); err != nil {
			problems = append(problems, fmt.Sprintf("%s.%s: %v", at, k, err))
		}
	}
	return problems
}

// SecretRefs lists every secret the proxy and its routes send upstream, in
// header order. The templates were validated, so the list is exact.
func (p Proxy) SecretRefs() []string {
	var refs []string
	add := func(headers map[string]string) {
		for _, k := range sortedKeys(headers) {
			r, _ := SecretRefs(headers[k])
			refs = append(refs, r...)
		}
	}
	add(p.Headers)
	for _, r := range p.Routes {
		add(r.Headers)
	}
	return refs
}

// RouteFor finds the capability whose proxy routes host.
func (s Set) RouteFor(host string) (Cap, Route, bool) {
	for _, name := range s.Names() {
		c := s[name]
		if c.Proxy == nil {
			continue
		}
		for _, r := range c.Proxy.Routes {
			if r.Host == host {
				return c, r, true
			}
		}
	}
	return Cap{}, Route{}, false
}

// InterceptHosts lists the hosts the granted capabilities intercept, sorted
// and without duplicates. Unknown names are ignored: a grant may outlive
// the capability file it names.
func (s Set) InterceptHosts(granted []string) []string {
	var hosts []string
	for _, name := range granted {
		c, ok := s[name]
		if !ok || c.Proxy == nil {
			continue
		}
		for _, r := range c.Proxy.Routes {
			if r.Intercept {
				hosts = append(hosts, r.Host)
			}
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// Validate checks rules that span capabilities: a host may be routed by one
// capability only, otherwise a grant for one would decide over the other.
func (s Set) Validate() error {
	owner := map[string]string{}
	var problems []string
	for _, name := range s.Names() {
		c := s[name]
		if c.Proxy == nil {
			continue
		}
		for _, r := range c.Proxy.Routes {
			if other, dup := owner[r.Host]; dup {
				problems = append(problems, fmt.Sprintf("caps %s (%s) and %s (%s) both route %s; remove or edit one of them",
					other, s[other].Source, name, c.Source, r.Host))
				continue
			}
			owner[r.Host] = name
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}
