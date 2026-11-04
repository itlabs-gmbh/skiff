package broker

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/sovyn-eu/skiff/internal/cap"
)

// credentialHeaders are always removed from the guest's request so a guest
// can never smuggle its own credentials upstream or override the injected ones.
var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "Api-Key", "X-Auth-Token",
	"Private-Token", "X-Github-Token", "X-Goog-Api-Key", "X-Amz-Security-Token", "X-Access-Token",
}

// alwaysKeep survive an allow_headers list because the request is unusable without them.
var alwaysKeep = []string{"Content-Type", "Content-Length", "Content-Encoding", "Accept", "Accept-Encoding"}

// newProxy serves the capability's main upstream, or route's when given.
func (b *Broker) newProxy(c cap.Cap, route *cap.Route) (http.Handler, error) {
	raw, headers := c.Proxy.Upstream, c.Proxy.Headers
	if route != nil {
		raw, headers = route.UpstreamURL(), route.Headers
	}
	upstream, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("cap %s: parse upstream: %w", c.Name, err)
	}
	p := &httputil.ReverseProxy{
		Transport: b.Transport,
		// Flush every write so streamed responses reach the guest as they arrive.
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.URL.Path = joinPath(upstream.Path, r.In.URL.Path)
			r.Out.URL.RawPath = ""
			if route != nil && route.Intercept {
				// cap lint guarantees the upstream has no base path.
				r.Out.URL.Path, r.Out.URL.RawPath = r.In.URL.Path, r.In.URL.RawPath
			}
			r.Out.Host = upstream.Host
			filterHeaders(r.Out.Header, c.Proxy)
			// Rendered credentials travel in the context so they are set
			// after filtering and never appear in the guest-facing request.
			for k, v := range injectedFrom(r.In.Context()) {
				r.Out.Header.Set(k, v)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			b.detail("cap %s: upstream: %v", c.Name, err)
			writeError(w, http.StatusBadGateway, c.Name+": upstream unreachable; see the audit log on the host", "")
		},
	}
	inject := b.headerInjector(headers)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers, err := inject(r)
		if err != nil {
			b.detail("cap %s: %v", c.Name, err)
			writeError(w, http.StatusBadGateway, c.Name+": credential unavailable on the host; see the audit log there", "")
			return
		}
		p.ServeHTTP(w, r.WithContext(withInjected(r.Context(), headers)))
	}), nil
}

// headerInjector renders header templates per request.
func (b *Broker) headerInjector(headers map[string]string) func(*http.Request) (map[string]string, error) {
	return func(r *http.Request) (map[string]string, error) {
		out := make(map[string]string, len(headers))
		for k, tmpl := range headers {
			v, err := cap.Render(tmpl, b.Data, func(ref string) (string, error) {
				return b.Secrets.Resolve(r.Context(), ref)
			})
			if err != nil {
				return nil, fmt.Errorf("header %s: %v", k, err)
			}
			out[k] = v
		}
		return out, nil
	}
}

func filterHeaders(h http.Header, p *cap.Proxy) {
	for _, k := range credentialHeaders {
		h.Del(k)
	}
	for _, k := range p.StripHeaders {
		h.Del(k)
	}
	if len(p.AllowHeaders) == 0 {
		return
	}
	keep := map[string]bool{}
	for _, k := range append(append([]string{}, alwaysKeep...), p.AllowHeaders...) {
		keep[http.CanonicalHeaderKey(k)] = true
	}
	for k := range h {
		if !keep[http.CanonicalHeaderKey(k)] {
			h.Del(k)
		}
	}
}

func joinPath(base, rest string) string {
	base = strings.TrimSuffix(base, "/")
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return base + rest
}
