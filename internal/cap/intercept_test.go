package cap

import (
	"slices"
	"strings"
	"testing"
)

const interceptProxy = `
name = "cloud"
[proxy]
upstream = "https://api.cloud.example"
[proxy.headers]
Authorization = "Bearer {{ secret \"env:T\" }}"
[[proxy.routes]]
host = "management.cloud.example"
intercept = true
[proxy.routes.headers]
Authorization = "Bearer {{ secret \"env:MGMT\" }}"
`

func TestParseInterceptRouteDefaultsUpstream(t *testing.T) {
	c, err := Parse(interceptProxy, "t")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := c.Proxy.Routes[0]
	if !r.Intercept {
		t.Fatal("intercept = false")
	}
	if got := r.UpstreamURL(); got != "https://management.cloud.example" {
		t.Errorf("UpstreamURL() = %q, want the route host over https", got)
	}
}

func TestRouteUpstreamURLPrefersDeclaredUpstream(t *testing.T) {
	r := Route{Host: "a.example.com", Upstream: "https://b.example.com/base", Intercept: true}
	if got := r.UpstreamURL(); got != "https://b.example.com/base" {
		t.Errorf("UpstreamURL() = %q", got)
	}
}

func TestParseRejectsBadInterceptRoutes(t *testing.T) {
	tests := []struct {
		name, from, to, want string
	}{
		{"no credential injected", "[proxy.routes.headers]\nAuthorization = \"Bearer {{ secret \\\"env:MGMT\\\" }}\"\n", "", "must inject"},
		{"cleartext upstream", "intercept = true", "intercept = true\nupstream = \"http://management.cloud.example\"", "cleartext"},
		{"ip host", `host = "management.cloud.example"`, `host = "10.0.0.1"`, "proxy.routes[0].host"},
		{"upstream with a path", "intercept = true", "intercept = true\nupstream = \"https://management.cloud.example/base\"", "must not have a path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := strings.Replace(interceptProxy, tt.from, tt.to, 1)
			if text == interceptProxy {
				t.Fatalf("fixture replacement %q did not apply", tt.from)
			}
			_, err := Parse(text, "t")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

// A plain route keeps requiring its upstream; only intercept routes may
// derive it from the host.
func TestParsePlainRouteStillNeedsUpstream(t *testing.T) {
	text := strings.Replace(interceptProxy, "intercept = true\n", "", 1)
	if _, err := Parse(text, "t"); err == nil || !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("want an upstream error, got %v", err)
	}
}

func TestSetInterceptHosts(t *testing.T) {
	cloud, err := Parse(interceptProxy, "t")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	second := strings.Replace(interceptProxy, `name = "cloud"`, `name = "cloud2"`, 1)
	second = strings.Replace(second, "management.cloud.example", "graph.cloud.example", 1)
	cloud2, err := Parse(second, "t")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	forge, err := Parse(routedProxy, "t")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set := Set{"cloud": cloud, "cloud2": cloud2, "forge": forge}
	tests := []struct {
		name    string
		granted []string
		want    []string
	}{
		{"none granted", nil, nil},
		{"plain routes are not intercepted", []string{"forge"}, nil},
		{"one cap", []string{"cloud"}, []string{"management.cloud.example"}},
		{"sorted across caps", []string{"forge", "cloud2", "cloud"}, []string{"graph.cloud.example", "management.cloud.example"}},
		{"unknown cap is ignored", []string{"gone", "cloud"}, []string{"management.cloud.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := set.InterceptHosts(tt.granted); !slices.Equal(got, tt.want) {
				t.Errorf("InterceptHosts(%v) = %v, want %v", tt.granted, got, tt.want)
			}
		})
	}
}

// The skeleton's commented intercept example must be valid once a user
// uncomments it.
func TestSkeletonInterceptExampleParses(t *testing.T) {
	text, err := Skeleton("mything")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	inExample := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "# [[proxy.routes]]") {
			inExample = true
		}
		if inExample && !strings.HasPrefix(line, "# ") {
			inExample = false
		}
		if inExample {
			line = strings.TrimPrefix(line, "# ")
		}
		out = append(out, line)
	}
	c, err := Parse(strings.Join(out, "\n"), "skeleton")
	if err != nil {
		t.Fatalf("uncommented intercept example: %v", err)
	}
	if len(c.Proxy.Routes) != 1 || !c.Proxy.Routes[0].Intercept {
		t.Fatalf("routes = %+v", c.Proxy.Routes)
	}
}
