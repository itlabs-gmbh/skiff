package cap

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validProxy = `
name = "example"
description = "test"
[proxy]
upstream = "https://api.example.com"
[proxy.headers]
Authorization = "Bearer {{ secret \"env:EXAMPLE_TOKEN\" }}"
[guest.env]
EXAMPLE_URL = "{{ .BrokerURL }}/example"
`

func TestParseValidProxyCap(t *testing.T) {
	c, err := Parse(validProxy, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Kind() != KindProxy || c.Proxy.Upstream != "https://api.example.com" {
		t.Errorf("unexpected cap: %+v", c)
	}
	if c.Source != "test" {
		t.Errorf("source = %q", c.Source)
	}
}

func TestParseRejectsProblems(t *testing.T) {
	cases := map[string]struct {
		text string
		want string
	}{
		"unknown key": {"bogus = 1\n" + validProxy, "unknown keys: bogus"},
		"bad name":    {strings.Replace(validProxy, `"example"`, `"Bad Name"`, 1), "cap name"},
		"no kind":     {"name = \"x\"\n", "exactly one of"},
		"two kinds":   {validProxy + "\n[mcp]\ncommand = \"x\"\n", "exactly one of"},
		"bad upstream": {strings.Replace(validProxy, "https://api.example.com", "ftp://x", 1),
			"proxy.upstream must be an http(s) URL"},
		"cleartext upstream": {strings.Replace(validProxy, "https://api.example.com", "http://api.example.com", 1),
			"cleartext"},
		"secret in guest": {validProxy + "\n[[guest.files]]\npath = \"/x\"\ncontent = \"{{ secret \\\"env:A\\\" }}\"\n",
			"secret is not available in guest sections"},
		"relative file":  {validProxy + "\n[[guest.files]]\npath = \"x\"\ncontent = \"\"\n", "path must be absolute"},
		"bad mode":       {validProxy + "\n[[guest.files]]\npath = \"/x\"\nmode = \"rw\"\ncontent = \"\"\n", "mode must be octal"},
		"bad env name":   {validProxy + "lower = \"x\"\n", "invalid variable name"},
		"typo in field":  {validProxy + "\n[[guest.files]]\npath = \"/x\"\ncontent = \"{{ .Broker }}\"\n", "Broker"},
		"missing key":    {validProxy + "\n[[guest.json_merge]]\npath = \"/x.json\"\nvalue = 1\n", "key is required"},
		"mcp no command": {"name = \"m\"\n[mcp]\nargs = [\"x\"]\n", "mcp.command is required"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tc.text, "test")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSecretRefsRequireLiterals(t *testing.T) {
	refs, err := SecretRefs(`Bearer {{ secret "keychain:skiff/a" }} {{ if .VM }}{{ secret "env:B" }}{{ end }}`)
	if err != nil || strings.Join(refs, ",") != "keychain:skiff/a,env:B" {
		t.Fatalf("refs = %v, %v", refs, err)
	}
	refs, err = SecretRefs(`{{ define "h" }}{{ secret "env:H" }}{{ end }}{{ template "h" . }}`)
	if err != nil || strings.Join(refs, ",") != "env:H" {
		t.Fatalf("defined templates must be listed: %v, %v", refs, err)
	}
	for _, bad := range []string{
		`{{ secret (print "env:" .VM) }}`,
		`{{ secret .VM }}`,
		`{{ if eq .VM "x" }}{{ secret (printf "%s" "env:A") }}{{ end }}`,
		`{{ "env:A" | secret }}`,
		`{{ call secret "env:A" }}`,
		`{{ range .List }}{{ secret .X }}{{ end }}`,
		`{{ define "h" }}{{ secret .VM }}{{ end }}{{ template "h" . }}`,
		`{{ block "h" . }}{{ secret (print .VM) }}{{ end }}`,
		`{{ (secret .VM) }}`,
		`{{ with .VM }}{{ secret . }}{{ end }}`,
	} {
		if _, err := SecretRefs(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
	// Parse enforces the same rule for capability files.
	dynamic := strings.Replace(validProxy, `{{ secret \"env:EXAMPLE_TOKEN\" }}`, `{{ secret (print \"env:\" .VM) }}`, 1)
	if _, err := Parse(dynamic, "t"); err == nil || !strings.Contains(err.Error(), "literal reference") {
		t.Errorf("dynamic secret references must fail Parse, got %v", err)
	}
}

func TestLoopbackUpstreamMayUseHTTP(t *testing.T) {
	if _, err := Parse(strings.Replace(validProxy, "https://api.example.com", "http://127.0.0.1:4000", 1), "t"); err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
}

func TestEmbeddedDefaultsAreValid(t *testing.T) {
	set, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	for _, name := range []string{"claude", "github"} {
		c, ok := set[name]
		if !ok {
			t.Errorf("missing embedded cap %q", name)
			continue
		}
		if c.Source != SourceEmbedded {
			t.Errorf("%s: source = %q", name, c.Source)
		}
	}
	// GitHub rejects Bearer for git over HTTPS; only Basic works there.
	auth, err := Render(set["github"].Proxy.Headers["Authorization"], lintData,
		func(string) (string, error) { return "tok", nil })
	if err != nil || auth != "Basic eC1hY2Nlc3MtdG9rZW46dG9r" {
		t.Errorf("github Authorization = %q, %v", auth, err)
	}
	// gh reaches the API through the same cap and the same token.
	_, api, ok := set.RouteFor("api.github.com")
	if !ok || api.Upstream != "https://api.github.com" {
		t.Fatalf("github should route api.github.com, got %+v, %v", api, ok)
	}
	if refs := set["github"].Proxy.SecretRefs(); strings.Join(refs, ",") != "keychain:skiff/github-token,keychain:skiff/github-token" {
		t.Errorf("git and gh must share the one token, got %v", refs)
	}
	g := set["github"].Guest
	// gh reads its files on every call, a daemon reads /etc/environment only
	// at start: a token in the environment would miss a later grant.
	if _, ok := g.Env["GH_TOKEN"]; ok {
		t.Errorf("the placeholder belongs in gh's hosts.yml, not in GH_TOKEN")
	}
	blocks := map[string]string{}
	for _, b := range g.Blocks {
		blocks[b.Path] = b.Content
	}
	if !strings.Contains(blocks["/root/.config/gh/config.yml"], "http_unix_socket: {{ .BrokerSocket }}") {
		t.Errorf("gh must be pointed at the broker socket, blocks = %+v", g.Blocks)
	}
	// Already in gh's multi-account shape with a user name, so gh never
	// migrates it, which would ask the API who the user is.
	hosts, err := RenderGuest(blocks["/root/.config/gh/hosts.yml"], TemplateData{PseudoToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"github.com.users.skiff.oauth_token": "tok",
		"github.com.git_protocol":            "https",
		"github.com.user":                    "skiff",
		"github.com.oauth_token":             "tok",
	}
	if got := yamlLeaves(t, hosts); !maps.Equal(got, want) {
		t.Errorf("hosts.yml block has the wrong shape:\n got %v\nwant %v\n%s", got, want, hosts)
	}
}

// yamlLeaves flattens a block-style YAML mapping (no lists, no flow style)
// into dotted key paths of its scalar leaves, so a test can check nesting,
// not just that some text occurs.
func yamlLeaves(t *testing.T, text string) map[string]string {
	t.Helper()
	type level struct {
		indent int
		key    string
	}
	var stack []level
	leaves := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			t.Fatalf("not a mapping line: %q", line)
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		path := key
		if len(stack) > 0 {
			path = stack[len(stack)-1].key + "." + key
		}
		if value = strings.TrimSpace(value); value != "" {
			leaves[path] = value
			continue
		}
		stack = append(stack, level{indent: indent, key: path})
	}
	return leaves
}

func TestYAMLLeavesSeesNesting(t *testing.T) {
	// The token one level too shallow must not pass for users.skiff.oauth_token.
	got := yamlLeaves(t, "github.com:\n    users:\n        skiff:\n    oauth_token: tok\n")
	if _, ok := got["github.com.users.skiff.oauth_token"]; ok || got["github.com.oauth_token"] != "tok" {
		t.Errorf("misnested token read as %v", got)
	}
}

func TestLoadUserFileOverridesEmbedded(t *testing.T) {
	dir := t.TempDir()
	custom := strings.Replace(validProxy, `"example"`, `"claude"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "claude.toml"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set["claude"].Proxy.Upstream != "https://api.example.com" {
		t.Errorf("user file should override embedded claude, got %+v", set["claude"].Proxy)
	}
	if _, ok := set["github"]; !ok {
		t.Errorf("embedded github should still be present")
	}
}

func TestLoadMissingDirUsesDefaults(t *testing.T) {
	set, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(set) == 0 {
		t.Errorf("expected embedded defaults")
	}
}

func TestLoadRejectsNameMismatchAndBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other.toml"), []byte(validProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "file is called other.toml") {
		t.Fatalf("want name mismatch error, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.toml"), []byte("name = [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatalf("broken file must fail Load")
	}
}

func TestRenderGuestAndBrokerTemplates(t *testing.T) {
	data := TemplateData{VM: "agent1", BrokerURL: "http://127.0.0.1:7777", PseudoToken: "abc"}
	got, err := RenderGuest("{{ .BrokerURL }}/claude for {{ .VM }} token {{ .PseudoToken }}", data)
	if err != nil || got != "http://127.0.0.1:7777/claude for agent1 token abc" {
		t.Fatalf("RenderGuest = %q, %v", got, err)
	}
	if _, err := RenderGuest(`{{ secret "env:X" }}`, data); err == nil {
		t.Fatalf("guest templates must not resolve secrets")
	}
	secret := func(ref string) (string, error) { return "resolved:" + ref, nil }
	got, err = Render(`Bearer {{ secret "env:X" }}`, data, secret)
	if err != nil || got != "Bearer resolved:env:X" {
		t.Fatalf("Render = %q, %v", got, err)
	}
	if got, err := Render("plain", data, nil); err != nil || got != "plain" {
		t.Fatalf("plain text should pass through, got %q, %v", got, err)
	}
}

func TestRenderBasicAuth(t *testing.T) {
	data := TemplateData{VM: "v", BrokerURL: "http://b", PseudoToken: "t"}
	secret := func(string) (string, error) { return "tok", nil }
	got, err := Render(`Basic {{ secret "env:X" | basicauth "x-access-token" }}`, data, secret)
	// base64("x-access-token:tok")
	if err != nil || got != "Basic eC1hY2Nlc3MtdG9rZW46dG9r" {
		t.Fatalf("Render = %q, %v", got, err)
	}
	refs, err := SecretRefs(`Basic {{ secret "env:X" | basicauth "x-access-token" }}`)
	if err != nil || strings.Join(refs, ",") != "env:X" {
		t.Fatalf("refs = %v, %v", refs, err)
	}
}

func TestRenderValueWalksStructures(t *testing.T) {
	data := TemplateData{VM: "v", BrokerURL: "http://b", PseudoToken: "t"}
	in := map[string]any{"url": "{{ .BrokerURL }}/x", "list": []any{"{{ .VM }}", 1}, "flag": true}
	out, err := RenderValue(in, data)
	if err != nil {
		t.Fatalf("RenderValue: %v", err)
	}
	m := out.(map[string]any)
	if m["url"] != "http://b/x" || m["list"].([]any)[0] != "v" || m["flag"] != true {
		t.Errorf("unexpected render: %+v", m)
	}
	if in["url"] != "{{ .BrokerURL }}/x" {
		t.Errorf("input must not be mutated")
	}
}

func TestSkeletonParses(t *testing.T) {
	text, err := Skeleton("mything")
	if err != nil {
		t.Fatalf("Skeleton: %v", err)
	}
	if _, err := Parse(text, "skeleton"); err != nil {
		t.Fatalf("skeleton must be a valid cap: %v", err)
	}
	if _, err := Skeleton("Bad"); err == nil {
		t.Fatalf("invalid names must be rejected")
	}
}

func TestSetNamesSorted(t *testing.T) {
	s := Set{"b": {}, "a": {}}
	if got := s.Names(); got[0] != "a" || got[1] != "b" {
		t.Errorf("Names = %v", got)
	}
}

func TestRenderSurfacesResolverError(t *testing.T) {
	data := TemplateData{VM: "v", BrokerURL: "http://b", PseudoToken: "t"}
	secret := func(ref string) (string, error) { return "", errors.New("keychain item missing") }
	_, err := Render(`Bearer {{ secret "keychain:skiff/x" }}`, data, secret)
	if err == nil || err.Error() != "keychain item missing" {
		t.Fatalf("want the resolver's message, got %v", err)
	}
}

func TestExampleCapsAreValid(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "examples", "caps", "*.toml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no example caps found: %v", err)
	}
	for _, f := range files {
		if _, err := ParseFile(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestParseRejectsReservedProfileName(t *testing.T) {
	_, err := Parse("name = \"profile\"\n[proxy]\nupstream = \"https://example.com\"\n", "test")
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("the profile owner name must be reserved, got %v", err)
	}
}
