package profile

import (
	"strings"
	"testing"
)

const full = `
grants = ["claude", "github", "ssh-agent"]
skills = ["anthropics/skills/skills/pdf", "obra/superpowers@v1.2"]

[machine]
vcpus = 4
mem = 4096
ports = ["3000", "8080:80"]

[guest]
tools = ["claude"]
packages = ["nodejs", "npm"]
setup = "npm install -g pnpm\n"
[guest.env]
NODE_OPTIONS = "--max-old-space-size=4096"

[claude]
plugins = ["frontend-design@claude-plugins-official", "superpowers@superpowers-marketplace"]
[claude.marketplaces.superpowers-marketplace]
source = "github"
repo = "obra/superpowers-marketplace"
[claude.mcp.context7]
type = "http"
url = "https://mcp.context7.com/mcp"
[claude.settings.permissions]
allow = ["Bash(go test:*)"]

[codex]
[codex.mcp.context7]
url = "https://mcp.context7.com/mcp"
[codex.config]
approval_policy = "never"
`

func TestParseFullProfile(t *testing.T) {
	p, err := Parse(full, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Machine.VCPUs != 4 || p.Machine.MemMiB != 4096 || len(p.Machine.Ports) != 2 {
		t.Errorf("machine: %+v", p.Machine)
	}
	if strings.Join(p.Grants, ",") != "claude,github,ssh-agent" {
		t.Errorf("grants: %v", p.Grants)
	}
	if p.Claude == nil || len(p.Claude.Plugins) != 2 || p.Claude.MCP["context7"]["url"] != "https://mcp.context7.com/mcp" {
		t.Errorf("claude: %+v", p.Claude)
	}
	if perms, _ := p.Claude.Settings["permissions"].(map[string]any); perms == nil {
		t.Errorf("settings not passed through: %+v", p.Claude.Settings)
	}
	if p.Codex == nil || p.Codex.Config["approval_policy"] != "never" || p.Codex.MCP["context7"] == nil {
		t.Errorf("codex: %+v", p.Codex)
	}
	if p.IsZero() || len(p.Sources) != 1 || p.Sources[0] != "test" {
		t.Errorf("sources: %v zero=%v", p.Sources, p.IsZero())
	}
}

func TestParseEmptyIsZero(t *testing.T) {
	p, err := Parse("", "empty")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.IsZero() {
		t.Errorf("empty profile should be zero: %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "[machine]\ncpus = 2\n",
		"unknown section":      "[gemini]\nx = 1\n",
		"too little memory":    "[machine]\nmem = 512\n",
		"too many vcpus":       "[machine]\nvcpus = 99\n",
		"bad port":             "[machine]\nports = [\"80\"]\n",
		"scoped grant":         "grants = [\"github:repo\"]\n",
		"bad grant name":       "grants = [\"GitHub\"]\n",
		"bad skill":            "skills = [\"nothing\"]\n",
		"duplicate skill name": "skills = [\"a/pdf\", \"b/pdf\"]\n",
		"unknown tool":         "[guest]\ntools = [\"gemini\"]\n",
		"bad package":          "[guest]\npackages = [\"rm -rf\"]\n",
		"bad env name":         "[guest.env]\nfoo = \"x\"\n",
		"env with newline":     "[guest.env]\nFOO = \"a\\nb\"\n",
		"env template typo":    "[guest.env]\nFOO = \"{{ .Nope }}\"\n",
		"setup template typo":  "[guest]\nsetup = \"{{ .Nope }}\"\n",
		"plugin without at":    "[claude]\nplugins = [\"foo\"]\n",
		"market without src":   "[claude.marketplaces.bar]\nrepo = \"x/y\"\n",
		"mcp with dot":         "[claude.mcp.\"a.b\"]\nurl = \"x\"\n",
		"empty mcp":            "[claude.mcp.a]\n",
		"plugins in settings":  "[claude.settings.enabledPlugins]\n\"a@b\" = true\n",
		"settings template":    "[claude.settings]\nx = \"{{ secret \\\"k\\\" }}\"\n",
		"codex mcp in config":  "[codex.config.mcp_servers.a]\nurl = \"x\"\n",
		"codex bad mcp name":   "[codex.mcp.\"a b\"]\nurl = \"x\"\n",
	}
	for name, text := range cases {
		if _, err := Parse(text, name); err == nil {
			t.Errorf("%s: expected an error for %q", name, text)
		}
	}
}

func TestUndeclaredMarketplaceIsOnlyAnErrorAfterMerge(t *testing.T) {
	p, err := Parse("[claude]\nplugins = [\"foo@bar\"]\n", "repo")
	if err != nil {
		t.Fatalf("a single file may reference a marketplace another file declares: %v", err)
	}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Errorf("the merged profile must declare it, got %v", err)
	}
	base := mustParse(t, "[claude.marketplaces.bar]\nsource = \"github\"\nrepo = \"o/bar\"\n", "default")
	if err := Merge(base, p).Validate(); err != nil {
		t.Errorf("declared in the other file: %v", err)
	}
}

func TestParseAcceptsOfficialMarketplaceAndTemplates(t *testing.T) {
	text := "[claude]\nplugins = [\"frontend-design@claude-plugins-official\"]\n[claude.mcp.chrome]\ntype = \"http\"\nurl = \"{{ .BrokerURL }}/chrome-devtools\"\n[guest.env]\nX = \"{{ .VM }}\"\n"
	if _, err := Parse(text, "ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	p, err := Parse(full, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	text, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Parse(text, "roundtrip")
	if err != nil {
		t.Fatalf("Parse(Encode): %v\n%s", err, text)
	}
	if back.Machine.VCPUs != p.Machine.VCPUs || back.Machine.MemMiB != p.Machine.MemMiB || strings.Join(back.Machine.Ports, ",") != strings.Join(p.Machine.Ports, ",") {
		t.Errorf("machine changed: %+v vs %+v", back.Machine, p.Machine)
	}
	if strings.Join(back.Skills, ",") != strings.Join(p.Skills, ",") || strings.Join(back.Claude.Plugins, ",") != strings.Join(p.Claude.Plugins, ",") {
		t.Errorf("lists changed:\n%s", text)
	}
	if back.Codex.Config["approval_policy"] != "never" || back.Claude.MCP["context7"]["type"] != "http" {
		t.Errorf("tables changed:\n%s", text)
	}
	if back.Guest.Setup != p.Guest.Setup {
		t.Errorf("setup changed: %q vs %q", back.Guest.Setup, p.Guest.Setup)
	}
}
