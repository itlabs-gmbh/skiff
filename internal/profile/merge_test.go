package profile

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, text, source string) Profile {
	t.Helper()
	p, err := Parse(text, source)
	if err != nil {
		t.Fatalf("Parse %s: %v", source, err)
	}
	return p
}

func TestMergeLayersRepoOverDefault(t *testing.T) {
	base := mustParse(t, `
grants = ["claude"]
[machine]
vcpus = 2
mem = 2048
ports = ["3000"]
[guest]
tools = ["claude"]
setup = "echo base"
[guest.env]
A = "base"
B = "base"
[claude]
plugins = ["x@m"]
[claude.marketplaces.m]
source = "github"
repo = "o/m"
[claude.settings.permissions]
allow = ["Bash(ls:*)"]
[claude.settings]
model = "sonnet"
`, "default")
	over := mustParse(t, `
grants = ["github", "claude"]
skills = ["a/b"]
[machine]
mem = 4096
ports = ["3000", "8080"]
[guest]
packages = ["jq"]
setup = "echo repo"
[guest.env]
B = "repo"
[claude]
plugins = ["y@m"]
[claude.marketplaces.m]
source = "github"
repo = "o/other"
[claude.settings.permissions]
allow = ["Bash(ls:*)", "Bash(go:*)"]
deny = ["Bash(rm:*)"]
[codex.config]
model = "x"
`, "repo")
	m := Merge(base, over)
	if m.Machine.VCPUs != 2 || m.Machine.MemMiB != 4096 {
		t.Errorf("scalars: %+v", m.Machine)
	}
	if got := strings.Join(m.Machine.Ports, ","); got != "3000,8080" {
		t.Errorf("ports: %s", got)
	}
	if got := strings.Join(m.Grants, ","); got != "claude,github" {
		t.Errorf("grants: %s", got)
	}
	if got := strings.Join(m.Guest.Tools, ",") + "|" + strings.Join(m.Guest.Packages, ","); got != "claude|jq" {
		t.Errorf("guest lists: %s", got)
	}
	if m.Guest.Setup != "echo base\necho repo" {
		t.Errorf("setup: %q", m.Guest.Setup)
	}
	if m.Guest.Env["A"] != "base" || m.Guest.Env["B"] != "repo" {
		t.Errorf("env: %v", m.Guest.Env)
	}
	if got := strings.Join(m.Claude.Plugins, ","); got != "x@m,y@m" {
		t.Errorf("plugins: %s", got)
	}
	if m.Claude.Marketplaces["m"]["repo"] != "o/other" {
		t.Errorf("marketplace should be replaced whole: %v", m.Claude.Marketplaces)
	}
	perms := m.Claude.Settings["permissions"].(map[string]any)
	if perms["allow"] == nil || perms["deny"] == nil || m.Claude.Settings["model"] != "sonnet" {
		t.Errorf("settings should deep-merge: %v", m.Claude.Settings)
	}
	if allow := perms["allow"].([]any); len(allow) != 2 || allow[0] != "Bash(ls:*)" || allow[1] != "Bash(go:*)" {
		t.Errorf("lists inside settings should be joined: %v", allow)
	}
	if m.Codex == nil || m.Codex.Config["model"] != "x" {
		t.Errorf("codex: %+v", m.Codex)
	}
	if got := strings.Join(m.Sources, ","); got != "default,repo" {
		t.Errorf("sources: %s", got)
	}
	if base.Guest.Env["B"] != "base" || len(base.Grants) != 1 {
		t.Error("Merge must not change its inputs")
	}
	if err := m.Validate(); err != nil {
		t.Errorf("merged profile should validate: %v", err)
	}
}

func TestMergeWithEmptySides(t *testing.T) {
	p := mustParse(t, "grants = [\"claude\"]\n", "a")
	if m := Merge(Profile{}, p); strings.Join(m.Grants, ",") != "claude" || m.Claude != nil {
		t.Errorf("merge onto empty: %+v", m)
	}
	if m := Merge(p, Profile{}); strings.Join(m.Grants, ",") != "claude" {
		t.Errorf("merge empty over: %+v", m)
	}
	if m := Merge(Profile{}, Profile{}); !m.IsZero() {
		t.Errorf("two empties: %+v", m)
	}
}
