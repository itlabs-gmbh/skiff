package profile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/guest"
)

var testData = cap.TemplateData{VM: "vm1", BrokerURL: "http://127.0.0.1:7777", PseudoToken: "tok", BrokerSocket: "/run/skiff/broker.sock"}

func TestGuestConfigRendersClaude(t *testing.T) {
	p := mustParse(t, full, "test")
	c, err := p.GuestConfig(testData)
	if err != nil {
		t.Fatalf("GuestConfig: %v", err)
	}
	if c.Name != Owner {
		t.Errorf("owner: %q", c.Name)
	}
	if c.Guest.Env["NODE_OPTIONS"] == "" || c.Guest.Env["CLAUDE_CODE_SYNC_PLUGIN_INSTALL"] != "1" {
		t.Errorf("env: %v", c.Guest.Env)
	}
	if len(c.Guest.Files) != 2 || c.Guest.Files[0].Path != ClaudeSettingsFile || c.Guest.Files[1].Path != CodexConfigFile {
		t.Fatalf("files: %+v", c.Guest.Files)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(c.Guest.Files[0].Content), &doc); err != nil {
		t.Fatalf("drop-in is not JSON: %v\n%s", err, c.Guest.Files[0].Content)
	}
	enabled := doc["enabledPlugins"].(map[string]any)
	if enabled["superpowers@superpowers-marketplace"] != true || enabled["frontend-design@claude-plugins-official"] != true {
		t.Errorf("enabledPlugins: %v", enabled)
	}
	mp := doc["extraKnownMarketplaces"].(map[string]any)["superpowers-marketplace"].(map[string]any)["source"].(map[string]any)
	if mp["source"] != "github" || mp["repo"] != "obra/superpowers-marketplace" {
		t.Errorf("marketplace: %v", mp)
	}
	if doc["permissions"] == nil {
		t.Errorf("settings must be merged into the drop-in: %v", doc)
	}
	if len(c.Guest.JSONMerge) != 1 || c.Guest.JSONMerge[0].Path != ClaudeConfigFile || c.Guest.JSONMerge[0].Key != "mcpServers.context7" {
		t.Errorf("mcp merges: %+v", c.Guest.JSONMerge)
	}
	codex := c.Guest.Files[1].Content
	if !strings.Contains(codex, "approval_policy = \"never\"") || !strings.Contains(codex, "[mcp_servers.context7]") || !strings.Contains(codex, "url = \"https://mcp.context7.com/mcp\"") {
		t.Errorf("codex config:\n%s", codex)
	}
	if len(c.Guest.Blocks) != 0 {
		t.Errorf("no managed blocks expected: %+v", c.Guest.Blocks)
	}
	// The result goes through the same planner as the capabilities.
	plan, err := guest.Render([]cap.Cap{c}, testData)
	if err != nil {
		t.Fatalf("guest.Render: %v", err)
	}
	if len(plan.Files) != 2 || len(plan.Blocks) != 0 || len(plan.Merges) != 1 {
		t.Errorf("plan: %+v", plan)
	}
}

func TestGuestConfigOmitsEmptySections(t *testing.T) {
	p := mustParse(t, "[claude]\n[codex]\n", "test")
	c, err := p.GuestConfig(testData)
	if err != nil {
		t.Fatalf("GuestConfig: %v", err)
	}
	if len(c.Guest.Files) != 0 || len(c.Guest.Blocks) != 0 || len(c.Guest.JSONMerge) != 0 || len(c.Guest.Env) != 0 {
		t.Errorf("nothing should be rendered: %+v", c.Guest)
	}
	// Without plugins the sync variable stays away, and a user value wins.
	p = mustParse(t, "[guest.env]\nCLAUDE_CODE_SYNC_PLUGIN_INSTALL = \"0\"\n[claude]\nplugins = [\"a@claude-plugins-official\"]\n", "test")
	c, _ = p.GuestConfig(testData)
	if c.Guest.Env["CLAUDE_CODE_SYNC_PLUGIN_INSTALL"] != "0" {
		t.Errorf("user env must win: %v", c.Guest.Env)
	}
}

func TestGuestConfigClashesWithCapsAreCaught(t *testing.T) {
	p := mustParse(t, "[claude.mcp.chrome-devtools]\ntype = \"http\"\nurl = \"x\"\n", "test")
	c, _ := p.GuestConfig(testData)
	other := cap.Cap{Name: "chrome-devtools", Guest: cap.Guest{JSONMerge: []cap.JSONMerge{{Path: ClaudeConfigFile, Key: "mcpServers.chrome-devtools", Value: map[string]any{"type": "http"}}}}}
	if _, err := guest.Render([]cap.Cap{other, c}, testData); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Errorf("expected a conflict naming the profile, got %v", err)
	}
}

func TestSetupScript(t *testing.T) {
	p := mustParse(t, full, "test")
	script, err := p.SetupScript(testData)
	if err != nil {
		t.Fatalf("SetupScript: %v", err)
	}
	for _, want := range []string{
		"skiff_setup() {\nset -euo pipefail",
		"}\nskiff_setup </dev/null\n",
		"exists and is not a skiff link",
		"apt-get install -y -q --no-install-recommends 'nodejs' 'npm'",
		"https://claude.ai/install.sh",
		"rm -rf /opt/skiff/skills",
		"git clone -q --depth 1 'https://github.com/anthropics/skills.git' '/opt/skiff/skills/pdf'",
		"git clone -q --depth 1 --branch 'v1.2' 'https://github.com/obra/superpowers.git' '/opt/skiff/skills/superpowers'",
		"test -f '/opt/skiff/skills/pdf/skills/pdf/SKILL.md'",
		"ln -sfn '/opt/skiff/skills/pdf/skills/pdf' '/root/.claude/skills/pdf'",
		"ln -sfn '/opt/skiff/skills/pdf/skills/pdf' '/root/.agents/skills/pdf'",
		"GIT_CONFIG_NOSYSTEM=1",
		"bash -e /root/.skiff-setup.sh",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "npm install -g pnpm") {
		t.Error("the user's setup must travel base64-encoded, not inline")
	}
}

func TestSetupScriptAlwaysRebuildsSkills(t *testing.T) {
	p := mustParse(t, "grants = [\"claude\"]\n[claude.mcp.a]\nurl = \"x\"\n", "test")
	script, err := p.SetupScript(testData)
	if err != nil || !strings.Contains(script, "rm -rf /opt/skiff/skills") || strings.Contains(script, "installing skills") || strings.Contains(script, "apt-get") {
		t.Errorf("a profile without skills must still remove earlier ones, got %q, %v", script, err)
	}
	p = mustParse(t, "[guest]\nsetup = \"echo {{ .VM }}\"\n", "test")
	script, _ = p.SetupScript(testData)
	if !strings.Contains(script, "SKIFF_B64") {
		t.Errorf("setup alone must produce a script: %q", script)
	}
}

func TestToolsAreEmbedded(t *testing.T) {
	if got := strings.Join(Tools(), ","); got != "claude,codex" {
		t.Errorf("Tools() = %s", got)
	}
	if !KnownTool("claude") || KnownTool("../profile") || KnownTool("gemini") {
		t.Error("KnownTool mismatch")
	}
}

func TestGuestConfigRendersQuotedTemplatesBeforeEncoding(t *testing.T) {
	p := mustParse(t, "[claude.settings]\nname = \"{{ printf \\\"%s\\\" .VM }}\"\nliteral = \"keep {{\\\"{{\\\"}} this\"\n[codex.config]\nmodel = \"{{ .VM }}-model\"\n", "test")
	c, err := p.GuestConfig(testData)
	if err != nil {
		t.Fatalf("GuestConfig: %v", err)
	}
	plan, err := guest.Render([]cap.Cap{c}, testData)
	if err != nil {
		t.Fatalf("guest.Render must not re-evaluate the encoded file: %v", err)
	}
	var settings, codex string
	for _, f := range plan.Files {
		switch f.Path {
		case ClaudeSettingsFile:
			settings = f.Content
		case CodexConfigFile:
			codex = f.Content
		}
	}
	if !strings.Contains(settings, `"name": "vm1"`) || !strings.Contains(settings, `"literal": "keep {{ this"`) {
		t.Errorf("settings:\n%s", settings)
	}
	if !strings.Contains(codex, `model = "vm1-model"`) {
		t.Errorf("codex:\n%s", codex)
	}
}
