package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/sovyn-eu/skiff/internal/cap"
)

const (
	// ClaudeSettingsFile is the managed settings drop-in Claude Code reads;
	// a drop-in cannot be edited away by the agent and is merged with the
	// user's own settings.
	ClaudeSettingsFile = "/etc/claude-code/managed-settings.d/50-skiff.json"
	// ClaudeConfigFile holds Claude Code's MCP servers, the same file the
	// capabilities use, so a conflict between a profile and a cap is caught.
	ClaudeConfigFile = "/root/.claude.json"
	// CodexConfigFile is the Codex CLI's configuration. skiff writes the
	// whole file: a block appended behind a table Codex wrote itself would
	// nest the profile's top-level keys under that table.
	CodexConfigFile = "/root/.codex/config.toml"
	// syncPluginInstall makes `claude -p` wait for plugin installation
	// instead of starting the first turn without the plugins.
	syncPluginInstall = "CLAUDE_CODE_SYNC_PLUGIN_INSTALL"
)

// GuestConfig renders the profile's guest-facing sections as a capability
// named Owner, so the same planner that applies grants applies the profile
// and reports a clash between the two. Env and MCP values stay templates
// for the planner; the settings and config files are rendered here, before
// they are encoded, because encoding would escape the quotes inside a
// template, and the encoded text is then protected from the planner.
func (p Profile) GuestConfig(data cap.TemplateData) (cap.Cap, error) {
	c := cap.Cap{Name: Owner, Description: "profile " + strings.Join(p.Sources, " + "), Source: strings.Join(p.Sources, " + ")}
	c.Guest.Env = mergeStrings(nil, p.Guest.Env)
	if p.Claude != nil {
		if len(p.Claude.Plugins) > 0 && c.Guest.Env[syncPluginInstall] == "" {
			if c.Guest.Env == nil {
				c.Guest.Env = map[string]string{}
			}
			c.Guest.Env[syncPluginInstall] = "1"
		}
		settings, err := p.Claude.managedSettings(data)
		if err != nil {
			return cap.Cap{}, err
		}
		if settings != "" {
			c.Guest.Files = append(c.Guest.Files, cap.File{Path: ClaudeSettingsFile, Mode: "0644", Content: literal(settings)})
		}
		for _, name := range sortedKeys(p.Claude.MCP) {
			c.Guest.JSONMerge = append(c.Guest.JSONMerge, cap.JSONMerge{Path: ClaudeConfigFile, Key: "mcpServers." + name, Value: copyTable(p.Claude.MCP[name])})
		}
	}
	if p.Codex != nil {
		text, err := p.Codex.configFile(data)
		if err != nil {
			return cap.Cap{}, err
		}
		if text != "" {
			c.Guest.Files = append(c.Guest.Files, cap.File{Path: CodexConfigFile, Mode: "0600", Content: literal(text)})
		}
	}
	return c, nil
}

// managedSettings renders the drop-in: the free-form settings plus the
// marketplaces and plugins in the keys Claude Code expects. Empty when the
// section declares nothing of the kind.
func (c Claude) managedSettings(data cap.TemplateData) (string, error) {
	doc, err := renderTable(c.Settings, data)
	if err != nil {
		return "", fmt.Errorf("claude.settings: %w", err)
	}
	if len(c.Marketplaces) > 0 {
		marketplaces := map[string]any{}
		for name, source := range c.Marketplaces {
			rendered, err := renderTable(source, data)
			if err != nil {
				return "", fmt.Errorf("claude.marketplaces.%s: %w", name, err)
			}
			marketplaces[name] = map[string]any{"source": rendered}
		}
		doc["extraKnownMarketplaces"] = marketplaces
	}
	if len(c.Plugins) > 0 {
		enabled := map[string]any{}
		for _, plugin := range c.Plugins {
			enabled[plugin] = true
		}
		doc["enabledPlugins"] = enabled
	}
	if len(doc) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return "", fmt.Errorf("render claude settings: %w", err)
	}
	return buf.String(), nil
}

// configFile renders the Codex section as config.toml: the free-form config
// and one [mcp_servers.<name>] per server.
func (c Codex) configFile(data cap.TemplateData) (string, error) {
	doc, err := renderTable(c.Config, data)
	if err != nil {
		return "", fmt.Errorf("codex.config: %w", err)
	}
	if len(c.MCP) > 0 {
		servers := map[string]any{}
		for name, server := range c.MCP {
			rendered, err := renderTable(server, data)
			if err != nil {
				return "", fmt.Errorf("codex.mcp.%s: %w", name, err)
			}
			servers[name] = rendered
		}
		doc["mcp_servers"] = servers
	}
	if len(doc) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString("# written by skiff from the VM's profile; edit the profile and run 'skiff apply'\n")
	if err := toml.NewEncoder(&b).Encode(doc); err != nil {
		return "", fmt.Errorf("render codex config: %w", err)
	}
	return b.String(), nil
}

// renderTable evaluates every template string in a table.
func renderTable(m map[string]any, data cap.TemplateData) (map[string]any, error) {
	v, err := cap.RenderValue(copyTable(m), data)
	if err != nil {
		return nil, err
	}
	out, _ := v.(map[string]any)
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// literal protects already rendered text from the planner's template pass:
// every "{{" becomes a template that prints "{{".
func literal(text string) string {
	return strings.ReplaceAll(text, "{{", `{{"{{"}}`)
}
