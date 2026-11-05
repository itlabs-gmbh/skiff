package profile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// OfficialMarketplace is the marketplace Claude Code knows without being told.
const OfficialMarketplace = "claude-plugins-official"

var (
	packageRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	envNameRe     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	pluginNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	marketplaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	// mcpNameRe has no dot: the name becomes part of a dotted JSON key.
	mcpNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

	// lintData has every field set so templates with typos fail early.
	lintData = cap.TemplateData{VM: "lint", BrokerURL: "http://127.0.0.1:1", PseudoToken: "lint", BrokerSocket: "/run/lint.sock"}
)

// Validate checks the profile, including references between sections such
// as a plugin's marketplace; the error lists every finding.
func (p Profile) Validate() error {
	return p.validate(true)
}

// validate checks one file (cross is false: a plugin may name a marketplace
// another file declares) or a merged profile (cross is true).
func (p Profile) validate(cross bool) error {
	var problems []string
	problems = append(problems, p.Machine.validate()...)
	for _, g := range p.Grants {
		if _, err := grant.Parse(g); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, g := range p.AllowGrants {
		if _, err := grant.Parse(g); err != nil {
			problems = append(problems, "allow_grants: "+err.Error())
		}
	}
	if _, err := ParseSkills(p.Skills); err != nil {
		problems = append(problems, err.Error())
	}
	problems = append(problems, p.Guest.validate()...)
	if p.Claude != nil {
		problems = append(problems, p.Claude.validate(cross)...)
	}
	if p.Codex != nil {
		problems = append(problems, p.Codex.validate()...)
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("profile: %s", strings.Join(problems, "; "))
}

func (m Machine) validate() []string {
	var problems []string
	if m.VCPUs < 0 || m.VCPUs > vm.MaxVCPUs {
		problems = append(problems, fmt.Sprintf("machine.vcpus must be between 1 and %d, got %d", vm.MaxVCPUs, m.VCPUs))
	}
	if m.MemMiB != 0 && (m.MemMiB < vm.MinMemMiB || m.MemMiB > vm.MaxMemMiB) {
		problems = append(problems, fmt.Sprintf("machine.mem must be between %d and %d MiB, got %d", vm.MinMemMiB, vm.MaxMemMiB, m.MemMiB))
	}
	for _, port := range m.Ports {
		if _, err := vm.ParseForward(port); err != nil {
			problems = append(problems, "machine.ports: "+err.Error())
		}
	}
	return problems
}

func (g Guest) validate() []string {
	var problems []string
	for _, t := range g.Tools {
		if !KnownTool(t) {
			problems = append(problems, fmt.Sprintf("guest.tools: unknown tool %q (known: %s)", t, strings.Join(Tools(), ", ")))
		}
	}
	for _, pkg := range g.Packages {
		if !packageRe.MatchString(pkg) {
			problems = append(problems, fmt.Sprintf("guest.packages: %q is not a package name", pkg))
		}
	}
	if err := checkTemplate(g.Setup); err != nil {
		problems = append(problems, fmt.Sprintf("guest.setup: %v", err))
	}
	for _, k := range sortedKeys(g.Env) {
		if !envNameRe.MatchString(k) {
			problems = append(problems, fmt.Sprintf("guest.env: invalid variable name %q", k))
		}
		if strings.ContainsAny(g.Env[k], "\"\n\r") {
			problems = append(problems, fmt.Sprintf("guest.env.%s must not contain quotes or newlines", k))
		}
		if err := checkTemplate(g.Env[k]); err != nil {
			problems = append(problems, fmt.Sprintf("guest.env.%s: %v", k, err))
		}
	}
	return problems
}

func (c Claude) validate(cross bool) []string {
	var problems []string
	for name := range c.Marketplaces {
		if !marketplaceRe.MatchString(name) || strings.Contains(name, "..") {
			problems = append(problems, fmt.Sprintf("claude.marketplaces: invalid name %q", name))
		}
		if src, ok := c.Marketplaces[name]["source"].(string); !ok || src == "" {
			problems = append(problems, fmt.Sprintf("claude.marketplaces.%s: needs a source, e.g. source = \"github\", repo = \"owner/repo\"", name))
		}
	}
	for _, plugin := range c.Plugins {
		name, marketplace, ok := strings.Cut(plugin, "@")
		if !ok || !pluginNameRe.MatchString(name) || !marketplaceRe.MatchString(marketplace) {
			problems = append(problems, fmt.Sprintf("claude.plugins: %q must be <plugin>@<marketplace>", plugin))
			continue
		}
		if _, known := c.Marketplaces[marketplace]; cross && !known && marketplace != OfficialMarketplace {
			problems = append(problems, fmt.Sprintf("claude.plugins: %q names marketplace %q, which is not declared in [claude.marketplaces.%s]", plugin, marketplace, marketplace))
		}
	}
	problems = append(problems, validateMCP("claude.mcp", c.MCP)...)
	for _, reserved := range []string{"extraKnownMarketplaces", "additionalMarketplaces", "enabledPlugins"} {
		if _, found := c.Settings[reserved]; found {
			problems = append(problems, fmt.Sprintf("claude.settings.%s: use claude.plugins and claude.marketplaces instead", reserved))
		}
	}
	if err := checkValues(c.Settings); err != nil {
		problems = append(problems, fmt.Sprintf("claude.settings: %v", err))
	}
	for name, m := range c.Marketplaces {
		if err := checkValues(m); err != nil {
			problems = append(problems, fmt.Sprintf("claude.marketplaces.%s: %v", name, err))
		}
	}
	return problems
}

func (c Codex) validate() []string {
	problems := validateMCP("codex.mcp", c.MCP)
	if _, found := c.Config["mcp_servers"]; found {
		problems = append(problems, "codex.config.mcp_servers: use [codex.mcp.<name>] instead")
	}
	if err := checkValues(c.Config); err != nil {
		problems = append(problems, fmt.Sprintf("codex.config: %v", err))
	}
	return problems
}

func validateMCP(section string, servers map[string]map[string]any) []string {
	var problems []string
	for name, server := range servers {
		if !mcpNameRe.MatchString(name) {
			problems = append(problems, fmt.Sprintf("%s: invalid server name %q", section, name))
		}
		if len(server) == 0 {
			problems = append(problems, fmt.Sprintf("%s.%s: needs command or url", section, name))
		}
		if err := checkValues(server); err != nil {
			problems = append(problems, fmt.Sprintf("%s.%s: %v", section, name, err))
		}
	}
	return problems
}

// checkTemplate dry-runs a guest template so a typo is reported by lint,
// not by the first VM.
func checkTemplate(text string) error {
	_, err := cap.RenderGuest(text, lintData)
	return err
}

func checkValues(m map[string]any) error {
	_, err := cap.RenderValue(m, lintData)
	return err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
