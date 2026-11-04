// Package profile describes what a VM needs to work on something: its size,
// the capabilities it is granted, the tools and skills installed in the
// guest, and the plugins and MCP servers of the coding agents inside. A
// profile is a TOML file: ~/.skiff/profile.toml holds the machine default,
// a .skiff file in a repository adds what that repository needs, and both
// are merged for `skiff new`.
package profile

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/sovyn-eu/skiff/internal/cap"
)

const (
	// RepoFile is the profile file skiff looks for in the working directory.
	RepoFile = ".skiff"
	// DefaultFile is the machine default, relative to the skiff home.
	DefaultFile = "profile.toml"
	// Owner is the name under which the profile's guest configuration is
	// managed, like a capability name; cap files may not use it.
	Owner = cap.ReservedProfile
)

// Profile is one profile file, or the merge of several.
type Profile struct {
	Machine Machine  `toml:"machine"`
	Grants  []string `toml:"grants,omitempty"`
	Skills  []string `toml:"skills,omitempty"`
	Guest   Guest    `toml:"guest"`
	Claude  *Claude  `toml:"claude,omitempty"`
	Codex   *Codex   `toml:"codex,omitempty"`

	// Sources lists the files the profile was read from, in merge order.
	Sources []string `toml:"-"`
}

// Machine sizes the VM; zero values mean "not set".
type Machine struct {
	VCPUs  int      `toml:"vcpus,omitzero"`
	MemMiB int      `toml:"mem,omitzero"`
	Ports  []string `toml:"ports,omitempty"`
}

// Guest is what gets installed and set in the VM itself.
type Guest struct {
	// Tools are agent CLIs skiff knows how to install (claude, codex).
	Tools []string `toml:"tools,omitempty"`
	// Packages are apt packages.
	Packages []string `toml:"packages,omitempty"`
	// Setup is a shell script run as root after packages and tools.
	Setup string `toml:"setup,omitempty"`
	// Env is added to /etc/environment.
	Env map[string]string `toml:"env,omitempty"`
}

// Claude configures Claude Code in the guest.
type Claude struct {
	// Plugins are "<plugin>@<marketplace>" entries to enable.
	Plugins []string `toml:"plugins,omitempty"`
	// Marketplaces declares the marketplaces plugins come from, by name; the
	// value is the source object of Claude Code's extraKnownMarketplaces.
	Marketplaces map[string]map[string]any `toml:"marketplaces,omitempty"`
	// MCP declares MCP servers by name, as Claude Code's mcpServers entries.
	MCP map[string]map[string]any `toml:"mcp,omitempty"`
	// Settings is merged verbatim into the managed settings drop-in.
	Settings map[string]any `toml:"settings,omitempty"`
}

// Codex configures the Codex CLI in the guest.
type Codex struct {
	// MCP declares MCP servers by name, as Codex's mcp_servers entries.
	MCP map[string]map[string]any `toml:"mcp,omitempty"`
	// Config is written verbatim into config.toml.
	Config map[string]any `toml:"config,omitempty"`
}

// Parse decodes one profile document. Unknown keys are errors so typos
// surface; the free-form tables (marketplaces, mcp, settings, config) are
// passed through as they are.
func Parse(text, source string) (Profile, error) {
	var p Profile
	meta, err := toml.Decode(text, &p)
	if err != nil {
		return Profile{}, fmt.Errorf("%s: %w", source, err)
	}
	var unknown []string
	for _, k := range meta.Undecoded() {
		if !freeForm(k) {
			unknown = append(unknown, k.String())
		}
	}
	if len(unknown) > 0 {
		return Profile{}, fmt.Errorf("%s: unknown keys: %s", source, strings.Join(unknown, ", "))
	}
	p.Sources = []string{source}
	if err := p.validate(false); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", source, err)
	}
	return p, nil
}

// ParseFile reads and parses a profile file.
func ParseFile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile: %w", err)
	}
	return Parse(string(data), path)
}

// freeForm reports whether a key lies inside a table whose content is not
// skiff's to know: it is handed to the agent as it is.
func freeForm(k toml.Key) bool {
	if len(k) < 2 {
		return false
	}
	switch k[0] {
	case "claude":
		return (k[1] == "settings") || (len(k) > 2 && (k[1] == "marketplaces" || k[1] == "mcp"))
	case "codex":
		return (k[1] == "config") || (len(k) > 2 && k[1] == "mcp")
	}
	return false
}

// IsZero reports whether the profile declares nothing.
func (p Profile) IsZero() bool {
	return p.Machine.VCPUs == 0 && p.Machine.MemMiB == 0 && len(p.Machine.Ports) == 0 &&
		len(p.Grants) == 0 && len(p.Skills) == 0 && p.Guest.isZero() && p.Claude == nil && p.Codex == nil
}

func (g Guest) isZero() bool {
	return len(g.Tools) == 0 && len(g.Packages) == 0 && strings.TrimSpace(g.Setup) == "" && len(g.Env) == 0
}

// Encode renders the profile as TOML, the form Parse reads back.
func (p Profile) Encode() (string, error) {
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(p); err != nil {
		return "", fmt.Errorf("encode profile: %w", err)
	}
	return b.String(), nil
}
