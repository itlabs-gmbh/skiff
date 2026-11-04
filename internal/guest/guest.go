// Package guest turns the capabilities granted to a microVM into the
// configuration the guest needs: environment variables, files and JSON
// merges. Everything is rendered on the Mac and applied over SSH with plain
// POSIX tools, so the guest image needs nothing skiff-specific.
package guest

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/sovyn-eu/skiff/internal/cap"
)

const (
	// EnvFile is read by pam_env for every SSH session, interactive or not.
	EnvFile = "/etc/environment"
	// ManifestPath lists what skiff manages so revoked caps can be cleaned up.
	ManifestPath = "/etc/skiff/manifest"
	markerBegin  = "# >>> skiff managed, do not edit"
	markerEnd    = "# <<< skiff managed"
)

// Plan is the rendered guest configuration for one VM.
type Plan struct {
	// Relay installs the broker socket relay (see relay.go).
	Relay bool
	// Intercept, when set, installs interception (see intercept.go).
	Intercept *Intercept
	Env       map[string]string
	Files     []cap.File
	Blocks    []Block
	Merges    []cap.JSONMerge
}

// Block is a rendered managed section; Owner is the cap name and part of
// the marker lines so several caps can share one file.
type Block struct {
	Path    string
	Owner   string
	Comment string
	Content string
}

// Render evaluates the guest sections of caps. Conflicting definitions are
// errors: two caps may not set the same variable, file or JSON key.
func Render(caps []cap.Cap, data cap.TemplateData) (Plan, error) {
	plan := Plan{Env: map[string]string{}, Relay: len(caps) > 0}
	envOwner := map[string]string{}
	fileOwner := map[string]string{}
	blockOwner := map[string]string{}
	blockOwners := map[string]bool{}
	keyOwner := map[string]string{}
	for _, c := range caps {
		for _, k := range sortedKeys(c.Guest.Env) {
			if owner, dup := envOwner[k]; dup {
				return Plan{}, fmt.Errorf("caps %s and %s both set %s", owner, c.Name, k)
			}
			v, err := cap.RenderGuest(c.Guest.Env[k], data)
			if err != nil {
				return Plan{}, fmt.Errorf("cap %s: env %s: %w", c.Name, k, err)
			}
			if strings.ContainsAny(v, "\"\n\r") {
				return Plan{}, fmt.Errorf("cap %s: env %s must not contain quotes or newlines", c.Name, k)
			}
			envOwner[k] = c.Name
			plan.Env[k] = v
		}
		for _, f := range c.Guest.Files {
			if isReserved(f.Path) {
				return Plan{}, fmt.Errorf("cap %s: %s is reserved for skiff", c.Name, f.Path)
			}
			if owner, dup := fileOwner[f.Path]; dup {
				return Plan{}, fmt.Errorf("caps %s and %s both write %s", owner, c.Name, f.Path)
			}
			if owner, dup := blockOwner[f.Path]; dup {
				return Plan{}, fmt.Errorf("cap %s manages a block in %s while cap %s writes it as a file", owner, f.Path, c.Name)
			}
			for other, owner := range keyOwner {
				if strings.HasPrefix(other, f.Path+"#") {
					return Plan{}, fmt.Errorf("cap %s merges JSON into %s while cap %s writes it as a file", owner, f.Path, c.Name)
				}
			}
			if err := validatePath(f.Path); err != nil {
				return Plan{}, fmt.Errorf("cap %s: %w", c.Name, err)
			}
			content, err := cap.RenderGuest(f.Content, data)
			if err != nil {
				return Plan{}, fmt.Errorf("cap %s: file %s: %w", c.Name, f.Path, err)
			}
			mode := f.Mode
			if mode == "" {
				mode = "0644"
			}
			fileOwner[f.Path] = c.Name
			plan.Files = append(plan.Files, cap.File{Path: f.Path, Mode: mode, Content: content})
		}
		for _, blk := range c.Guest.Blocks {
			if isReserved(blk.Path) {
				return Plan{}, fmt.Errorf("cap %s: %s is reserved for skiff", c.Name, blk.Path)
			}
			if err := validatePath(blk.Path); err != nil {
				return Plan{}, fmt.Errorf("cap %s: %w", c.Name, err)
			}
			if owner, dup := fileOwner[blk.Path]; dup {
				return Plan{}, fmt.Errorf("cap %s writes %s as a file while cap %s manages a block in it", owner, blk.Path, c.Name)
			}
			if blockOwners[blk.Path+"#"+c.Name] {
				return Plan{}, fmt.Errorf("cap %s declares two blocks for %s", c.Name, blk.Path)
			}
			for other, owner := range keyOwner {
				if strings.HasPrefix(other, blk.Path+"#") {
					return Plan{}, fmt.Errorf("cap %s merges JSON into %s while cap %s manages a block in it", owner, blk.Path, c.Name)
				}
			}
			blockOwners[blk.Path+"#"+c.Name] = true
			content, err := cap.RenderGuest(blk.Content, data)
			if err != nil {
				return Plan{}, fmt.Errorf("cap %s: block %s: %w", c.Name, blk.Path, err)
			}
			comment := blk.Comment
			if comment == "" {
				comment = "#"
			}
			if strings.Contains(content, "skiff:"+c.Name) {
				return Plan{}, fmt.Errorf("cap %s: block %s must not contain its own marker", c.Name, blk.Path)
			}
			blockOwner[blk.Path] = c.Name
			plan.Blocks = append(plan.Blocks, Block{Path: blk.Path, Owner: c.Name, Comment: comment, Content: strings.TrimRight(content, "\n") + "\n"})
		}
		for _, m := range c.Guest.JSONMerge {
			if isReserved(m.Path) {
				return Plan{}, fmt.Errorf("cap %s: %s is reserved for skiff", c.Name, m.Path)
			}
			id := m.Path + "#" + m.Key
			if owner, dup := keyOwner[id]; dup {
				return Plan{}, fmt.Errorf("caps %s and %s both set %s in %s", owner, c.Name, m.Key, m.Path)
			}
			if owner, dup := fileOwner[m.Path]; dup {
				return Plan{}, fmt.Errorf("cap %s writes %s as a file while cap %s merges JSON into it", owner, m.Path, c.Name)
			}
			if owner, dup := blockOwner[m.Path]; dup {
				return Plan{}, fmt.Errorf("cap %s manages a block in %s while cap %s merges JSON into it", owner, m.Path, c.Name)
			}
			for other, owner := range keyOwner {
				if nested(id, other) {
					return Plan{}, fmt.Errorf("caps %s and %s set overlapping keys %s and %s in %s", owner, c.Name, strings.TrimPrefix(other, m.Path+"#"), m.Key, m.Path)
				}
			}
			if err := validatePath(m.Path); err != nil {
				return Plan{}, fmt.Errorf("cap %s: %w", c.Name, err)
			}
			v, err := cap.RenderValue(m.Value, data)
			if err != nil {
				return Plan{}, fmt.Errorf("cap %s: json %s: %w", c.Name, id, err)
			}
			keyOwner[id] = c.Name
			plan.Merges = append(plan.Merges, cap.JSONMerge{Path: m.Path, Key: m.Key, Value: v})
		}
	}
	return plan, nil
}

// Manifest lists what the plan manages, in the format stored in the guest.
func (p Plan) Manifest() []string {
	var lines []string
	if p.Relay {
		lines = append(lines, "file:"+RelaySocketUnit, "file:"+RelayServiceUnit)
	}
	if p.Intercept != nil {
		lines = append(lines, p.Intercept.manifest()...)
	}
	for _, f := range p.Files {
		lines = append(lines, "file:"+f.Path)
	}
	for _, b := range p.Blocks {
		lines = append(lines, "block:"+b.Path+"#"+b.Owner)
	}
	for _, m := range p.Merges {
		lines = append(lines, "json:"+m.Path+"#"+m.Key)
	}
	sort.Strings(lines)
	return lines
}

// pathRe allows only characters that need no quoting in the generated
// scripts. Cap files can come from `skiff cap add`, so a path is
// attacker-influenced input that ends up in a root shell.
var pathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// nested reports whether two path#key ids target the same JSON file and one
// key is an ancestor of the other (settings vs settings.mode).
func nested(a, b string) bool {
	pa, ka, _ := strings.Cut(a, "#")
	pb, kb, _ := strings.Cut(b, "#")
	if pa != pb {
		return false
	}
	return strings.HasPrefix(ka, kb+".") || strings.HasPrefix(kb, ka+".")
}

func validatePath(p string) error {
	if err := validateManifestPath(p); err != nil {
		return err
	}
	// Ownership, conflicts and the relay reservation compare paths as
	// strings, so every file must have exactly one spelling.
	if path.Clean(p) != p {
		return fmt.Errorf("guest path %q must be in canonical form (%s)", p, path.Clean(p))
	}
	return nil
}

// validateManifestPath is the check for paths read back from a guest's
// manifest: safe for the generated root scripts, but without the canonical
// form rule, which older versions did not enforce. Their entries must still
// be cleaned up on revoke instead of being dropped from the manifest.
func validateManifestPath(p string) error {
	if !pathRe.MatchString(p) || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return fmt.Errorf("guest path %q must be absolute and consist of letters, digits, '.', '_', '-' and '/'", p)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
