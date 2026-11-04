package cap

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// defaults are the capabilities skiff ships. They are data, not code: a
// user file of the same name in the caps directory replaces them.
//
//go:embed defaults/*.toml
var defaults embed.FS

// SourceEmbedded marks a capability that came from the embedded defaults.
const SourceEmbedded = "embedded"

// ReservedProfile is the owner name under which a VM's profile manages its
// guest configuration; no capability may be called that.
const ReservedProfile = "profile"

// Set is the resolved collection of capabilities, keyed by name.
type Set map[string]Cap

// Parse decodes one TOML document. Unknown keys are errors so typos surface.
func Parse(text string, source string) (Cap, error) {
	var c Cap
	meta, err := toml.Decode(text, &c)
	if err != nil {
		return Cap{}, fmt.Errorf("%s: %w", source, err)
	}
	var unknown []string
	for _, k := range meta.Undecoded() {
		if !insideMergeValue(k) {
			unknown = append(unknown, k.String())
		}
	}
	if len(unknown) > 0 {
		return Cap{}, fmt.Errorf("%s: unknown keys: %s", source, strings.Join(unknown, ", "))
	}
	c.Source = source
	if err := c.Validate(); err != nil {
		return Cap{}, fmt.Errorf("%s: %w", source, err)
	}
	if c.Name == ReservedProfile {
		return Cap{}, fmt.Errorf("%s: the name %q is reserved for VM profiles", source, ReservedProfile)
	}
	return c, nil
}

// insideMergeValue reports whether a key lies under guest.json_merge[].value,
// whose free-form content the decoder reports as undecoded.
func insideMergeValue(k toml.Key) bool {
	for i := 0; i+1 < len(k); i++ {
		if k[i] == "json_merge" && k[i+1] == "value" {
			return true
		}
	}
	return false
}

// ParseFile reads and parses a cap file. The file's base name must match the
// declared name so overrides are unambiguous.
func ParseFile(path string) (Cap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Cap{}, fmt.Errorf("read cap: %w", err)
	}
	c, err := Parse(string(data), path)
	if err != nil {
		return Cap{}, err
	}
	if stem := strings.TrimSuffix(filepath.Base(path), ".toml"); stem != c.Name {
		return Cap{}, fmt.Errorf("%s: declares name %q but the file is called %s.toml", path, c.Name, stem)
	}
	return c, nil
}

// Embedded returns the capabilities shipped with skiff.
func Embedded() (Set, error) {
	set := Set{}
	entries, err := fs.ReadDir(defaults, "defaults")
	if err != nil {
		return nil, fmt.Errorf("read embedded caps: %w", err)
	}
	for _, e := range entries {
		data, err := defaults.ReadFile("defaults/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded cap %s: %w", e.Name(), err)
		}
		c, err := Parse(string(data), SourceEmbedded)
		if err != nil {
			return nil, err
		}
		set[c.Name] = c
	}
	return set, nil
}

// EmbeddedSource returns the TOML text of an embedded capability.
func EmbeddedSource(name string) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := defaults.ReadFile("defaults/" + name + ".toml")
	if err != nil {
		return nil, fmt.Errorf("no embedded capability %q", name)
	}
	return data, nil
}

// Load merges the embedded defaults with the user's cap files in dir. A user
// file wins over an embedded cap of the same name; a broken user file is an
// error rather than silently ignored.
func Load(dir string) (Set, error) {
	set, err := Embedded()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return set, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read caps directory: %w", err)
	}
	merged := make(Set, len(set)+len(entries))
	for k, v := range set {
		merged[k] = v
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		c, err := ParseFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		merged[c.Name] = c
	}
	if err := merged.Validate(); err != nil {
		return nil, err
	}
	return merged, nil
}

// Names returns the capability names in sorted order.
func (s Set) Names() []string {
	names := make([]string, 0, len(s))
	for n := range s {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
