package profile

// Merge layers over on top of base and returns the result: scalars of over
// win when set, lists are the union in order of first appearance, tables are
// merged key by key with over's entries winning, and setup scripts run one
// after the other. Neither input is changed.
func Merge(base, over Profile) Profile {
	out := Profile{
		Machine: Machine{
			VCPUs:  pick(base.Machine.VCPUs, over.Machine.VCPUs),
			MemMiB: pick(base.Machine.MemMiB, over.Machine.MemMiB),
			Ports:  union(base.Machine.Ports, over.Machine.Ports),
		},
		Grants: union(base.Grants, over.Grants),
		Skills: union(base.Skills, over.Skills),
		Guest: Guest{
			Tools:    union(base.Guest.Tools, over.Guest.Tools),
			Packages: union(base.Guest.Packages, over.Guest.Packages),
			Setup:    joinScripts(base.Guest.Setup, over.Guest.Setup),
			Env:      mergeStrings(base.Guest.Env, over.Guest.Env),
		},
		Claude:  mergeClaude(base.Claude, over.Claude),
		Codex:   mergeCodex(base.Codex, over.Codex),
		Sources: union(base.Sources, over.Sources),
	}
	return out
}

func mergeClaude(base, over *Claude) *Claude {
	if base == nil && over == nil {
		return nil
	}
	b, o := orEmptyClaude(base), orEmptyClaude(over)
	return &Claude{
		Plugins:      union(b.Plugins, o.Plugins),
		Marketplaces: mergeTables(b.Marketplaces, o.Marketplaces),
		MCP:          mergeTables(b.MCP, o.MCP),
		Settings:     deepMerge(b.Settings, o.Settings),
	}
}

func mergeCodex(base, over *Codex) *Codex {
	if base == nil && over == nil {
		return nil
	}
	b, o := orEmptyCodex(base), orEmptyCodex(over)
	return &Codex{
		MCP:    mergeTables(b.MCP, o.MCP),
		Config: deepMerge(b.Config, o.Config),
	}
}

func orEmptyClaude(c *Claude) Claude {
	if c == nil {
		return Claude{}
	}
	return *c
}

func orEmptyCodex(c *Codex) Codex {
	if c == nil {
		return Codex{}
	}
	return *c
}

func pick(base, over int) int {
	if over != 0 {
		return over
	}
	return base
}

// union keeps the order of first appearance and drops duplicates.
func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func joinScripts(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	if a[len(a)-1] != '\n' {
		a += "\n"
	}
	return a + b
}

func mergeStrings(a, b map[string]string) map[string]string {
	if a == nil && b == nil {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// mergeTables replaces whole entries: a marketplace or MCP server declared
// in both files is taken from over.
func mergeTables(a, b map[string]map[string]any) map[string]map[string]any {
	if a == nil && b == nil {
		return nil
	}
	out := make(map[string]map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = copyTable(v)
	}
	for k, v := range b {
		out[k] = copyTable(v)
	}
	return out
}

// deepMerge merges nested tables key by key and joins lists, as the typed
// sections do (a permissions.allow list grows, it is not replaced);
// anything else is replaced.
func deepMerge(a, b map[string]any) map[string]any {
	if a == nil && b == nil {
		return nil
	}
	out := copyTable(a)
	for k, v := range b {
		switch bv := v.(type) {
		case map[string]any:
			if av, ok := out[k].(map[string]any); ok {
				out[k] = deepMerge(av, bv)
				continue
			}
		case []any:
			if av, ok := out[k].([]any); ok {
				out[k] = unionAny(av, bv)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// unionAny joins two lists, dropping later duplicates of comparable values.
func unionAny(a, b []any) []any {
	seen := map[any]bool{}
	out := make([]any, 0, len(a)+len(b))
	for _, v := range append(append([]any(nil), a...), b...) {
		if comparable(v) {
			if seen[v] {
				continue
			}
			seen[v] = true
		}
		out = append(out, v)
	}
	return out
}

// comparable reports whether v can be a map key (scalars, not tables or lists).
func comparable(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return false
	}
	return true
}

func copyTable(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			out[k] = copyTable(sub)
			continue
		}
		out[k] = v
	}
	return out
}
