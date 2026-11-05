package profile

import (
	"strings"
	"testing"
)

func TestParseAllowGrants(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
		set  bool
	}{
		{"absent means no limit", "grants = [\"claude\"]\n", nil, false},
		{"empty list allows nothing", "allow_grants = []\n", []string{}, true},
		{"names", "allow_grants = [\"claude\", \"github\"]\n", []string{"claude", "github"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(c.text, "default")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if (p.AllowGrants != nil) != c.set {
				t.Fatalf("AllowGrants set = %v, want %v (%#v)", p.AllowGrants != nil, c.set, p.AllowGrants)
			}
			if strings.Join(p.AllowGrants, ",") != strings.Join(c.want, ",") {
				t.Errorf("AllowGrants = %v, want %v", p.AllowGrants, c.want)
			}
		})
	}
}

func TestParseRejectsInvalidAllowGrants(t *testing.T) {
	for _, text := range []string{"allow_grants = [\"GitHub\"]\n", "allow_grants = [\"github:repo\"]\n", "allow_grants = \"claude\"\n"} {
		if _, err := Parse(text, "default"); err == nil {
			t.Errorf("Parse(%q) expected an error", text)
		}
	}
}

func TestGrantsOutside(t *testing.T) {
	p := mustParse(t, "grants = [\"claude\", \"github\", \"ssh-agent\"]\n", "repo")
	cases := []struct {
		name    string
		allowed []string
		want    string
	}{
		{"no limit", nil, ""},
		{"nothing allowed", []string{}, "claude,github,ssh-agent"},
		{"some allowed", []string{"claude", "azure"}, "github,ssh-agent"},
		{"all allowed", []string{"ssh-agent", "github", "claude"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := strings.Join(p.GrantsOutside(c.allowed), ","); got != c.want {
				t.Errorf("GrantsOutside(%v) = %q, want %q", c.allowed, got, c.want)
			}
		})
	}
}

func TestAllowGrantsIsPolicyNotContent(t *testing.T) {
	base := mustParse(t, "allow_grants = [\"claude\"]\n", "default")
	if !base.IsZero() {
		t.Error("a file that only limits grants declares nothing to apply")
	}
	over := mustParse(t, "grants = [\"claude\"]\n", "repo")
	if m := Merge(base, over); m.AllowGrants != nil {
		t.Errorf("Merge must not carry allow_grants into the applied profile: %v", m.AllowGrants)
	}
	text, err := base.WithoutPolicy().Encode()
	if err != nil || strings.Contains(text, "allow_grants") {
		t.Errorf("WithoutPolicy().Encode() = %q, %v", text, err)
	}
	if base.AllowGrants == nil {
		t.Error("WithoutPolicy must not change its receiver")
	}
}
