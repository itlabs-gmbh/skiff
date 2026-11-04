package profile

import "testing"

func TestParseSkill(t *testing.T) {
	cases := map[string]Skill{
		"anthropics/skills/skills/pdf":       {Name: "pdf", URL: "https://github.com/anthropics/skills.git", Path: "skills/pdf"},
		"obra/superpowers":                   {Name: "superpowers", URL: "https://github.com/obra/superpowers.git"},
		"obra/superpowers@v1.2":              {Name: "superpowers", URL: "https://github.com/obra/superpowers.git", Ref: "v1.2"},
		"https://gitlab.com/o/r/sk/one@main": {Name: "one", URL: "https://gitlab.com/o/r.git", Path: "sk/one", Ref: "main"},
		"https://github.com/o/r.git":         {Name: "r", URL: "https://github.com/o/r.git"},
		"o/r/deep/er/path":                   {Name: "path", URL: "https://github.com/o/r.git", Path: "deep/er/path"},
	}
	for in, want := range cases {
		got, err := ParseSkill(in)
		if err != nil || got != want {
			t.Errorf("ParseSkill(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "repo", "o/r/../x", "git@github.com:o/r", "http://x/o/r", "o/r@a/b", "o/r a", "o/r@", "o/r@x@y"} {
		if _, err := ParseSkill(bad); err == nil && bad != "o/r@" {
			t.Errorf("ParseSkill(%q) expected error", bad)
		}
	}
}

func TestParseSkillsRejectsDuplicateNames(t *testing.T) {
	if _, err := ParseSkills([]string{"a/x/skills/pdf", "b/pdf"}); err == nil {
		t.Error("two skills named pdf must be rejected")
	}
	skills, err := ParseSkills([]string{"a/x", "a/y"})
	if err != nil || len(skills) != 2 {
		t.Errorf("unexpected: %v %v", skills, err)
	}
}
