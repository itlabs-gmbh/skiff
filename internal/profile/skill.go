package profile

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Skill is one entry of the skills list: a git repository and, optionally,
// the directory inside it that holds the SKILL.md.
type Skill struct {
	// Name is the directory name the skill gets in the guest.
	Name string
	// URL is the https clone URL.
	URL string
	// Path is the directory inside the repository, "" for the root.
	Path string
	// Ref is a branch or tag, "" for the default branch.
	Ref string
}

var (
	skillNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	repoPartRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	hostRe      = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]+)?$`)
)

// ParseSkill reads the shorthand "owner/repo[/path/in/repo][@ref]" for a
// GitHub repository, or "https://host/owner/repo[/path][@ref]" for any
// other https git host. The skill's name is the last path element, or the
// repository name when the SKILL.md sits at the root.
func ParseSkill(spec string) (Skill, error) {
	text, ref := spec, ""
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		text, ref = spec[:i], spec[i+1:]
	}
	if strings.ContainsAny(ref, "/@ '") {
		return Skill{}, fmt.Errorf("skill %q: ref %q must be a branch or tag name", spec, ref)
	}
	host := "https://github.com"
	if strings.HasPrefix(text, "https://") {
		u, err := url.Parse(text)
		if err != nil || u.Host == "" || !hostRe.MatchString(u.Host) || u.User != nil {
			return Skill{}, fmt.Errorf("skill %q: not a valid https URL", spec)
		}
		host = "https://" + u.Host
		text = strings.TrimPrefix(u.Path, "/")
	} else if strings.Contains(text, "://") {
		return Skill{}, fmt.Errorf("skill %q: only https URLs are supported", spec)
	}
	parts := strings.Split(strings.Trim(text, "/"), "/")
	if len(parts) < 2 {
		return Skill{}, fmt.Errorf("skill %q: expected owner/repo[/path][@ref]", spec)
	}
	for _, part := range parts {
		if !repoPartRe.MatchString(part) || part == ".." {
			return Skill{}, fmt.Errorf("skill %q: invalid path element %q", spec, part)
		}
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	sub := path.Join(parts[2:]...)
	name := repo
	if sub != "" {
		name = path.Base(sub)
	}
	if !skillNameRe.MatchString(name) {
		return Skill{}, fmt.Errorf("skill %q: cannot derive a name from it", spec)
	}
	return Skill{Name: name, URL: host + "/" + parts[0] + "/" + repo + ".git", Path: sub, Ref: ref}, nil
}

// ParseSkills reads every entry and rejects two skills of the same name,
// which would share one directory in the guest.
func ParseSkills(specs []string) ([]Skill, error) {
	seen := map[string]string{}
	skills := make([]Skill, 0, len(specs))
	for _, spec := range specs {
		s, err := ParseSkill(spec)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[s.Name]; dup {
			return nil, fmt.Errorf("skills %q and %q would both be installed as %q", other, spec, s.Name)
		}
		seen[s.Name] = spec
		skills = append(skills, s)
	}
	return skills, nil
}
