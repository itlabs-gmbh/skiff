package profile

import (
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/sovyn-eu/skiff/internal/cap"
)

// tools are the install scripts skiff ships for agent CLIs, one per name.
// They are data: the vendors' own installers, pinned to a location on PATH.
//
//go:embed tools/*.sh
var tools embed.FS

const (
	// SkillsDir is where skill repositories are cloned in the guest.
	SkillsDir = "/opt/skiff/skills"
	// setupFile is where the user's setup script lands before it runs.
	setupFile = "/root/.skiff-setup.sh"
)

// skillLinkDirs are the directories the agents scan for personal skills.
var skillLinkDirs = []string{"/root/.claude/skills", "/root/.agents/skills"}

// Tools lists the tool names skiff can install.
func Tools() []string {
	entries, _ := fs.ReadDir(tools, "tools")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".sh"))
	}
	sort.Strings(names)
	return names
}

// KnownTool reports whether an install script for name is embedded.
func KnownTool(name string) bool {
	_, err := tools.ReadFile("tools/" + name + ".sh")
	return err == nil && !strings.ContainsAny(name, "/.")
}

// SetupScript renders the bash script that installs packages, tools and
// skills and then runs the profile's own setup, as root in the guest. Skills
// are always rebuilt, so one dropped from the profile disappears even when
// nothing else is installed. The broker is not up while it runs, so nothing
// in it can use a capability; git bypasses /etc/gitconfig for the same
// reason. The script is streamed to `bash -s`, so its body is a function
// called with stdin closed: a command that reads stdin would otherwise eat
// the rest of the script.
func (p Profile) SetupScript(data cap.TemplateData) (string, error) {
	skills, err := ParseSkills(p.Skills)
	if err != nil {
		return "", err
	}
	setup, err := cap.RenderGuest(p.Guest.Setup, data)
	if err != nil {
		return "", fmt.Errorf("guest.setup: %w", err)
	}
	var b strings.Builder
	b.WriteString("skiff_setup() {\nset -euo pipefail\nexport DEBIAN_FRONTEND=noninteractive\n")
	if len(p.Guest.Packages) > 0 {
		b.WriteString("echo '==> installing packages: " + strings.Join(p.Guest.Packages, " ") + "'\n")
		b.WriteString("apt-get update -q\napt-get install -y -q --no-install-recommends")
		for _, pkg := range p.Guest.Packages {
			b.WriteString(" " + shQuote(pkg))
		}
		b.WriteString("\n")
	}
	for _, tool := range p.Guest.Tools {
		script, err := tools.ReadFile("tools/" + tool + ".sh")
		if err != nil {
			return "", fmt.Errorf("unknown tool %q", tool)
		}
		b.WriteString("echo '==> installing " + tool + "'\n")
		b.Write(script)
	}
	writeSkills(&b, skills)
	if strings.TrimSpace(setup) != "" {
		b.WriteString("echo '==> running setup'\n")
		b.WriteString("base64 -d > " + setupFile + " <<'SKIFF_B64'\n" + base64.StdEncoding.EncodeToString([]byte(setup)) + "\nSKIFF_B64\n")
		b.WriteString("bash -e " + setupFile + "\nrm -f " + setupFile + "\n")
	}
	b.WriteString("}\nskiff_setup </dev/null\n")
	return b.String(), nil
}

// writeSkills rebuilds SkillsDir from scratch and links every skill into
// the agents' skill directories; links from an earlier run are removed
// first, so a skill dropped from the profile disappears.
func writeSkills(b *strings.Builder, skills []Skill) {
	if len(skills) > 0 {
		b.WriteString("echo '==> installing skills'\n")
	}
	b.WriteString("rm -rf " + SkillsDir + "\ninstall -d -m 0755 " + SkillsDir + "\n")
	for _, dir := range skillLinkDirs {
		b.WriteString("install -d -m 0755 " + dir + "\n")
		b.WriteString("for l in " + dir + "/*; do if [ -L \"$l\" ]; then case \"$(readlink \"$l\")\" in " + SkillsDir + "/*) rm -f \"$l\";; esac; fi; done\n")
	}
	for _, s := range skills {
		repoDir := path.Join(SkillsDir, s.Name)
		b.WriteString("GIT_CONFIG_NOSYSTEM=1 git clone -q --depth 1")
		if s.Ref != "" {
			b.WriteString(" --branch " + shQuote(s.Ref))
		}
		b.WriteString(" " + shQuote(s.URL) + " " + shQuote(repoDir) + "\n")
		skillDir := path.Join(repoDir, s.Path)
		b.WriteString("test -f " + shQuote(path.Join(skillDir, "SKILL.md")) + " || { echo 'skill " + s.Name + ": no SKILL.md in " + s.URL + "/" + s.Path + "' >&2; exit 1; }\n")
		for _, dir := range skillLinkDirs {
			link := shQuote(path.Join(dir, s.Name))
			b.WriteString("if [ -e " + link + " ] && [ ! -L " + link + " ]; then echo 'skill " + s.Name + ": " + path.Join(dir, s.Name) + " exists and is not a skiff link' >&2; exit 1; fi\n")
			b.WriteString("ln -sfn " + shQuote(skillDir) + " " + link + "\n")
		}
	}
}

// shQuote single-quotes a word for POSIX shells; every value is validated
// to a safe character class already, quoting is defence in depth.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
