package profile

// Skeleton is a commented starting point for a profile file.
const Skeleton = `# skiff profile (TOML). A .skiff file in a repository says what a VM for
# that repository needs; ~/.skiff/profile.toml is the machine default and
# applies to every VM. 'skiff new' merges both: lists are joined, tables
# merged, and a value set in .skiff wins.
#
#   skiff profile show            # the merged result (--render: what the guest gets)
#   skiff profile trust           # accept a repository's .skiff as it is now
#   skiff new                     # a VM from it (flags still win)
#   skiff apply <vm>              # re-apply after editing (--setup to rerun installs)

# Capabilities to grant, as with 'skiff grant' (see 'skiff cap ls').
# grants = ["claude", "github"]

# Only in ~/.skiff/profile.toml: the grants a repository's .skiff (or a
# --profile file) may ask for, however often it is trusted. No key: no
# limit; [] allows none. --grant and 'skiff grant' are not limited.
# allow_grants = ["claude", "github"]

# Skills (folders with a SKILL.md) from public git repositories, cloned at
# setup and linked for Claude Code and Codex: owner/repo[/path][@ref] on
# GitHub, or a full https URL.
# skills = ["anthropics/skills/skills/pdf"]

[machine]
# vcpus = 4
# mem = 4096                      # MiB
# ports = ["3000", "8080:80"]     # like 'skiff new -p'

[guest]
# tools = ["claude"]              # agent CLIs skiff knows how to install (claude, codex)
# packages = ["nodejs", "npm"]    # apt
# setup = """
# npm install -g pnpm
# """
# [guest.env]
# NODE_OPTIONS = "--max-old-space-size=4096"

# [claude]
# plugins = ["frontend-design@claude-plugins-official", "superpowers@superpowers-marketplace"]
# [claude.marketplaces.superpowers-marketplace]
# source = "github"
# repo = "obra/superpowers-marketplace"
# [claude.mcp.context7]
# type = "http"
# url = "https://mcp.context7.com/mcp"
# [claude.settings.permissions]
# allow = ["Bash(go test:*)"]

# [codex]
# [codex.mcp.context7]
# url = "https://mcp.context7.com/mcp"
# [codex.config]
# approval_policy = "never"
# sandbox_mode = "danger-full-access"
`
