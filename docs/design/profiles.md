# Design: profiles (what a VM needs)

Status: implemented 2026-11-04.

Decision sought: how a VM gets everything an agent needs to work on a
repository (size, grants, tools, skills, plugins, MCP servers) from one
declaration instead of a hand-run script after every `skiff new`, with a
machine-wide default and a per-repository file.

## Why

A fresh skiff VM is a plain Ubuntu. Capabilities bring credentials, but the
agent's toolchain (Claude Code, Codex, Node, Go), its plugins and skills and
the MCP servers it should see were installed by hand, or by every tool that
drives skiff (bb, paseo) in its own way. The spike of 2026-10-28 showed that
Claude Code installs plugins by itself when a managed-settings drop-in names
a marketplace and enables them, so a declarative file is enough for the
agent side too.

## Shape

Two TOML files, same format, merged for `skiff new`:

| File                   | Meaning                                  |
|------------------------|------------------------------------------|
| `~/.skiff/profile.toml`| machine default, every VM                |
| `./.skiff`             | what this repository needs, committed    |

Merge: scalars from `.skiff` win, lists are the union in order of first
appearance, tables (marketplaces, MCP servers) are replaced per key, the
free-form settings tables are deep-merged, and the two setup scripts run one
after the other. The merged profile is stored with the VM
(`~/.skiff/vms/<vm>/profile.toml`), so later `grant`/`revoke` re-render it
and `rm` removes it.

Sections and where they land:

| Section            | Lands as                                                                 |
|--------------------|--------------------------------------------------------------------------|
| `[machine]`        | `skiff new` defaults; explicit flags win                                 |
| `grants`           | `skiff grant`, together with `--grant`                                   |
| `skills`           | setup: `git clone` into `/opt/skiff/skills/<name>`, symlinks in `/root/.claude/skills` and `/root/.agents/skills` |
| `[guest]`          | setup: apt packages, embedded install scripts for `tools`, the `setup` script; `env` into `/etc/environment` |
| `[claude]`         | plugins, marketplaces and settings as one managed drop-in `/etc/claude-code/managed-settings.d/50-skiff.json`; MCP servers as `json_merge` into `/root/.claude.json` |
| `[codex]`          | `/root/.codex/config.toml`, written whole: free-form config plus `[mcp_servers.<name>]` |

## Decisions

- **One planner.** The profile's guest sections are rendered as a
  pseudo-capability named `profile` (reserved) and go through
  `guest.Render` with the granted caps. That gives conflict detection (a
  cap and a profile both defining `mcpServers.context7` is an error),
  manifest-based cleanup when a section disappears, and the same template
  data. The relay is tied to the real grants, not the pseudo-cap.
- **A repository file needs trust.** A `.skiff` is attacker-controlled
  input: it asks for grants that apply to everything the VM runs later,
  forwards host ports and runs a script as root. `new` and `apply` refuse
  it until `skiff profile trust` (or `--trust`) has recorded its sha256 and
  absolute path in `~/.skiff/trusted`, as direnv does; an edit withdraws
  the trust. The refusal lists what the file would do. The machine default
  is the user's own file and needs none.
- **Setup before grants, without the broker, outside the lock.** The setup
  runs over plain ssh right after boot, before any grant exists and never
  with a tunnel, so a script cannot reach a credential while it runs (what
  it installs can, once the grants are made; hence the trust above). While
  it runs, skiff owns the VM's broker claim: an open session or tunnel makes
  `apply --setup` refuse, a session started meanwhile gets its shell at once
  but its broker only when the setup ends (standby), and a second setup
  cannot interleave with the first. It runs before the VM's
  grant lock is taken, because `new` and `gc` wait on every VM's lock and a
  setup takes minutes; a clash between profile and grants is rendered and
  rejected before the setup starts. The script body is a function called
  with stdin closed: `bash -s` reads the script from stdin, and a command
  that read stdin would eat the rest of it. Skills are cloned with
  `GIT_CONFIG_NOSYSTEM=1` so the github cap's `insteadOf` rewrite does not
  send the clone to a broker that is not there.
- **Managed drop-in for plugins, not user settings.** Claude Code merges
  `managed-settings.d/*.json` alphabetically and installs
  `enabledPlugins` from `extraKnownMarketplaces` at the start of the next
  session. The user's own `~/.claude/settings.json` stays the agent's;
  skiff's file is skiff's. The drop-in cannot be edited away by the agent,
  which is what a profile means. `CLAUDE_CODE_SYNC_PLUGIN_INSTALL=1` is set
  when plugins are declared so `claude -p` waits for the install.
- **Settings are rendered before they are encoded.** A template inside a
  settings value contains quotes that JSON or TOML encoding would escape;
  so the free-form tables are rendered with the VM's data first, and the
  encoded file is handed to the planner with its braces escaped. Env values
  and Claude MCP entries stay templates, as in capability files.
- **Skills by clone and symlink, not by marketplace.** Both agents scan a
  personal skills directory; a symlink there needs no plugin machinery,
  works offline after setup, and the same clone serves Codex (which has no
  declarative install). The cost: private repositories are out (no broker
  during setup), and a changed skill needs `apply --setup`.
- **Codex gets a whole file, not a managed block.** A block is appended
  behind whatever the file holds; behind a `[projects."/x"]` table Codex
  wrote itself, the profile's top-level keys would nest under that table.
  So skiff owns `config.toml` while `[codex]` is set, and the manifest
  removes it when the section goes.
- **Per-file syntax, merged semantics.** Each file is checked on its own
  for unknown keys, names and templates; a plugin's marketplace may be
  declared in the other file, so that reference is checked after the merge.
- **Free-form tables pass through.** `claude.settings`, `codex.config`,
  the marketplace sources and MCP entries are not modelled: skiff validates
  names and templates and hands the rest to the agent as it is, so new
  agent options need no skiff release. The keys skiff fills itself
  (`enabledPlugins`, `extraKnownMarketplaces`, `mcp_servers`) are rejected
  in the free-form tables.
- **Tools are embedded data.** `tools = ["claude", "codex"]` runs the
  vendors' install scripts from `internal/profile/tools/*.sh`, pinned to
  `/usr/local/bin` so non-interactive ssh sessions find them.
- **Grants only grow.** `apply` adds the profile's grants and never
  revokes; removing a grant is a deliberate `skiff revoke`.

## Non-goals

- Image variants or snapshots. Setup runs in the fresh VM every time; a
  cached image is a separate decision.
- Running the setup through the broker (private skills, private package
  registries). It would hand a repository's script a credential.
- A lock file or version pinning for plugins beyond what the agent's own
  marketplace sources offer (`ref`, `sha` in the source object).

## Open points

- Codex has no declarative plugin install yet; when it gets one, `[codex]`
  grows a `plugins` list rendered the same way.
- A machine default could restrict which grants a repository's `.skiff`
  may ask for (`allow_grants`). Not needed while skiff is personal.
- bb's skiff provider can pass its own profile with `--profile` instead of
  its bootstrap script.
