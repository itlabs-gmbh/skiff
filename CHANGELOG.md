# Changelog

All notable changes to skiff are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `--profile` on `new`, `apply` and `profile show` can be repeated. The files
  are merged in the order given, after the machine default; a later file's
  values win and its setup runs later. Each file is trusted on its own, so a
  tool can trust the profile it writes and pass the repository's `.skiff`
  next to it, which still needs your `skiff profile trust`. With a single
  `--profile` nothing changes.

### Changed

- A refusal of untrusted profiles names every untrusted file and says what
  each one does by itself (before, the description included the machine
  default's grants).
- A file named twice with `--profile` is an error (its setup would run
  twice), and `--profile` together with `--no-profile` is refused instead of
  ignoring `--profile`.

## [0.4.0] - 2026-11-04

One file says what a VM needs. A `.skiff` in a repository and
`~/.skiff/profile.toml` on the Mac declare size, grants, tools, skills and
the agents' plugins and MCP servers, and `skiff new` builds the VM from them.
No `skiff prepare` and no new guest image are needed; existing VMs are
unchanged until `skiff apply`. `skiff new` now reads both files when they
exist, so a tool that runs it inside a repository with a `.skiff` gets that
file's settings; pass `--no-profile` where that is not wanted. A repository
file is refused until `skiff profile trust` has recorded it.

### Added

- **Profiles.** A `.skiff` file in a repository and `~/.skiff/profile.toml`
  as the machine default say what a VM needs: `[machine]` size and ports,
  `grants`, `skills` from git repositories, `[guest]` packages, agent CLIs
  (`tools = ["claude", "codex"]`) and a setup script, plus `[claude]`
  plugins, marketplaces, MCP servers and settings and `[codex]` MCP servers
  and config. `skiff new` merges both (flags win), runs the setup as root
  before any grant, grants the profile's capabilities and writes the agent
  configuration through the same planner as capabilities, so a clash with
  a capability is an error. A repository's `.skiff` is used only after
  `skiff profile trust` (or `--trust`) recorded its content. New commands:
  `skiff apply NAME [--setup]`, `skiff profile show [--vm NAME] [--render]`,
  `skiff profile init [--global]`, `skiff profile lint`, `skiff profile
  trust`; new flags `--profile FILE`, `--no-profile` and `--trust` on `new`
  and `apply`, and `apply --clear` to remove a profile's configuration
  again. The capability name `profile` is reserved.

## [0.3.0] - 2026-11-04

Azure DevOps without a PAT, through the intercept routes of 0.2.0. skiff
itself is unchanged; the docs now also say that a running broker keeps the
capability files it started with. After adding or replacing one, close the
VM's existing sessions and tunnels, then start a new `skiff ssh` or
`skiff tunnel`.

### Added

- **Azure DevOps example capability.** `examples/caps/azure-devops.toml`
  serves git over HTTPS, the REST API, Artifacts feeds and package downloads
  and, together with `azure.toml` and `azure-identity.toml`, `az devops`
  through intercept routes. The token is an Entra token that `az` on the Mac
  mints for Azure DevOps, so no PAT is needed, and
  `https://<org>@dev.azure.com/...` URLs work without an `insteadOf` per
  organization.

## [0.2.1] - 2026-11-04

A fix for the Azure example capabilities. The website now documents
intercept routes and the Azure CLI (`capabilities.html#intercept`,
`agents.html#azure`).

### Fixed

- `examples/caps/azure-identity.sh` writes `~/.skiff/azure-identity.json`
  itself and replaces it only on success. Redirected with `>`, a missing
  tool or an `az` that was not logged in left an empty file behind, and
  `az login --identity` in the guest failed with "None, None". It now also
  checks for `az` and `jq` first and handles a service principal login.

## [0.2.0] - 2026-11-04

Capabilities now also serve clients that insist on `https://` to fixed hosts,
such as the Azure CLI, without a credential in the VM. Nothing changes for
existing capabilities; no `skiff prepare` or new VMs are needed, and an
intercept capability takes effect with the next `skiff grant`.

### Added

- **Intercept routes for HTTPS-only clients.** A proxy route with
  `intercept = true` lets clients that insist on `https://` to a fixed host
  (the Azure CLI and SDKs, for example) use a capability without a credential
  in the VM. The guest resolves the host to the broker, trusts a per-VM CA
  whose key stays on the Mac, and the broker injects the capability's headers.
  Hosts are listed by name; revoke removes hosts entry, relay socket and CA.
- **Azure example capabilities.** `examples/caps/azure.toml` and
  `azure-identity.toml` run `az login --identity`, ARM, Graph and, by name,
  Key Vaults and storage accounts with tokens minted by `az` on the Mac; the
  guest only holds a placeholder.
- `make e2e-intercept` tests intercept routes against a real VM.

### Changed

- Broker connections that stay idle between requests are closed after two
  minutes.
- A connection to the broker that sends nothing for 10 seconds is closed
  (it was 30); the broker reads the first byte to tell TLS from HTTP.

## [0.1.1] - 2026-10-30

The first release under `github.com/sovyn-eu/skiff`. Reinstall from the new
path; `go install github.com/itlabs-gmbh/skiff/...` stays on 0.1.0.

### Changed

- **skiff moved to `sovyn-eu/skiff`.** The repository, the module path
  (`github.com/sovyn-eu/skiff`) and the website
  (`sovyn-eu.github.io/skiff`) follow. Install with
  `go install github.com/sovyn-eu/skiff/cmd/skiff@latest`; the old
  `itlabs-gmbh` path gets no new versions. Old GitHub links redirect.

### Fixed

- **The login banner is back.** The guest image replaces Ubuntu's motd (help
  links, the "minimized" notice, the legal text) with skiff's banner again:
  logo, host, IP, vCPUs, memory, uptime, kernel, disk and load. It got lost
  with the Firecracker guest agent; `skiff prepare` rebuilds the image, new
  VMs show it.

## [0.1.0] - 2026-10-16

The first release under the new name. Everything below is a break from
0.0.1: the binary, state directory, ssh alias and guest paths are renamed,
and the Lima/Firecracker runtime is replaced by Apple's `container`. Run
`skiff prepare` and recreate your VMs.

### Removed

- **The Lima/Firecracker backend.** `prepare --backend`, `--cpus/--memory/
  --disk/--profile` on `prepare`, `--disk/--profile/--fresh` on `new`, golden
  snapshots, image profiles, the guest agent, the `skiff-envd` daemon and the
  M3/macOS 15 preflight are gone; Apple's `container` is the only runtime.
  `~/.skiff/backend` is ignored. Delete an old Lima instance with
  `limactl delete cracklet` (or `skiff`).

### Changed

- **The container backend is the default.** A new `~/.skiff` uses Apple's
  `container`; `skiff prepare --backend lima` still selects the deprecated
  Firecracker-in-Lima backend until it is removed. README, website and the
  CLI texts describe the container backend first; the tagline is now
  "A fresh Linux VM on your Mac in half a second".

- **cracklet is now skiff.** The binary, the module path
  (`github.com/itlabs-gmbh/skiff`), the state directory (`~/.skiff`,
  `SKIFF_HOME`), the ssh alias (`ssh <vm>.skiff`), the guest image
  (`skiff/guest`), the Lima instance, the guest-side paths
  (`/run/skiff/broker.sock`, `/var/lib/skiff`) and the `SKIFF_*` environment
  of capability hooks all change name. There is no migration: run
  `skiff prepare` and recreate your VMs. The old `~/.cracklet` directory and a
  Lima instance named `cracklet` can be deleted (`limactl delete cracklet`).
  Entries below this one keep the old name.

### Added

- A second backend on Apple's `container` (macOS 26, any Apple Silicon): one
  Virtualization.framework VM per microVM, no Lima and no nested
  virtualization, so JIT-heavy workloads such as Claude Code run at Mac speed
  and a cold boot takes about half a second. Select it once with
  `cracklet prepare --backend container` (remembered in `~/.cracklet/backend`);
  `prepare` installs the CLI through Homebrew if needed, starts the system
  service and builds the guest image (Ubuntu 24.04 with systemd, sshd and
  cracklet's key). `ssh`, `exec`, grants, the broker and `gc` work unchanged;
  `ssh <vm>.cracklet` reaches the guest through `cracklet _dial`. Not on
  this backend: golden snapshots (`--fresh` is a no-op) and profiles (the root
  disk is a sparse 512 GiB volume). `cracklet doctor` names the active backend.

- Port forwards on the container backend. `cracklet forward` (and `new -p`)
  stores the forward with the VM, and `cracklet _relay`, a hidden command
  that cracklet starts as a detached process whenever forwards exist and no
  relay runs, listens on `localhost:HOST` and joins every connection to the
  VM's guest port. Forwards survive `stop`/`start` and a reboot of the Mac
  (the first `cracklet` command after login brings the relay back), follow a
  VM to a new address, and go away with the VM; the relay exits on its own
  after two minutes without forwards. Its log is `~/.cracklet/relay.log`.
  The relay is deliberately not a launchd agent: macOS denies a launchd-
  started binary the local network silently, while a child of your terminal
  inherits its permission, as the ssh ProxyCommand already does.

- Host key pinning on the container backend. Every VM makes its own ed25519
  host key on first boot (the guest image no longer ships the keys apt
  generated at build time); `cracklet new` reads it with `ssh-keyscan` before
  anything else talks to the VM and keeps it in `~/.cracklet/known_hosts`,
  which the generated `ssh_config` uses with `StrictHostKeyChecking yes`. All
  guests share one vmnet subnet, so a guest that took a neighbour's address
  can no longer pose as it towards `cracklet ssh`, grants or the broker
  tunnel. VMs created before this change have no pinned key: recreate them.

- An internet-only guard rail in the container guest image: nftables rejects
  connections from the guest to private networks (the Mac at `192.168.64.1`
  and the LAN behind it included) except DNS and DHCP to the gateway, so a
  careless agent fails fast instead of reaching your network. Unlike the
  Lima backend's host-side rules, root inside the guest can lift it.
  `cracklet prepare` rebuilds the guest image.

- `cracklet _dial HOST PORT`, a hidden ssh ProxyCommand that relays a session
  to a port on a microVM through the backend; the generated `ssh_config` now
  takes its ProxyCommand from the backend. The Lima backend keeps hopping
  through the Lima VM with `ssh -W`, so nothing changes for it yet.

### Changed

- The code that drives Lima and the guest agent moved behind a backend
  interface (`internal/backend`); `app` keeps grants, broker, tunnel and gc
  and no longer knows about limactl. No user-visible change; the guest agent's
  checksum is now verified once per process instead of on every poll of
  `cracklet tunnel`. This is the seam for the apple/container backend described
  in docs/design/container-backend.md.

### Added

- After a reboot of the Mac, any command that needs the Lima VM starts it
  when it is stopped (once, even when several commands run in parallel; never
  during a resize) instead of asking for `cracklet prepare`. The microVMs that
  were running come back: `start`/`new` mark a VM, `stop` clears the mark, and
  the agent's new `restore` boots the marked VMs once per boot of the Lima VM,
  from the CLI and from `cracklet-restore.service`, which `prepare` installs.

## [0.0.1] - 2026-10-08

First public release.

### Added

- VM metadata: `cracklet new --owner NAME [--slot N]` labels a VM managed by a
  tool, and every new VM records its creation time. `ls` shows OWNER and AGE
  columns, `inspect` and `--json` report `owner`, `slot` and `created_at`.
- `cracklet gc` removes orphaned owned VMs, selected by `--owner` and
  `--older-than` with `--keep` exemptions and `--dry-run`, and deletes the
  grants and tokens left on the Mac for VMs that no longer exist. VMs without an
  owner are never collected, nor are VMs `ls` reports as `creating`; the agent
  re-checks owner and creation time under its lock before removing, so a VM
  recreated under the same name survives.
- `cracklet prepare --cpus/--memory/--disk` resizes an existing Lima VM in
  place (stop, `limactl edit`, start) instead of only applying at creation.
  Only explicitly given flags count, running microVMs block the restart, a
  host-side lock keeps `new`/`start` from racing it, and the disk can only grow.
- `cracklet exec NAME -- command [arg...]` runs a command with every argument
  shell-quoted, so the guest receives exactly that argv. `cracklet ssh NAME cmd`
  keeps plain-ssh semantics and passes a shell command line.
- Image profiles: `cracklet prepare --profile paseo` builds an 8G guest image
  with Node 22, `@getpaseo/cli`, Claude Code, git, gh and rsync (with
  `paseo.service` installed but disabled), and `cracklet new --profile paseo`
  restores its own golden snapshot. `--disk` now defaults to the profile's
  image size.
- Capability broker: `cracklet grant NAME CAP...`, `revoke`, `grants` and
  `new --grant` let a microVM use GitHub, Claude Code or host-side MCP servers
  through a per-VM Unix socket that `cracklet ssh` forwards into the guest.
  Credentials stay on the Mac; the guest gets a placeholder token and a
  provisioned `/etc/environment`, files and JSON merges. Decisions are logged
  to `~/.cracklet/audit.log`.
- Capability files (`cracklet cap ls|show|lint|init|add`): TOML definitions
  with three primitives (`proxy`, `mcp`, `exec`), embedded defaults for
  `claude` and `github`, user overrides in `~/.cracklet/caps/`.
- The `github` capability also serves the `gh` CLI: API calls for
  `api.github.com` reach the broker through `/run/cracklet/broker.sock` and use
  the same `github-token`. A grant is per capability: what the VM reaches on
  GitHub is what the token reaches, so use a fine-grained token limited to the
  agent's repositories.
- Capability files: `[[proxy.routes]]` reach further upstreams by `Host`
  header (public DNS names only), and guest templates get `.BrokerSocket`, a
  Unix socket that systemd relays to the broker tunnel while any capability is
  granted.
- `cracklet secret set|rm` stores credentials in the macOS Keychain for
  capabilities to reference as `keychain:cracklet/<name>`.
- `cracklet ls` shows a GRANTS column.
- `cracklet tunnel NAME` serves a VM's broker without an interactive session,
  reconnecting until interrupted or the VM stops. `cracklet ssh` reuses a
  running broker instead of failing on the already forwarded guest port, and
  takes the broker over when the session or tunnel that owned it ends.
- `cracklet inspect NAME` shows one microVM; `ls`, `new` and `inspect` take
  `--json` for scripting (progress messages then go to stderr).
- Apache-2.0 license, contributing guide, code of conduct, security policy,
  issue and pull request templates, and a CI workflow.
- `cracklet new` prints a ready-to-use `ssh NAME.cracklet` command.
- Golden snapshots: `cracklet new` restores a pre-booted VM in about 3 s
  instead of cold-booting; `--fresh` forces a cold boot.
- Port forwarding with `-p HOST:GUEST` on `new` and `cracklet forward` /
  `cracklet unforward`, backed by transient systemd socket units.
- `Include ~/.cracklet/ssh_config` lets plain `ssh NAME.cracklet` work via the
  Lima VM as jump host.

### Fixed

- The `github` capability puts gh's placeholder token in
  `/root/.config/gh/hosts.yml` instead of `GH_TOKEN`: long-running processes
  such as the Paseo daemon read `/etc/environment` only at start, so gh in
  them stayed logged out after a later grant.

- The `github` capability sends `Basic x-access-token:<token>` instead of
  `Bearer`, which GitHub rejects for git over HTTPS. Capability templates gain
  a `basicauth` function for this: `{{ secret "ref" | basicauth "user" }}`.

### Security

- A new microVM never inherits the grants or placeholder token left on the Mac
  by an earlier VM of the same name; the broker authorises by name, so such
  leftovers would have handed the new VM the old one's capabilities.
- Firewall chains are rebuilt atomically with `iptables-restore`; CGNAT
  (`100.64.0.0/10`) is blocked alongside the other private ranges.
- Guests are internet-only: tap-to-tap traffic, the Lima VM's own services,
  the Mac and the LAN are unreachable; anti-spoofing rules drop packets with
  a source outside the guest subnet; IPv6 is disabled on every tap.
- The guest CRNG is reseeded from the Lima VM's `/dev/urandom` after every
  snapshot restore so clones diverge immediately.

[Unreleased]: https://github.com/sovyn-eu/skiff/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/sovyn-eu/skiff/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sovyn-eu/skiff/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/sovyn-eu/skiff/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/sovyn-eu/skiff/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/sovyn-eu/skiff/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sovyn-eu/skiff/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/sovyn-eu/skiff/releases/tag/v0.0.1
