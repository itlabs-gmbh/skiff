# skiff – a fresh Linux VM on your Mac in half a second

[![CI](https://github.com/sovyn-eu/skiff/actions/workflows/ci.yml/badge.svg)](https://github.com/sovyn-eu/skiff/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/sovyn-eu/skiff.svg)](https://pkg.go.dev/github.com/sovyn-eu/skiff)

`skiff` gives you throwaway Linux VMs on Apple Silicon, one per task or coding
agent: `skiff new dev` boots an Ubuntu 24.04 VM with its own kernel, disk, IP
and root SSH in about two seconds (the boot itself takes half a second), and
`skiff rm dev` throws it away. Credentials the agent needs stay on the Mac and
reach the VM through a broker, never as copies.

```
macOS (skiff)
 ├── VM dev   (Virtualization.framework via Apple's `container`, 192.168.64.x, ssh dev.skiff)
 ├── VM ai    (…)                                     ──┐ relay: localhost:3000 → ai:3000
 └── broker   (credentials, MCP servers, audit log)   ◀─┘ ssh -R tunnel per session
```

Each VM is a `container machine`: a Virtualization.framework VM driven by
Apple's [container](https://github.com/apple/container) CLI. There is no
nested virtualization and no shared runtime VM, so JIT-heavy workloads such as
Claude Code run at Mac speed. The host side is one Go binary; the guest is a
plain Ubuntu image with systemd, sshd and skiff's key.

## Requirements

- Apple Silicon (any generation)
- macOS 26 or newer (what Apple's `container` supports)
- Homebrew (skiff installs `container` through it if needed)
- Go 1.26+ to build skiff

Check with `skiff doctor`.

## Install

```sh
go install github.com/sovyn-eu/skiff/cmd/skiff@latest
skiff prepare           # one-time setup, about a minute
```

Or from a checkout: `make install` (go install ./cmd/skiff → `$(go env GOPATH)/bin/skiff`).

`skiff prepare` is idempotent. It:

1. verifies the host (Apple Silicon, macOS version, Hypervisor framework, `container`),
2. generates an SSH key pair in `~/.skiff/`,
3. starts the `container` system service (first run downloads Apple's guest kernel),
4. builds the guest image `skiff/guest` (Ubuntu 24.04 with systemd, sshd,
   your public key and the internet-only firewall), rebuilt only when the
   image recipe or your key changes,
5. writes `~/.skiff/ssh_config`.

### Why Apple's container

skiff started as Firecracker microVMs inside a Lima VM with nested
virtualization. Measured on an M4 Pro (2 vCPU / 1 GiB guests), the nesting
cost JIT-heavy workloads such as Claude Code about twice the CPU, which is why
skiff moved to one Virtualization.framework VM per guest:

| measurement                           | Mac     | Firecracker in Lima | container |
|---------------------------------------|---------|---------------------|-----------|
| first touch of fresh RAM, ms/MiB      | 0.18    | 0.39                | 0.18–0.23 |
| `CTR_EL0` read (JIT icache flushes)   | n/a     | 24 µs               | 0.001 µs  |
| Claude Code CPU in the first 3 s, JIT | 0.64–0.71 s | 1.13–1.22 s     | 0.69–0.87 s |
| cold boot to sshd                     | –       | 1.5 s (+0.1 s ssh)  | 0.5 s     |

There are no golden snapshots (every boot is cold and fast), no image
profiles (install what a task needs over ssh) and no `--disk` (the root disk
is a sparse 512 GiB volume that grows on demand); VMs need at least 1 GiB of
memory.

## Usage

```sh
skiff new                    # boots vm1 (2 vCPUs, 1 GiB RAM, 2G disk)
skiff new dev --vcpus 4 --mem 2048
skiff ls
skiff ls --json              # also: new --json, inspect --json
skiff inspect dev            # details of one VM
skiff ssh dev                # interactive root shell
skiff ssh dev uname -a       # run a command (a shell command line, like plain ssh)
skiff exec dev -- git commit -m "it's done"   # exact argv, every word quoted
skiff stop dev               # keep the disk
skiff start dev
skiff rm dev                 # stop and delete
skiff gc --owner paseo       # remove VMs a tool created and lost track of
```

### Owned VMs and `skiff gc`

Tools that create VMs on your behalf label them with an owner and, if they keep a
pool, a slot. skiff records both together with the creation time in the VM's
directory, so the labels disappear with the VM:

```sh
skiff new paseo-3 --owner paseo --slot 3
skiff ls                             # OWNER shows paseo/3, AGE the time since creation
skiff gc --owner paseo --keep paseo-1 --keep paseo-2   # a tool reconciling its pool
skiff gc --older-than 7d --dry-run   # owned VMs older than a week
```

`gc` only ever removes VMs that have an owner; VMs created by hand have none and
are never collected. `--owner` and `--older-than` select which owned VMs go,
`--keep` exempts VMs by name, and `--dry-run` shows the plan. Without `--owner`
or `--older-than`, gc removes no VM and only deletes the grants and tokens left
on the Mac for VMs that no longer exist. A VM a tool is creating right now is not
in its keep list yet; guard it with `--keep` or `--older-than`. `gc --json`
reports `{"vms": [...], "host_state": [...], "dry_run": ...}`.

### Port forwarding

```sh
skiff new web -p 8080:80 -p 3000    # forwards at creation
skiff forward web 5432              # localhost:5432 -> web:5432
skiff forward web                   # list
skiff unforward web 5432
```

Forwards appear as `localhost:PORT` on the Mac, persist across `stop`/`start`
and a reboot, follow the VM to a new address, and are removed with the VM. Host
ports must be 1024 or higher because the relay runs as your user. Under the
hood `skiff _relay`, started by skiff whenever forwards exist, listens on the
host port and joins each connection to the VM's guest port; a stopped VM keeps
its port and connections are closed until it runs again. `skiff forward web`
shows each forward as `active` or `inactive`.

To use plain `ssh`, add one line to `~/.ssh/config`:

```
Include ~/.skiff/ssh_config
```

Then `ssh dev.skiff` works from anywhere, including `scp`, `rsync` and your IDE.
The alias runs `skiff _dial` as ProxyCommand, which connects to the VM's
current address and verifies the host key pinned at creation, so no port
forwarding or `sudo` is needed on macOS.

### Capabilities: credentials and MCPs without copying secrets

A VM is isolated from your Mac on purpose. When an agent inside needs
GitHub, Claude Code or an MCP server that only runs on the Mac, skiff opens
one controlled hole: a **broker** that hands out *connections, never secrets*.

```sh
skiff secret set claude-token          # paste the output of `claude setup-token`
skiff secret set github-token          # a fine-grained token, limited to the repos the agent may use
skiff grant agent1 claude github ssh-agent
skiff ssh agent1                       # the broker lives as long as this session
skiff grants agent1
skiff revoke agent1 github
```

While `skiff ssh` is open, the broker listens on a Unix socket on the Mac and
ssh forwards it to `127.0.0.1:7777` inside the guest (`-R`). Tools in the guest
talk to that address with a per-VM placeholder token; the broker swaps it for
the real credential from the macOS Keychain. The socket identifies the VM, so
there is nothing in the guest worth stealing, and the hole closes with the
terminal. `ssh-agent` is a built-in grant that adds `-A`; pair it with
`ssh-add -c` to confirm every signature. For clients that only speak HTTP over
a Unix socket, the guest also gets `/run/skiff/broker.sock` while any
capability is granted: a systemd socket that relays to the same tunnel.

When something other than `skiff ssh` drives the guest, such as an editor or
an agent runner with its own ssh session, keep the broker up with
`skiff tunnel agent1`. It holds only the forward, reconnects when the
connection drops, logs `tunnel=open|closed` to the audit log and ends with
Ctrl-C or when the VM stops. `skiff ssh agent1` keeps working alongside it
and uses the running broker instead of forwarding a second time; if the session
or tunnel that owns the broker ends first, the remaining session takes it over
within a few seconds.

Grants are the only policy: default deny, one file per VM in `~/.skiff/vms/`,
checked on every request and logged to `~/.skiff/audit.log`. Capability files
are read when the broker starts: after adding or changing one, close the VM's
sessions and tunnels and start a new one. A denied request
answers with the exact `skiff grant` command that would allow it. A grant is
all or nothing per capability: what a granted VM can reach is what the
credential behind it can reach. Limit that at the source, for GitHub with a
fine-grained token restricted to the repositories the agent works on. GitHub
enforces that limit itself, and the token never enters the guest.

The broker is harness-neutral. It knows three primitives, and everything
specific to Claude Code, GitHub or any other tool is a **capability file**:

| Primitive | What the broker does                                                        |
|-----------|-----------------------------------------------------------------------------|
| `proxy`   | reverse-proxies `/<cap>/...` (or a routed `Host`) to an upstream and injects headers from secrets |
| `mcp`     | runs a stdio MCP server on the Mac and serves it as an HTTP MCP endpoint     |
| `exec`    | pipes the request through an external program (`skiff-cap-<name>`)        |

```sh
skiff cap ls                           # embedded: claude, github; yours in ~/.skiff/caps
skiff cap show claude                  # the TOML file
skiff cap show github --render --vm agent1   # what the guest receives
skiff cap init codex                   # commented skeleton, then: skiff cap lint codex
skiff cap add https://example.com/gemini.toml   # shown before it is installed
```

A capability declares the primitive plus a `[guest]` section with environment
variables, files, managed blocks inside shared files (such as `/etc/gitconfig`)
and JSON merges, all templated with `.BrokerURL`, `.BrokerSocket`, `.PseudoToken`
and `.VM`. Secrets (`keychain:`, `env:`, `cmd:`, `file:`) are only valid on the
broker side; `skiff cap lint` rejects them in guest sections. Header
templates can encode Basic credentials with
`{{ secret "ref" | basicauth "user" }}`. A proxy can add `[[proxy.routes]]`:
requests that reach the broker for another `host` (for example through
`.BrokerSocket`) go to that route's upstream with its own headers. A user file in
`~/.skiff/caps/<name>.toml` replaces an embedded capability of the same name.
See `examples/caps/` for an MCP bridge and an exec plugin.

The embedded `github` capability serves git and the `gh` CLI with one token.
git is rewritten to the broker in `/etc/gitconfig`; gh sends its API calls
through `.BrokerSocket` (`http_unix_socket`) with a placeholder token in its
`hosts.yml`, which gh reads on every call, so a grant applies to running
processes without a restart. Paths with percent-encoding are refused, and
downloads that GitHub redirects to other hosts (`gh release download`) do not
work through the broker. Route hosts must be public DNS names, never an IP or
`localhost`, so no capability can catch the requests of another.

Some clients insist on `https://` to fixed hosts and cannot be pointed at the
broker: the Azure CLI and SDKs, for example. A proxy route with
`intercept = true` serves them. While it is granted, the guest's `/etc/hosts`
sends the route's host to `127.77.0.1`, where a systemd socket relays port 443
into the tunnel, and the guest trusts a CA of its own whose key stays on the
Mac (`~/.skiff/vms/<vm>/intercept/ca.pem`). The broker completes the TLS
handshake only for intercept routes of granted capabilities, requires the
`Host` header to match the server name, and forwards with the capability's
headers, so the guest's placeholder never reaches the upstream. The CA is
name-constrained to the intercepted hosts and their subdomains, and a revoke
removes hosts entry, socket and CA from the guest. Hosts are listed by name;
there are no wildcards. `examples/caps/azure.toml` with `azure-identity.toml`
runs `az` this way, `examples/caps/azure-devops.toml` git, REST and Artifacts
for Azure DevOps without a PAT, and `make e2e-intercept` tests the mechanism against a
real VM. Design and trade-offs: `docs/design/credential-intercept.md`.

The embedded `claude` capability points `ANTHROPIC_BASE_URL` at the broker and
sets `CLAUDE_CODE_OAUTH_TOKEN` to the placeholder, so the unmodified Claude Code
binary in the guest sends exactly the headers of a normal subscription login.
Usage draws on your own subscription like any other session. Anthropic's terms
allow signing in to the unmodified binary with your own subscription, including
in sandboxes you run; they do not allow routing other people's requests through
your account, so keep the broker personal.

## How a VM is wired

| Piece            | Value                                                                 |
|------------------|-----------------------------------------------------------------------|
| VM               | `container machine create skiff/guest --name NAME --cpus N --memory M` |
| Kernel           | Apple's default guest kernel, fetched by `container system start`     |
| Root disk        | sparse 512 GiB volume, grows on demand                                |
| Network          | vmnet, `192.168.64.x` by DHCP; the address can change across restarts |
| SSH              | `ssh NAME.skiff` through the ProxyCommand `skiff _dial`, host key pinned at creation in `~/.skiff/known_hosts` |
| Port forwards    | `skiff _relay`, a detached process that listens on `localhost:HOST` and dials the VM |
| State            | `~/.skiff/machines/NAME.json` (owner, slot, creation time, host key, forwards) |

### Network isolation

The guest image carries an nftables ruleset that rejects connections from the
VM to private networks: the Mac at `192.168.64.1`, your LAN, other VMs, and
link-local and carrier-grade ranges. DNS and DHCP to the gateway stay open, the
internet is reachable through vmnet's NAT. It is a guard rail inside the guest,
not a boundary: root in the VM can lift it. The only controlled way back to the
Mac is the [capability broker](#capabilities-credentials-and-mcps-without-copying-secrets).

Because all VMs share one vmnet subnet, `skiff new` reads each VM's ssh host
key right after its first boot and pins it; a VM that takes a neighbour's
address cannot pose as it towards `skiff ssh`, grants or the broker tunnel.

## Troubleshooting

- `skiff doctor` explains what is missing on the host.
- Boot log of a VM: `container machine logs NAME`
- Port forwards: `skiff forward NAME` shows their state; the relay logs to `~/.skiff/relay.log`.
  The relay runs as a child of your terminal (macOS denies a launchd agent the local
  network), so it ends at logout; the next `skiff` command starts it again.
- After a reboot of the Mac, the next `skiff` command starts the `container` service and
  the VMs that were running come back. VMs stopped with `skiff stop` stay stopped.
- `ssh` reports `Host key verification failed` for a VM created before host keys were
  pinned, or one replaced under the same name: recreate it.
- `skiff ssh` and `skiff exec` mirror the remote exit status; exit 255 means the connection failed.
- `skiff ssh dev a b` joins its words into one shell command line, as ssh does, so
  quotes and `$` are interpreted by the guest shell. Use `skiff exec dev -- a b` from
  scripts: it quotes every argument and the guest sees exactly that argv.
- Ctrl-C during `skiff new NAME` removes the half-created VM again.
- Reset everything: `skiff rm` each VM, then `rm -rf ~/.skiff` and
  `container image rm skiff/guest:latest`.

## Development

```sh
make test     # unit tests (with -race)
make cover    # coverage summary
make lint     # gofmt, go vet
make e2e      # boots a real VM (requires skiff prepare), cleans up afterwards
make e2e-intercept  # intercept routes against a real VM and httpbin.org
```

Layout: `cmd/skiff` (entry point), `internal/cli` (cobra commands),
`internal/app` (workflows), `internal/backend` (the interface, the `container`
backend and an in-memory fake for tests), `internal/host` (host facts),
`internal/broker` (per-VM capability broker), `internal/intercept` (per-VM
intercept CA), `internal/cap` (capability files,
embedded defaults), `internal/grant` (per-VM policy), `internal/guest`
(guest provisioning scripts), `internal/secret` (Keychain/env/cmd/file resolver),
`internal/vm` (spec validation), `internal/sshcfg` (ssh_config rendering).

## Contributing

Bug reports and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, coding
guidelines and PR process, and [SECURITY.md](SECURITY.md) for how to report
vulnerabilities privately. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## License

skiff is licensed under the [Apache License 2.0](LICENSE).
Copyright 2026 IT-Labs GmbH. Apple's container CLI, its guest kernel and the
Ubuntu image are installed or downloaded at `skiff prepare` time and keep
their own licenses; see [NOTICE](NOTICE).
