# Contributing to skiff

Thanks for taking the time to contribute. skiff is a small project, so the
rules are short. If something here is unclear, open an issue and ask.

## Before you start

- **Bugs and small fixes:** open a pull request directly.
- **New features or behaviour changes:** open an issue first so we can agree on
  the approach before you invest time. skiff deliberately stays small; not
  every feature fits.
- **Security issues:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

You need an Apple Silicon Mac with macOS 26+ to run VMs.
Unit tests, `go vet` and `shellcheck` also run on Linux.

```sh
git clone https://github.com/sovyn-eu/skiff.git
cd skiff
make build    # -> bin/skiff
make test     # unit tests with -race
make lint     # gofmt, go vet
make e2e      # boots a real VM, needs `skiff prepare` first
```

`make lint` and `make test` must pass before you open a pull request. CI runs
the same targets.

Tools: Go 1.26+.

## Repository layout

| Path                | Purpose                                              |
|---------------------|------------------------------------------------------|
| `cmd/skiff`      | CLI entry point                                      |
| `internal/cli`      | cobra commands                                       |
| `internal/app`      | workflows (prepare, new, ssh, forward, ...)          |
| `internal/backend`  | backend interface, the `container` backend and an in-memory fake for tests |
| `internal/host`     | host preflight checks (`skiff doctor`)            |
| `internal/cap`      | capability files and embedded defaults               |
| `internal/profile`  | profile files (`.skiff`, machine default), merge, rendering |
| `internal/guest`    | guest provisioning scripts                           |
| `internal/vm`       | VM spec and port-forward validation                  |
| `internal/sshcfg`   | `~/.skiff/ssh_config` rendering                   |
| `internal/config`   | pinned versions and SHA-256 digests                  |
| `website/`          | static project website                               |

## Coding guidelines

- **Go:** idiomatic Go, `gofmt`-formatted, `go vet` clean. Keep functions and
  files small. Return errors with context (`fmt.Errorf("...: %w", err)`),
  never swallow them.
- **Backend calls:** anything that changes state through the `container`
  CLI runs under the backend lock (`internal/backend/container/records.go`)
  and rolls back on failure, as the existing create/remove paths do. A helper
  that takes the lock must never be called from under it.
- **Guest image:** a change to the Dockerfile or the nftables ruleset in
  `internal/backend/container` bumps `imageRev`, so `skiff prepare` rebuilds.
- **Tests:** every change comes with tests. Table-driven tests for pure logic,
  fakes for `container`/`ssh` (see `internal/runner`) and the in-memory
  backend in `internal/backend/backendtest` for app and cli.
- **Security:** skiff's network isolation rules are documented in the
  README. A change that loosens them needs a written justification in the PR.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

<optional body explaining why, not what>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`.

Examples from the history:

```
feat: show SSH command with DNS name on VM creation
fix: rebuild firewall chains atomically and block CGNAT ranges
```

## Pull requests

1. Fork and create a branch from `main`.
2. Make your change, add tests, run `make lint test`.
3. Add a line to the *Unreleased* section of [CHANGELOG.md](CHANGELOG.md).
4. Open the PR. Fill in the template: what changed, why, and how you tested
   it (`make e2e` output is welcome for anything that touches the backend or
   networking).
5. One maintainer review is required. Squash-merge is the default.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as the project
(Apache-2.0 §5). No separate CLA is required.
