# Example profiles

A profile says what a VM needs; see the README section *Profiles: what a VM
needs* for the format. Two layers:

| File             | Where it goes            | Shows                                                    |
|------------------|--------------------------|----------------------------------------------------------|
| `profile.toml`   | `~/.skiff/profile.toml`  | a machine default: Claude Code installed and granted in every VM, GitHub through the broker |
| `web-app.skiff`  | `.skiff` in a repository | what a Node project adds: size, dev-server port, packages, plugins, an MCP server, Codex alongside |

```sh
cp examples/profiles/profile.toml ~/.skiff/profile.toml
cp examples/profiles/web-app.skiff path/to/repo/.skiff
cd path/to/repo && skiff profile show --render
skiff profile trust
skiff new
```
