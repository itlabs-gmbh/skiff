# Example capabilities

Copy a file into `~/.skiff/caps/`, run `skiff cap lint <name>`, then
`skiff grant <vm> <name>`. Each file is a complete capability; the comments
at the top explain what it hands into the guest and how.

| File                   | Primitive | Shows                                              |
|------------------------|-----------|----------------------------------------------------|
| `chrome-devtools.toml` | `mcp`     | a stdio MCP server on the Mac bridged into the guest |
| `gh-api.toml`          | `exec`    | an external program answering requests (no secret leaves the Mac) |
| `azure.toml`           | `proxy`   | intercept routes for an HTTPS-only CLI (az): TLS ends at the broker, tokens come from az on the Mac |
| `azure-identity.toml`  | `exec`    | a static placeholder identity for `az login --identity`, made by `azure-identity.sh` |
| `azure-devops.toml`    | `proxy`   | git, REST, Artifacts and `az devops` for Azure DevOps through intercept routes, with an Entra token from az instead of a PAT |
| `mongodb.toml`         | `tcp`     | a database port in the guest that reaches a proxy on the Mac, which holds the password and logs in upstream |

The embedded `claude` and `github` capabilities are the `proxy` examples; print
them with `skiff cap show claude` and `skiff cap show github`.
