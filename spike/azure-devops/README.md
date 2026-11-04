# Spike: Azure DevOps with Entra tokens through intercept routes (phase 3)

Question: can Azure DevOps run in a VM without a PAT, with a token that `az`
on the Mac mints for the Azure DevOps resource
(`499b84ac-1321-427f-aa17-267ca6975798`), and without `insteadOf` rewrites?

`ado-spike.toml` intercepts `dev.azure.com`, `vssps.dev.azure.com`,
`feeds.dev.azure.com` and `pkgs.dev.azure.com` and injects
`Bearer <az account get-access-token --resource 499b84ac-…>`. Nothing is
configured for git in the guest.

## Results (2026-11-04, skiff at v0.2.1, host az 2.86, guest az 2.92, org with 20 projects)

Stage A, on the Mac with curl and git (no VM):

| Check | Result |
|---|---|
| `az account get-access-token --resource 499b84ac-…` | works with the normal user login |
| REST `_apis/projects`, `_apis/git/repositories` with `Bearer` | 200 |
| `git ls-remote` with `http.extraHeader: Authorization: Bearer …` | works |
| `feeds.dev.azure.com/_apis/packaging/feeds` with `Bearer` | 200 |

Stage B, in a VM with `ado-spike` (and for `az devops` also `azure` and
`azure-identity` from `examples/caps/`):

| Check | Result |
|---|---|
| `git ls-remote https://dev.azure.com/<org>/<project>/_git/<repo>` | works, no git config in the guest |
| the same with `https://<org>@dev.azure.com/…` (the form the API and the Clone button use) | works; git only prints "redirecting to https://dev.azure.com/…" |
| `git clone --depth 1` (upload-pack POST) | works |
| REST and feeds with curl, no auth in the guest | 200 |
| `az devops project list`, `az repos list` | work (20 projects, 0.8 s) **only with `azure` granted too** |
| `az devops` with only `ado-spike` + `azure-identity` | `az login --identity` fails: it lists subscriptions on ARM, which is not intercepted, so ARM sees the placeholder |
| git credentials in the guest | none (`~/.git-credentials` absent, no credential helper) |
| revoke `ado-spike` | `dev.azure.com` resolves to Microsoft again; git fails with "could not read Username" |
| Hosts hit | `dev.azure.com`, `feeds.dev.azure.com`, `management.azure.com` (for az login); `vssps.dev.azure.com` not needed so far |

Not tested: `git push` (receive-pack, same auth path), package downloads
from `pkgs.dev.azure.com` (npm/NuGet/pip), `az pipelines`, SSH remotes
(`git@ssh.dev.azure.com`, not intercepted; use the `ssh-agent` grant).

## Findings

- An Entra token from `az` replaces the PAT for git, REST and Artifacts.
  The rights are those of the Mac's az login (or of a dedicated identity
  via `AZURE_CONFIG_DIR`), not a PAT's scopes; there is no PAT to rotate.
- Intercept removes the `insteadOf` problem of the PAT capability (and of
  closed #36): `org@dev.azure.com` URLs work without one line per org.
- One token resource serves all Azure DevOps hosts; the cmd secret is
  shared, so az runs once per minute at most.
- `az devops` needs ARM as well, because `az login --identity` lists
  subscriptions. The example should say: grant `azure` and `azure-identity`
  too, or use only git/REST.
- Phase 3 can again be an example capability without Go code
  (`examples/caps/azure-devops.toml`), replacing the user's PAT copy.
