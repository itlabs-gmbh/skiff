# Design: credentials for HTTPS-only clients (broker intercept)

Status: phase 1 implemented, 2026-11-04 (e2e: az 2.92 in an Ubuntu 24.04
arm64 guest against ARM, Graph and Key Vault through the broker alone).
Based on the three Azure spikes in `spike/azure/` (host az 2.86).

Decision sought: the broker learns to terminate TLS for hosts a capability
declares, so that clients which insist on `https://` to fixed hosts get
credentials injected on the Mac like every other capability. The guest only
ever holds placeholders.

## Why

The broker works for clients that can be pointed at a plain-HTTP broker URL:
Claude Code (`ANTHROPIC_BASE_URL`), git (`insteadOf`), gh
(`http_unix_socket`). Many clients cannot:

- the Azure CLI and SDKs: azure-core refuses bearer tokens over `http://`
  ("Bearer token authentication is not permitted for non-TLS protected
  (non-https) URLs"), and data-plane URLs (`<vault>.vault.azure.net`) come
  from API responses, not from configuration;
- the AWS CLI and SDKs (SigV4-signed requests to regional hosts), gcloud and
  Google client libraries, Node programs (which ignore `HTTPS_PROXY`), and
  scripts that simply call `https://api.github.com`.

For these the only option today is a credential in the guest. Spike 1
(managed-identity endpoint answered by `az account get-access-token` on the
Mac) works, but puts a real access token (60–90 min, no refresh token) into
the guest: replayable from anywhere, not revocable before it expires,
unaudited.

Spike 2 (`spike/azure/mitm/`) showed the alternative end to end: a proxy on
the Mac terminates TLS for allow-listed Azure hosts with a name-constrained
CA, swaps a placeholder JWT for a real token and forwards the request. ARM,
Graph and the Key Vault data plane worked at ~1 s per az command. The
guest's token is rejected by Azure (`401`), closing the tunnel ends access at
once, and every request is audited with method, host and path.

## Non-goals

- A general egress proxy. The broker terminates the hosts a granted
  capability declares and nothing else; there is no passthrough.
- Hiding what an API returns. A guest that may call
  `az keyvault secret show` or `az storage account keys list` receives
  secrets in the response. Scope the identity behind the capability instead.
- Non-HTTP protocols (SSH, databases), mutual TLS towards the upstream,
  clients that pin certificates.

## Relation to superfly/tokenizer

[tokenizer](https://github.com/superfly/tokenizer) (Apache-2.0, like skiff) is
an HTTP proxy that injects third-party credentials. It is the closest prior
art for the broker as it is *today*, and it deliberately does not do what
this design adds:

| Concern | tokenizer | skiff today | this design |
|---|---|---|---|
| How the client reaches the proxy | plain `http://` to the proxy, proxy upgrades to TLS upstream; **CONNECT is refused** | plain HTTP over the per-VM ssh tunnel | adds TLS termination for declared hosts |
| Who may use a secret | sealed secret (NaCl box) + `bearer_auth` or `fly-src` machine binding | per-VM Unix socket + grants, secrets in the Keychain | unchanged |
| How a credential is applied | processors: `inject` (header or query, `fmt`), `inject_hmac`, `sigv4`, `jwt`, `client_credentials`, `github_app` | header templates (`secret`, `basicauth`) | header templates; add `sigv4` later |
| Token exchanges (JWT bearer, client credentials, GitHub App) | in the proxy, result re-sealed | `cmd:` secret on the Mac | `cmd:` on the Mac (`az`, `gcloud`, `gh`) |
| Host restriction | `allowed_hosts` / `allowed_host_pattern` per secret | routes per capability | same, plus a wildcard rule |
| Upstream dial | refuses private, loopback, link-local addresses at connect time | default transport (upstreams are declared by the cap author) | adopt tokenizer's connect-time check where the guest picks the host (wildcards) |

tokenizer refuses CONNECT because its validators check the `Host` header
while a tunnel is delivered to whatever the CONNECT line named. A host-scoped
secret could then reach another host. This design does not tunnel. The
broker terminates TLS itself, requires SNI, `Host` and the route's host to be
identical, and dials only the route's upstream.

What to take from tokenizer:

1. The connect-time dial guard (`net.Dialer.ControlContext` rejecting
   non-public IPs; it also covers DNS rebinding, which a resolve-then-dial
   check misses). It matters once the guest can pick the upstream host, i.e.
   with wildcard routes. Not for the existing proxy upstreams: their author
   declares them, and some deliberately point into the LAN (an on-premises
   Azure DevOps Server, say), which a blanket guard would break.
2. The SigV4 re-signing processor, ported with attribution in `NOTICE`, when
   AWS comes (phase 4).
3. The threat note about echo services: a credential sent to a host the
   attacker controls is a leaked credential. This drives the wildcard rule
   below.

What not to take: tokenizer as a dependency (it is a server, not a library,
built on a 2023 `goproxy`, logrus and macaroons), sealed secrets (the broker
is local and per VM, so the socket already identifies the client) and the
in-proxy token-exchange processors (the Mac's CLIs already do that, with
the user's login).

## Architecture

```
guest                                         Mac
az ── https://management.azure.com ─┐
     /etc/hosts → 127.77.0.1        │
     skiff-intercept.socket :443 ───┴─ tunnel ─▶ broker socket
                                                 ├─ first byte 0x16 (TLS) → intercept
                                                 │    SNI = granted route host?
                                                 │    leaf cert from the VM's CA
                                                 │    Host == SNI, strip credential headers,
                                                 │    inject headers, audit, dial upstream (public IPs only)
                                                 └─ otherwise → today's HTTP handler
```

### Guest side: name-based, not HTTPS_PROXY

The spike used `HTTPS_PROXY` in a wrapper around `az`. The proposal instead
maps each intercepted host to a loopback address:

- a managed block in `/etc/hosts` (the existing `[[guest.blocks]]`
  mechanism) maps every intercept host of the granted capabilities to
  `127.77.0.1`;
- a second systemd socket, `skiff-intercept.socket` on `127.77.0.1:443`,
  forwards to the tunnel port with `systemd-socket-proxyd`, exactly like
  `skiff-broker.socket` does for `/run/skiff/broker.sock`.

Why: it needs no proxy support in the client (Node ignores `HTTPS_PROXY`,
Go and Python honour it inconsistently), it leaves all other traffic on the
direct path (no tunnel dependency, no passthrough, no SSRF surface on the
Mac) and it disappears with the grant. The cost is that `/etc/hosts` cannot
express wildcards (see Open questions).

### Broker side

- **Multiplexing on one socket.** The broker peeks at the first byte of each
  tunnelled connection: `0x16` (TLS handshake) goes to the intercept path,
  anything else to today's HTTP handler. One tunnel, one socket, no new
  forward.
- **Per-VM CA.** ECDSA P-256, `IsCA`, `MaxPathLenZero`, name constraints
  (critical): DNS names limited to the intercept hosts of the VM's granted
  capabilities and the names below them (X.509 DNS constraints always cover
  subdomains), no IP addresses, email and URI names only under the reserved
  TLD `invalid`. Certificate and key live together in
  `~/.skiff/vms/<vm>/intercept/ca.pem` (0600, replaced by one rename), are
  created on the first intercept grant and go with the VM's state (`skiff
  rm`, `skiff gc`, a new VM of the same name). The CA is re-issued (and the
  guest reprovisioned) only when a grant needs a host the CA does not cover
  yet. Revokes do not shrink it: grants are checked per request, and the
  constraints only matter if the key leaves the Mac. The broker reads the CA
  through a watcher per handshake, so a CA created or re-issued while the
  tunnel is up applies without a restart.
- **Leaf certificates** are issued on demand per host, valid 24 h, cached in
  memory.
- **Routing.** SNI must name an intercept route of a capability the VM is
  granted (checked per connection *and* per request, as today). Unknown SNI:
  the handshake is aborted and the attempt audited. Inside the TLS stream
  every request must carry `Host` equal to the SNI.
- **Injection** reuses the proxy route handler: `filterHeaders`, header
  templates rendered per request, `FlushInterval: -1`. Audit lines gain the
  host.
- **ALPN** offers `http/1.1` only at first (az, the Python and Node SDKs and
  curl are fine with it; gRPC is not, see GCP).
- **Upstream dial guard** as described above, introduced together with
  wildcard routes; exact-host routes dial their declared host.

### Capability files

An intercept route is a proxy route with `intercept = true`. Its upstream
defaults to `https://<host>`:

```toml
[[proxy.routes]]
host = "management.azure.com"
intercept = true
[proxy.routes.headers]
Authorization = "Bearer {{ secret \"cmd:az account get-access-token --resource https://management.core.windows.net/ --query accessToken -o tsv\" }}"
```

`skiff cap lint` rules: intercept hosts follow `routableHost` (public DNS
names only); a host may be intercepted by one capability only; header
templates must inject at least one credential header (an intercept route
without injection makes no sense and only widens the CA).

Wildcards are not allowed at first. A wildcard is only safe when every name
under the suffix is terminated by the service the token is meant for
(`*.vault.azure.net`). It is never safe when customers can host content under
the suffix (`*.azurewebsites.net`, `*.github.io`): the guest would send the
real token to a host it controls. Key Vaults and storage accounts are
therefore listed by name in the user's own capability file, which is also
least privilege.

### Placeholder tokens and identity endpoints

SDKs that fetch tokens from a local identity endpoint get placeholders:

- **Azure:** the guest gets `IDENTITY_ENDPOINT`/`IDENTITY_HEADER`. The
  endpoint answers with a **static** JWT that carries tenant, object id and
  UPN, expires in 2100 and has an invalid signature. az decodes it without
  verification and Azure rejects it; one placeholder serves every resource
  because the broker ignores the guest's token. It is generated once on the
  Mac (`az`, `jq`, `base64`) and served by an ordinary exec capability
  (`command = "cat"`), so skiff needs no Azure code. Spike 3 confirmed this
  through the real broker.
- **GCP (later):** `GCE_METADATA_HOST` pointing at a metadata emulation with
  an opaque placeholder.
- **AWS (later):** `AWS_CONTAINER_CREDENTIALS_FULL_URI` with dummy keys; the
  broker re-signs with SigV4.

### Guest provisioning

New in the provisioning script, only while an intercept capability is
granted:

- the CA certificate at `/usr/local/share/ca-certificates/skiff.crt`, then
  `update-ca-certificates` when the file changed (the first provisioning
  step that runs a command; keep it a fixed, built-in step, not a cap
  feature);
- `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` pointing at
  the system bundle in `/etc/environment`;
- the `/etc/hosts` block and `skiff-intercept.socket`.

`skiff revoke` removes all of it, as it does for blocks and the relay today.

## What it covers

| Capability | Today | With intercept |
|---|---|---|
| `azure` (example in `examples/caps/`) | not possible without a token in the guest | az, Azure SDKs (`DefaultAzureCredential` picks up the managed-identity variables), placeholders only |
| `azure-devops` (user file) | git via `insteadOf`, PAT | plus `az devops`/`az repos`/`az pipelines`, REST scripts, Azure Artifacts feeds (`pkgs.dev.azure.com`) without per-tool config. Azure DevOps also accepts Entra tokens (resource `499b84ac-1321-427f-aa17-267ca6975798`), so the PAT can go and the Mac's az login is used instead |
| `github` | git (`insteadOf`), gh (`http_unix_socket`); `gh release download` fails on redirects | additionally any client calling `https://api.github.com` (Octokit, curl, Go private modules). Redirects to `objects.githubusercontent.com` go direct and work. The existing hooks keep working; migrating them is optional |
| `claude` | `ANTHROPIC_BASE_URL` | no change needed |
| AWS | not possible | phase 4: credentials endpoint + SigV4 processor (ported from tokenizer) |
| GCP | not possible | phase 4: metadata emulation; needs wildcards (`*.googleapis.com`) and HTTP/2 for gRPC |
| private npm/PyPI registries | possible today with broker URLs per tool | works with the registry's real URL |

Not covered: Docker registries (token dance over several hosts),
`kubectl` against clusters with private CAs (the broker would need the
cluster CA), anything over SSH.

## Phasing

1. **Broker intercept core.** TLS multiplexing, per-VM CA, exact-host
   intercept routes, SNI/Host checks, audit
   with host, lint rules. Guest: CA install step, `/etc/hosts` block,
   `skiff-intercept.socket`. No capability ships yet; tests use a fake
   upstream via `Broker.Transport`.
2. **`azure` example capability**, no Go code: `examples/caps/azure.toml`
   with ARM and Graph intercept routes and the static managed-identity
   endpoint, the placeholder generator next to it, docs on adding Key Vaults
   and storage accounts by name and on a dedicated identity
   (`AZURE_CONFIG_DIR` or a service principal). It doubles as the manual
   acceptance test for phase 1. Delete `spike/azure/` afterwards.
3. **Azure DevOps via Entra tokens** as an example user capability; evaluate
   whether `github` should move to intercept.
4. **AWS and GCP** (SigV4 port, credentials and metadata endpoints),
   depending on the wildcard and HTTP/2 decisions.

## Testing

- Unit: CA and leaf issuance (name constraints present and enforced by
  `x509.Verify`), multiplexer (TLS vs. HTTP first byte), SNI not granted →
  handshake aborted, `Host` ≠ SNI → 421, guest `Authorization` stripped,
  injection rendered per request, dial guard (private, loopback, link-local,
  CGNAT, IPv6 ULA), revoke during an open TLS connection → next request 403.
- Guest script: golden tests like the existing ones for the CA step, hosts
  block and socket units, including revoke.
- e2e (`make e2e`): a VM with an intercept route to a public echo-free test
  upstream; curl through the hosts mapping; placeholder never visible in the
  upstream request.
- Manual: the spike's Azure checklist (`spike/azure/README.md`).

## Open questions

1. **Wildcards.** A small DNS hook in the guest (e.g. a resolved/dnsmasq
   rule for a suffix) versus explicit hostnames forever. Needed for GCP, not
   for Azure.
2. **Secret TTL.** `cmd:` results are cached 60 s; access tokens live 60–90
   min. A per-reference TTL (or reading `expires_on`) would save an az call
   per minute and route.
3. **HTTP/2.** Needed for gRPC clients (GCP); not for phase 1–3.
Decided:

- The CA key is a 0600 file (like `~/.skiff/id_ed25519`), not a Keychain
  item.
- Intercepted requests keep their path verbatim, percent-encoding included
  (Graph addresses users by UPN, `%40`): they go to the root of their own
  host, so there is no cap name to split off and no base path to climb out
  of; `cap lint` refuses intercept upstreams with a path. Dot segments,
  empty segments, backslashes and NUL are still refused.
- TLS session tickets are off, so every connection passes the route and
  grant check in the handshake; the server name is quoted in audit lines.
