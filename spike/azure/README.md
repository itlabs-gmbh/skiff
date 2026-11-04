# Spike: Azure CLI in a skiff VM through the broker

Goal: `az` in the guest without `az login` in the guest, so the refresh
token stays on the Mac.

## How

`az login --identity` in the guest finds `IDENTITY_ENDPOINT` and
`IDENTITY_HEADER` (set by the `azure` capability's `[guest.env]`) and treats
the VM as Azure App Service. Every token request,
`GET {{.BrokerURL}}/azure?api-version=2019-08-01&resource=…`, goes through the
broker to the exec program `skiff-cap-azure` on the Mac. It checks the
resource against an allowlist and answers with
`az account get-access-token --resource <resource>` in App Service's JSON
shape. The guest's az then calls Azure directly over HTTPS.

Try it (the `command` path in `azure.toml` is absolute; fix it after a move):

```sh
cp spike/azure/azure.toml ~/.skiff/caps/ && skiff cap lint azure
skiff new azspike --mem 2048
skiff ssh azspike 'curl -sL https://aka.ms/InstallAzureCLIDeb | bash'
skiff grant azspike azure
skiff ssh azspike 'az login --identity && az group list -o table'
```

## Results (2026-11-03, host az 2.86, guest az 2.92 on Ubuntu 24.04 arm64)

| Check | Result |
|---|---|
| `az login --identity` without grant | fails after 1.3 s: IMDS `169.254.169.254` blocked by the guest firewall |
| `az login --identity` with grant | works in 0.8 s, lists both subscriptions of the Mac's login |
| ARM (`az group list`, `az vm list`) in a new session | works, ~1.2 s per command |
| Graph (`az rest …/v1.0/me`, `az ad signed-in-user show`) | works: the "managed identity" is the Mac's user token |
| Resource outside the allowlist (SQL) | refused; reason in the audit log, guest sees `ERROR: None, None` |
| Tokens on the guest disk | none in `/root/.azure` (MSAL keeps MI tokens in memory) |
| `skiff revoke` | env vars removed, az falls back to the blocked IMDS and fails |
| Host program latency | ~0.65 s per token (host az serves from its own MSAL cache) |

## Findings

- Works with the broker as it is today; no Go change needed.
- An access token (~60–90 min, no refresh token) does reach the guest.
  Revoking stops new tokens, not one already issued.
- The guest acts with the full rights of the Mac's az login. The allowlist
  limits audiences, not subscriptions or roles; a dedicated
  `AZURE_CONFIG_DIR` or service principal on the Mac would limit that.
- Errors are opaque in the guest (MSAL turns the broker's 502 into
  `None, None` plus an `az login` hint). The audit log records only the path,
  not the requested resource.
- az shows the user as `systemAssignedIdentity`; tenant and subscription
  follow the Mac's az defaults.

# Spike 2: no real token in the guest (`mitm/`)

`mitm/` is a stand-alone prototype of a credential-injecting broker. On the
Mac it:

- serves the managed-identity endpoint (`/mi`) with a **placeholder JWT**:
  the real token's identity claims (`tid`, `oid`, `upn`, `aud`, `exp`, …)
  and the signature `skiff-placeholder-no-signature`. az only decodes the
  token without verifying it, Azure rejects it;
- answers `CONNECT` for `management.azure.com`, `graph.microsoft.com`,
  `*.vault.azure.net` and `*.blob.core.windows.net` by terminating TLS with a
  per-run CA (name-constrained to exactly those domains, key only on the Mac),
  replacing `Authorization` with a real token minted by the Mac's az for that
  host's resource, and forwarding over TLS;
- tunnels every other `CONNECT host:443` unchanged, but only to public
  addresses.

In the guest, a wrapper `/usr/local/bin/az` sets `HTTPS_PROXY`, `NO_PROXY`,
`IDENTITY_ENDPOINT`, `IDENTITY_HEADER` and `REQUESTS_CA_BUNDLE` for az only;
the CA goes to `/usr/local/share/ca-certificates` + `update-ca-certificates`.
The guest reaches the proxy through `ssh -R 18080:<unix socket>`.

## Results (2026-11-03, same versions)

| Check | Result |
|---|---|
| `az login --identity`, `az group list`, `az keyvault list` (ARM) | work, ~1.0–1.1 s per command |
| `az ad signed-in-user show` (Graph) | works |
| `az keyvault secret list` (Key Vault data plane, `*.vault.azure.net`) | works |
| Token the guest holds (`az account get-access-token`) | placeholder, signature `skiff-placeholder-no-signature` |
| That token sent straight to ARM, bypassing the proxy | `401` |
| `CONNECT` to `localhost`, `192.168.64.1`, `10.0.0.1` via the proxy | refused (non-public) |
| Tokens on the guest disk | none |
| Tunnel closed | az fails at once (`Connection refused`) |
| Audit | every Azure request logged with method, host, path, status |

## Findings

- The approach holds: az works end to end and the guest never sees a real
  token. Revocation is immediate; there is nothing to replay elsewhere.
- az telemetry (`dc.services.visualstudio.com`) went through the passthrough.
  `az config set core.collect_telemetry=false` would avoid that.
- Still out of scope: what the identity itself can read lands in the guest
  (Key Vault secret values, storage keys, `az acr login`, `az aks
  get-credentials`). Limit the identity behind the proxy.
- Not tested: claims challenges (Conditional Access/CAE), storage data plane,
  long uploads/streams, HTTP/2.
- For the broker: CONNECT + per-VM CA + wildcard routes + token per route
  (the existing `cmd:` secrets with 60 s cache would do), plus a guest
  provisioning step to install the CA, which skiff does not have yet.

# Spike 3: static placeholder through the real broker (`static-mi/`)

Question: does the managed-identity endpoint need any Azure code, or can a
plain capability file serve a placeholder that never changes?

- `static-mi/make-placeholder.sh` builds the managed-identity response once
  with `az account show`, `az ad signed-in-user show`, `jq` and `base64`: a
  JWT with `tid`, `oid`, `upn`, `exp` = 2100-01-01 and the signature
  `skiff-placeholder-no-signature`, plus `expires_on` = 2100-01-01. It holds
  no secret.
- `static-mi/azure-mi.toml` is an ordinary exec capability (`command = "cat"`)
  that returns that file. `skiff grant` sets `IDENTITY_ENDPOINT` and
  `IDENTITY_HEADER`; the guest wrapper only sets the proxy and CA bundle.
- Real tokens were still injected by `mitm/` (phase 1 does not exist yet).

## Results (2026-11-03, same versions)

| Check | Result |
|---|---|
| `az login --identity` | works (2.0 s), both subscriptions |
| Token the guest holds | the static placeholder, `expiresOn` 2100-01-01 |
| `az group list`, `az ad signed-in-user show`, `az keyvault secret list` | work; one placeholder (aud ARM) serves ARM, Graph and Key Vault |
| `az role assignment list --assignee <oid>` (uses the token's `oid` locally) | works |
| Managed-identity requests | answered by the broker's exec cap (audit: `cap=azure-mi … 200`); no az call on the Mac |

## Findings

- No Azure-specific code is needed in skiff: phase 2 becomes an example
  capability plus a generator script.
- The placeholder only has to be regenerated when the Mac's az login moves
  to another user or tenant.
- Not covered: switching tenants per request (`az login --identity` sees one
  tenant, the one in the placeholder).
