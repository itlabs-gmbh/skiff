#!/bin/sh
# Writes the managed-identity response azure-identity.toml serves: a JWT for
# the Mac's az login with tenant and identity, no valid signature and an
# expiry in 2100, since the broker injects a fresh real token on every
# intercepted request. It holds nothing secret.
#
#   sh azure-identity.sh          # writes ~/.skiff/azure-identity.json
#   sh azure-identity.sh FILE     # writes FILE instead
#
# The file is replaced only when everything succeeded, so a failure never
# leaves an empty file behind. Needs az (logged in) and jq, which ships with
# macOS 15 and later. Set AZURE_CONFIG_DIR as for azure.toml to describe a
# dedicated identity; for a service principal the object id is looked up
# best effort (az login --identity only needs the tenant).
set -eu

out=${1:-$HOME/.skiff/azure-identity.json}

# 2100-01-01T00:00:00Z
EXPIRES_ON=4102444800

fail() {
	echo "azure-identity.sh: $*" >&2
	exit 1
}

for tool in az jq base64; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

account=$(az account show --query "{tid: tenantId, type: user.type, name: user.name}" --output json 2>/dev/null) ||
	fail "az is not logged in; run az login first"
tid=$(printf '%s' "$account" | jq -r '.tid // empty')
type=$(printf '%s' "$account" | jq -r '.type // empty')
name=$(printf '%s' "$account" | jq -r '.name // empty')
[ -n "$tid" ] || fail "az did not report a tenant"

if [ "$type" = user ]; then
	identity=$(az ad signed-in-user show --query "{oid: id, upn: userPrincipalName}" --output json) ||
		fail "could not read the signed-in user from Microsoft Graph"
	claims=$(printf '%s' "$identity" | jq -c '{oid, upn, unique_name: .upn, idtyp: "user"}')
else
	# A service principal: user.name is its application id.
	oid=$(az ad sp show --id "$name" --query id --output tsv 2>/dev/null || true)
	claims=$(jq -cn --arg appid "$name" --arg oid "$oid" '{appid: $appid, idtyp: "app"} + (if $oid == "" then {} else {oid: $oid} end)')
fi

b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

header=$(printf '%s' '{"alg":"RS256","typ":"JWT","kid":"skiff-placeholder"}' | b64url)
body=$(jq -cn --arg tid "$tid" --argjson exp "$EXPIRES_ON" --argjson claims "$claims" '{
  aud: "https://management.core.windows.net/",
  iss: ("https://sts.windows.net/" + $tid + "/"),
  tid: $tid, iat: 0, nbf: 0, exp: $exp, skiff: "placeholder"
} + $claims') || fail "could not build the placeholder"
payload=$(printf '%s' "$body" | b64url)
signature=$(printf '%s' 'skiff-placeholder-no-signature' | b64url)

dir=$(dirname "$out")
mkdir -p "$dir"
tmp=$(mktemp "$dir/.azure-identity.XXXXXX")
trap 'rm -f "$tmp"' EXIT
jq -cn --arg token "$header.$payload.$signature" --arg exp "$EXPIRES_ON" \
	'{access_token: $token, expires_on: $exp, token_type: "Bearer"}' >"$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
echo "wrote $out" >&2
