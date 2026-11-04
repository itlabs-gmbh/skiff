#!/bin/sh
# Spike: print a static managed-identity response for the Mac's az login.
# The JWT carries tenant, object id and UPN only and has no valid signature;
# it never expires because the broker injects a fresh real token anyway.
#   make-placeholder.sh > placeholder.json
set -eu

# 2100-01-01T00:00:00Z
EXPIRES_ON=4102444800

b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

tid=$(az account show --query tenantId --output tsv)
oid=$(az ad signed-in-user show --query id --output tsv)
upn=$(az ad signed-in-user show --query userPrincipalName --output tsv)

header=$(printf '%s' '{"alg":"RS256","typ":"JWT","kid":"skiff-placeholder"}' | b64url)
payload=$(jq -cn --arg tid "$tid" --arg oid "$oid" --arg upn "$upn" --argjson exp "$EXPIRES_ON" '{
  aud: "https://management.core.windows.net/",
  iss: ("https://sts.windows.net/" + $tid + "/"),
  tid: $tid, oid: $oid, upn: $upn, unique_name: $upn, idtyp: "user",
  iat: 0, nbf: 0, exp: $exp, skiff: "placeholder"
}' | b64url)
signature=$(printf '%s' 'skiff-placeholder-no-signature' | b64url)

jq -cn --arg token "$header.$payload.$signature" --arg exp "$EXPIRES_ON" \
  '{access_token: $token, expires_on: $exp, token_type: "Bearer"}'
