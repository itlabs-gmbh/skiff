#!/bin/sh
# End-to-end test of broker intercept routes against a real VM.
#
# A test capability intercepts httpbin.org, which echoes the request headers
# back. The guest calls https://httpbin.org/headers with a placeholder token;
# the test passes when the echo shows the value injected on the Mac instead
# of the placeholder, and when a revoke sends the guest to the real host
# again. The injected value is a random test string, never a credential:
# an echo service is exactly where real credentials must not go.
#
# Needs a prepared skiff (skiff prepare) and internet access in the guest.
# Usage: scripts/e2e-intercept.sh [path/to/skiff]
set -eu

SKIFF=${1:-./bin/skiff}
VM=e2e-intercept
CAP=e2e-intercept
HOST=httpbin.org
CAPS_DIR=${SKIFF_HOME:-$HOME/.skiff}/caps
CAP_FILE=$CAPS_DIR/$CAP.toml
SKIFF_E2E_SECRET=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
export SKIFF_E2E_SECRET

tunnel_pid=
cleanup() {
	[ -n "$tunnel_pid" ] && kill "$tunnel_pid" 2>/dev/null || true
	"$SKIFF" rm "$VM" >/dev/null 2>&1 || true
	rm -f "$CAP_FILE"
}
trap cleanup EXIT INT TERM

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

if [ -e "$CAP_FILE" ]; then
	fail "$CAP_FILE exists; remove it first"
fi
mkdir -p "$CAPS_DIR"
cat > "$CAP_FILE" <<EOF
name = "$CAP"
description = "e2e test of intercept routes (echo service, test value only)"
[proxy]
upstream = "https://$HOST"
[proxy.headers]
X-Skiff-E2e = "{{ secret \"env:SKIFF_E2E_SECRET\" }}"
[[proxy.routes]]
host = "$HOST"
intercept = true
[proxy.routes.headers]
X-Skiff-E2e = "{{ secret \"env:SKIFF_E2E_SECRET\" }}"
Authorization = "Bearer {{ secret \"env:SKIFF_E2E_SECRET\" }}"
EOF

"$SKIFF" cap lint "$CAP"
"$SKIFF" new "$VM" --mem 1024 >/dev/null
"$SKIFF" grant "$VM" "$CAP"
"$SKIFF" tunnel "$VM" >/dev/null 2>&1 &
tunnel_pid=$!
sleep 3

echo "==> intercepted request"
resolved=$("$SKIFF" ssh "$VM" "getent hosts $HOST" | awk '{print $1}')
[ "$resolved" = 127.77.0.1 ] || fail "$HOST resolves to '$resolved', want 127.77.0.1"
echo=$("$SKIFF" ssh "$VM" "curl -sf -H 'Authorization: Bearer placeholder' https://$HOST/headers")
echo "$echo" | grep -q "\"X-Skiff-E2e\": \"$SKIFF_E2E_SECRET\"" || fail "injected header missing: $echo"
echo "$echo" | grep -q "Bearer $SKIFF_E2E_SECRET" || fail "placeholder not replaced: $echo"
if echo "$echo" | grep -q placeholder; then fail "placeholder reached the upstream: $echo"; fi

echo "==> TLS for a host nobody intercepts is untouched"
"$SKIFF" ssh "$VM" "curl -sf -o /dev/null https://example.com/" || fail "plain HTTPS from the guest broke"

echo "==> revoke"
"$SKIFF" revoke "$VM" "$CAP" >/dev/null
resolved=$("$SKIFF" ssh "$VM" "getent hosts $HOST" | awk '{print $1}')
[ "$resolved" != 127.77.0.1 ] || fail "$HOST still points at the broker after revoke"
echo=$("$SKIFF" ssh "$VM" "curl -sf https://$HOST/headers")
if echo "$echo" | grep -q "$SKIFF_E2E_SECRET"; then fail "value still injected after revoke"; fi

echo "PASS"
