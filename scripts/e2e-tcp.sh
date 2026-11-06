#!/bin/sh
# End-to-end test of tcp capabilities against a real VM.
#
# A listener on the Mac's loopback stands in for a database proxy: it greets
# every connection with a random test string. A test capability hands it into
# the guest on another port. The test passes when the guest reads the greeting
# on its own 127.0.0.1, the connection shows up in the audit log, and a revoke
# closes the port for the guest again.
#
# Needs a prepared skiff (skiff prepare) and nc on the Mac.
# Usage: scripts/e2e-tcp.sh [path/to/skiff]
set -eu

SKIFF=${1:-./bin/skiff}
VM=e2e-tcp
CAP=e2e-tcp
UPSTREAM_PORT=47016
GUEST_PORT=47017
STATE=${SKIFF_HOME:-$HOME/.skiff}
CAP_FILE=$STATE/caps/$CAP.toml
GREETING=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')

# Cleanup only touches what this run created: a VM or cap file of the same
# name that existed before is left alone.
tunnel_pid=
upstream_pid=
created_vm=
created_cap=
cleanup() {
	if [ -n "$tunnel_pid" ]; then kill "$tunnel_pid" 2>/dev/null || true; fi
	if [ -n "$upstream_pid" ]; then
		kill "$upstream_pid" 2>/dev/null || true
		pkill -f "nc -l 127.0.0.1 $UPSTREAM_PORT" 2>/dev/null || true
	fi
	if [ -n "$created_vm" ]; then "$SKIFF" rm "$VM" >/dev/null 2>&1 || true; fi
	if [ -n "$created_cap" ]; then rm -f "$CAP_FILE"; fi
}
trap cleanup EXIT INT TERM

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# read_port prints what the guest reads from its side of the capability.
read_port() {
	"$SKIFF" ssh "$VM" "timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/$GUEST_PORT && head -c ${#GREETING} <&3' 2>/dev/null || true"
}

if [ -e "$CAP_FILE" ]; then
	fail "$CAP_FILE exists; remove it first"
fi
if "$SKIFF" inspect "$VM" >/dev/null 2>&1; then
	fail "a VM named $VM exists; remove it first"
fi

# The stand-in upstream: one greeting per connection, bound to loopback only.
(
	while :; do
		printf '%s' "$GREETING" | nc -l 127.0.0.1 "$UPSTREAM_PORT" >/dev/null 2>&1 || sleep 1
	done
) &
upstream_pid=$!

mkdir -p "$STATE/caps"
created_cap=1
cat > "$CAP_FILE" <<EOF
name = "$CAP"
description = "e2e test of tcp capabilities (loopback listener, test value only)"
[tcp]
upstream = "127.0.0.1:$UPSTREAM_PORT"
port = $GUEST_PORT
[guest.env]
SKIFF_E2E_TCP = "127.0.0.1:$GUEST_PORT"
EOF

"$SKIFF" cap lint "$CAP"
# --no-profile: the test must not depend on the checkout's .skiff being trusted.
"$SKIFF" new "$VM" --mem 1024 --no-profile >/dev/null
created_vm=1
"$SKIFF" grant "$VM" "$CAP"
"$SKIFF" tunnel "$VM" >/dev/null 2>&1 &
tunnel_pid=$!
sleep 3

echo "==> the guest reaches the upstream on its own loopback"
got=$(read_port)
[ "$got" = "$GREETING" ] || fail "the guest read '$got', want the greeting"
env=$("$SKIFF" ssh "$VM" 'echo $SKIFF_E2E_TCP')
[ "$env" = "127.0.0.1:$GUEST_PORT" ] || fail "guest env is '$env'"

echo "==> the connection is in the audit log"
grep -q "vm=$VM cap=$CAP allow TCP \"127.0.0.1:$UPSTREAM_PORT\"" "$STATE/audit.log" || fail "no allow line in $STATE/audit.log"

echo "==> revoke"
"$SKIFF" revoke "$VM" "$CAP" >/dev/null
got=$(read_port)
[ -z "$got" ] || fail "the guest still read '$got' after revoke"
grep -q "vm=$VM cap=$CAP deny TCP" "$STATE/audit.log" || fail "no deny line in $STATE/audit.log"

echo "PASS"
