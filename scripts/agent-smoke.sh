#!/usr/bin/env bash
# End-to-end check of the sesh agent with a real binary, in an isolated
# HOME: vault creation, unlock through a terminal, agent-served reads,
# the wire format, and lock/stop. Usage: scripts/agent-smoke.sh <sesh-binary>
set -euo pipefail

SESH=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
# Short path: Unix socket paths are limited to 104 bytes on macOS.
SOCK=$(mktemp -u /tmp/sesh-smoke.XXXXXX)
PASSWORD=correct-horse-battery

cleanup() {
	run "$SESH" agent stop >/dev/null 2>&1 || true
	rm -rf "$WORK" "$SOCK" "$SOCK.spawn.lock"
}
trap cleanup EXIT

# A clean environment, so nothing from the caller's sesh setup leaks in.
run() {
	env -i PATH=/usr/bin:/bin HOME="$WORK" TERM=dumb \
		SESH_KEY_SOURCE=password SESH_AUTH_SOCK="$SOCK" "$@"
}

fail() {
	echo "FAIL: $*" >&2
	# The agent logs under the isolated HOME (Library/Caches on macOS,
	# .cache on Linux).
	find "$WORK" -name agent.log -exec sed "s/^/  agent log: /" {} + >&2 || true
	exit 1
}

expect_contains() { # <label> <haystack> <needle>
	case "$2" in
	*"$3"*) echo "ok: $1" ;;
	*) fail "$1: expected '$3' in: $2" ;;
	esac
}

# 1. The run that creates the vault must not start an agent.
out=$(echo "smoke-secret" | run SESH_MASTER_PASSWORD=$PASSWORD "$SESH" -service password \
	-action store -service-name smoke -entry-type secure_note 2>&1) ||
	fail "vault creation: $out"
expect_contains "vault created" "$out" "Stored secure_note"
expect_contains "no agent after vault creation" "$(run "$SESH" agent status)" "agent: not running"

# 2. The next interactive run prompts once, starts the agent, and decrypts.
out=$(run SMOKE_PASSWORD=$PASSWORD python3 "$HERE/pty-run.py" "$SESH" -service password -action get \
	-service-name smoke -entry-type secure_note -show 2>&1) || fail "interactive get: $out"
expect_contains "unlock through a terminal" "$out" "smoke-secret"
expect_contains "agent unlocked" "$(run "$SESH" agent status)" "state: unlocked"

# 3. Later runs need no password and no terminal: the agent serves them.
out=$(run "$SESH" -service password -action get -service-name smoke -entry-type secure_note -show </dev/null 2>&1) ||
	fail "passwordless read: $out"
expect_contains "agent serves a read without a password" "$out" "smoke-secret"

# 4. The wire format a client sees: hello then ping, newline-delimited JSON.
out=$(python3 - "$SOCK" 2>&1 <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(sys.argv[1])
f = s.makefile("rwb")
for msg in ({"type": "hello", "version": 1}, {"type": "ping", "version": 1}):
    f.write(json.dumps(msg).encode() + b"\n")
    f.flush()
    print(json.loads(f.readline())["type"])
PY
) || fail "wire check: $out"
expect_contains "hello_ack on the wire" "$out" "hello_ack"
expect_contains "pong on the wire" "$out" "pong"

# 5. lock drops the key; stop shuts the agent down and removes its socket.
expect_contains "lock" "$(run "$SESH" agent lock)" "agent locked"
expect_contains "locked after lock" "$(run "$SESH" agent status)" "state: locked"
expect_contains "stop" "$(run "$SESH" agent stop)" "agent stopped"
for _ in $(seq 1 50); do [ -e "$SOCK" ] || break; sleep 0.1; done
[ ! -e "$SOCK" ] || fail "socket still present after stop"
echo "ok: socket removed after stop"
expect_contains "not running after stop" "$(run "$SESH" agent status)" "agent: not running"

echo "agent smoke test passed"
