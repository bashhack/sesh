#!/bin/bash
# make.sh writes this folder's files with sesh v0.1.1, all made-up: the
# vault (vault.db), an encrypted export (export.sesh) and a sync folder
# (sync/). They're kept as v0.1.1 wrote them; compat_test.go checks that
# today's sesh still reads them. Run it only to remake them, with v0.1.1:
#
#   internal/compat/testdata/v0.1.1/make.sh /path/to/sesh-0.1.1
#
# Nothing personal goes in: a throwaway home for everything, made-up
# passwords, and a made-up computer name (sync records which computer made
# each change, and anyone can open these files with the password below).
set -euo pipefail

sesh=$1
out=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
"$sesh" --version | grep -q '^sesh version 0.1.1 ' || {
	echo "make.sh: $sesh isn't sesh 0.1.1" >&2
	exit 2
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home" "$tmp/config" "$tmp/out"
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/config"
export SESH_DB_PATH="$tmp/out/vault.db" SESH_AUTH_SOCK="$tmp/agent.sock"
export SESH_MASTER_PASSWORD=fixture-v0.1.1-master SESH_SYNC_NAME=test-laptop
export SESH_KDF_MEMORY=19MiB SESH_KDF_TIME=2 SESH_KDF_THREADS=1
unset SESH_BACKUP_DIR SESH_SYNC_DIR

printf 'gh-pass-1\n' | "$sesh" add password GitHub --username maya --url https://github.com/login --folder work --tag dev
"$sesh" edit password/GitHub/maya --field recovery-email=maya@example.com
printf '4711\n' | "$sesh" edit password/GitHub/maya --secret-field pin
printf 'Personal account. Recovery codes in the safe.\n' | "$sesh" edit password/GitHub/maya --notes
printf 'gh-pass-2\n' | "$sesh" edit password/GitHub/maya --secret
printf 'gh-pass-3\n' | "$sesh" edit password/GitHub/maya --secret
printf 'JBSWY3DPEHPK3PXP\n' | "$sesh" add totp GitHub --username maya --folder work
printf 'sk-test-0123456789abcdef\n' | "$sesh" add key OpenAI --folder work --tag dev
printf 'Door code 4711\nAlarm 2580\n' | "$sesh" add note House --folder home
printf 'apiVersion: v1\nkind: Config\n' >"$tmp/kubeconfig"
"$sesh" add file kubeconfig --from "$tmp/kubeconfig" --folder work
printf 'old-shop-pass\n' | "$sesh" add password Shop --username maya@example.org
"$sesh" trash --force password/Shop/maya@example.org

# The export asks for its password at a terminal: a pseudo-terminal answers.
python3 - "$sesh" export --file "$tmp/out/export.sesh" <<'EOF'
import os, pty, select, signal, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
out, seen, deadline = b"", 0, time.monotonic() + 60
while time.monotonic() < deadline:
    if not select.select([fd], [], [], 1)[0]:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    last = out[seen:].rstrip().lower().split(b"\n")[-1]
    if b"password" in last and last.endswith(b":"):
        os.write(fd, b"fixture-v0.1.1-export\n")
        seen = len(out)
else:
    os.kill(pid, signal.SIGKILL)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
EOF

mkdir "$tmp/sync"
"$sesh" sync init "$tmp/sync" </dev/null

rm -rf "$out/vault.db" "$out/export.sesh" "$out/sync"
cp "$tmp/out/vault.db" "$tmp/out/export.sesh" "$out/"
cp -R "$tmp/sync" "$out/sync"
chmod -R u=rwX,go=rX "$out/vault.db" "$out/export.sesh" "$out/sync"
echo "Wrote $out"
