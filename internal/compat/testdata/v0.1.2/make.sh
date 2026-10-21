#!/bin/bash
# make.sh writes this folder's export.sesh with sesh v0.1.2, all made-up: an
# encrypted export whose entries carry earlier secrets (v0.1.2 is the first
# release whose encrypted exports hold them). It's kept as v0.1.2 wrote it;
# compat_test.go checks that today's sesh still reads it. Run it only to
# remake it, with v0.1.2:
#
#   internal/compat/testdata/v0.1.2/make.sh /path/to/sesh-0.1.2
#
# Nothing personal goes in: a throwaway home for everything, made-up
# passwords, and a made-up computer name.
set -euo pipefail

sesh=$1
out=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
"$sesh" --version | grep -q '^sesh version 0.1.2 ' || {
	echo "make.sh: $sesh isn't sesh 0.1.2" >&2
	exit 2
}

# Nothing from the caller's own sesh settings.
for v in $(compgen -e | grep '^SESH_' || true); do
	unset "$v"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home" "$tmp/config" "$tmp/out"
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/config"
export SESH_DB_PATH="$tmp/out/vault.db" SESH_AUTH_SOCK="$tmp/agent.sock"
export SESH_MASTER_PASSWORD=fixture-v0.1.2-master SESH_SYNC_NAME=test-laptop
export SESH_KDF_MEMORY=19MiB SESH_KDF_TIME=2 SESH_KDF_THREADS=1

# A password with two earlier ones, and a file with an earlier version under
# another name.
printf 'gh-pass-1\n' | "$sesh" add password GitHub --username maya --url https://github.com/login --folder work --tag dev
printf 'gh-pass-2\n' | "$sesh" edit password/GitHub/maya --secret
printf 'gh-pass-3\n' | "$sesh" edit password/GitHub/maya --secret
mkdir -p "$tmp/files"
printf 'apiVersion: v1\nkind: Config\n# old\n' >"$tmp/files/old.yaml"
printf 'apiVersion: v1\nkind: Config\n' >"$tmp/files/config"
"$sesh" add file kubeconfig --from "$tmp/files/old.yaml" --folder work
"$sesh" edit file/kubeconfig --from "$tmp/files/config"

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
        os.write(fd, b"fixture-v0.1.2-export\n")
        seen = len(out)
else:
    os.kill(pid, signal.SIGKILL)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
EOF

rm -f "$out/export.sesh"
cp "$tmp/out/export.sesh" "$out/"
chmod u=rw,go=r "$out/export.sesh"
echo "Wrote $out/export.sesh"
