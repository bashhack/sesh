#!/usr/bin/env python3
"""Run a command in a pseudo-terminal, answering its password prompt.

Usage: SMOKE_PASSWORD=... pty-run.py <command> [args...]

Waits until the command prints "Master password:" before typing the
password, so the run doesn't depend on timing. Prints everything the
command wrote and exits with its exit code. Gives up after 60 seconds.
"""

import os
import pty
import select
import sys
import time

PROMPT = b"Master password:"


def main() -> int:
    password = os.environ["SMOKE_PASSWORD"].encode()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(sys.argv[1], sys.argv[1:])

    out = b""
    answered = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # the child closed the terminal
            break
        if not chunk:
            break
        out += chunk
        if not answered and PROMPT in out:
            os.write(fd, password + b"\r")
            answered = True
    else:
        os.kill(pid, 9)
        sys.stderr.write("pty-run: timed out after 60s\n")

    _, status = os.waitpid(pid, 0)
    sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
