# Working on sesh

For anyone changing sesh, person or coding agent. If you use sesh day to day
as well, the first thing is keeping the sesh you use apart from the one you're
working on.

## Two seshes: the one in use, and the one being built

- **The daily sesh** is an installed release (`brew install bashhack/sesh/sesh`,
  so `/opt/homebrew/bin/sesh`). Its vault, config, agent and Touch ID key are in
  the default places: `~/Library/Application Support/sesh/` (on Linux
  `~/.local/share/sesh/`), `~/.config/sesh/config.toml`, and the agent's socket
  under the user cache folder.
- **The dev sesh** is this checkout, run with `scripts/sesh-dev`. It builds the
  working tree to `build/sesh-dev` and runs it on a vault, config and agent of
  its own, in `SESH_DEV_DIR` (default `~/.local/share/sesh-dev`):

  ```bash
  scripts/sesh-dev add password github --username alice
  scripts/sesh-dev ui
  ```

Don't run a development build against the daily sesh's vault, config or agent.
The two would also replace each other's agent on every switch (an agent from
another build is replaced), so the daily sesh would keep asking to unlock.

### For coding agents

- **Use a throwaway folder for every run,** never the person's dev vault or the
  daily one, and give the master password in the environment, with a small key
  setting so it's quick:

  ```bash
  export SESH_DEV_DIR=$(mktemp -d) SESH_MASTER_PASSWORD=throwaway-test-1 SESH_KDF_MEMORY=19MiB
  printf 'pw\n' | scripts/sesh-dev add password demo --username me
  scripts/sesh-dev list
  ```

  `mktemp -d` gives a short enough path: an agent socket's path can be at most
  103 characters on macOS. Delete the folder when you're done.
- **Don't touch:** the daily vault, `~/.config/sesh`, the running agent,
  `~/.aws`, or the person's tmux sessions. Use a separate tmux server
  (`tmux -L <name>`) to drive `sesh ui`.
- **Don't copy:** `sesh copy`, `--clip`, `add --generate` (it copies the new
  password) and `history --clip` use the real clipboard. Read the code instead,
  or use `sesh get`.
- **Don't run `sesh touchid enable`, or `sesh browser install`** unless asked:
  the first makes a key in the Mac's secure chip, tied to the person's
  fingerprints; the second repoints their browsers (below).
- Stop every agent and process you start (`scripts/sesh-dev agent stop`), and
  put a time limit on every test run, so nothing is left behind.

### What the two still share

- **The browser extension.** The browser starts whatever sesh the script in the
  daily data folder (`browser-host`) names. `scripts/sesh-dev browser install`
  points it at the dev build, to try the extension against it;
  `sesh browser install` (the daily one) points it back. A `go run` build is
  refused: its path is gone when it ends.
- **The agent's log**, `agent.log` in the user cache folder: both agents write
  to it.
- **The clipboard**, and the AWS CLI's own files: `scripts/sesh-dev aws` uses
  the real `~/.aws`. For AWS work without AWS, see `scripts/README.md` (a mock
  AWS CLI).
- `scripts/sesh-dev` sets `XDG_CONFIG_HOME` to its own folder, so programs run
  through it (`sesh run`) read their own config from there too.

### Trying a dev build as the daily sesh

Rarely, a change needs trying for real before it's released:

```bash
go build -o ~/go/bin/sesh ./sesh/cmd/sesh   # a folder on PATH after Homebrew's
brew unlink sesh                            # now `sesh` is the dev build
# … and back:
brew link sesh
```

## Building and testing

- Go 1.27+, and on macOS Xcode's command line tools: Touch ID and the screen
  lock check are built with cgo.
- `go build ./...`, then test only the packages you changed while you work
  (`go test ./internal/tui/`). CI runs everything, and the race detector in
  three parts; to run it locally, set `GOEXPERIMENT=nosizespecializedmalloc`
  as CI does: without it, the race detector reports false races in Argon2id's
  code.
- `make dev/setup/hooks` installs the pre-commit hook (gofmt, go vet and
  golangci-lint, on the packages a commit touches). `make audit` tidies,
  formats, vets, lints and tests everything, and rewrites files as it goes.
- `make agent-smoke` runs the agent end to end.

## Changes

- **One pull request per change**, each on its own branch (a git worktree per
  branch keeps them apart). Each is reviewed before it's merged, and CI must
  pass.
- **Commit messages are one line,** saying what the change does.
- **Stage files by name,** not `git add -A`: a checkout can hold notes and
  scratch files that aren't meant for the repo.
- **Comments and docs say how things are,** not how they came to be.
  `docs/USAGE_AND_CONFIGURATION.md`, `docs/SECURITY_MODEL.md` and
  `docs/ARCHITECTURE.md` are checked against the code; change them with it.

## Releasing

Tag `vX.Y.Z` on `main` and push the tag. The release job tests it again,
builds, signs and notarizes the macOS binaries, publishes the GitHub release,
and updates the Homebrew formula in `bashhack/homebrew-sesh`. A tag with
`.github/release-notes/<tag>.md` is released with those notes; otherwise, with
the commits since the last tag. Then `brew upgrade sesh` updates the daily sesh.
