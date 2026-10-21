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
  its own, in `SESH_DEV_DIR` (an absolute path; default
  `~/.local/share/sesh-dev`):

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
- **Don't copy:** these use the real clipboard: `sesh copy`, `--clip`,
  `add --generate` and `generate --copy` (they copy the new password),
  `history --clip`, and `sesh aws` while it signs in (it puts the MFA code
  there). In `sesh ui`: Enter and Ctrl-Y, the copy actions, the password
  generator, and saving a generated password. Read the code instead, or use
  `sesh get`.
- **Don't run `sesh touchid enable` or `sesh browser install`** unless asked:
  the first makes a key in the Mac's secure chip, tied to the person's
  fingerprints; the second repoints their browsers (below). And don't accept
  `sesh sync init`'s offer of an iCloud Drive folder: iCloud copies it to the
  person's other computers.
- Stop every agent and process you start (`scripts/sesh-dev agent stop`), and
  put a time limit on every test run, so nothing is left behind.

### What the two still share

- **The browser extension.** The browser starts whatever sesh the script in the
  daily data folder (`browser-host`) names, without `scripts/sesh-dev`'s
  settings, so it always runs on the daily vault and agent.
  `scripts/sesh-dev browser …` refuses for that reason; to try the extension
  against a dev build, try the build as the daily sesh (below).
- **The agent's log**, `agent.log` in the user cache folder: both agents write
  to it.
- **The clipboard**, and the AWS CLI's own files: `scripts/sesh-dev aws` uses
  the real `~/.aws`. For AWS work without AWS, see `scripts/README.md` (a mock
  AWS CLI).
- **What the dev sesh starts** keeps its settings: in `sesh run`'s command,
  `sesh aws`'s shell and the notes editor, `SESH_DB_PATH`, `SESH_AUTH_SOCK`
  and `XDG_CONFIG_HOME` point at the dev folder, so a `sesh` run there uses
  the dev vault, and other programs (git, an editor) look for their config in
  it. The other way round, a `scripts/sesh-dev aws` run inside the daily
  sesh's AWS shell refuses ("already in a sesh environment"), except for a
  profile that signs in with `aws login` or SSO whose session has ended: the
  dev build signs it in again.
- **`sesh init`:** it offers the default vault location, not the dev one;
  `scripts/sesh-dev init` gives it the dev vault's.

### Trying a dev build as the daily sesh

Rarely, a change needs trying for real before it's released:

```bash
go build -o ~/go/bin/sesh ./sesh/cmd/sesh   # a folder on PATH after Homebrew's
brew unlink sesh && hash -r                 # now `sesh` is the dev build
~/go/bin/sesh browser install               # the extension too, if needed
# … and back:
rm ~/go/bin/sesh && brew link sesh && hash -r
sesh browser install                        # the extension back to Homebrew's
```

While it's unlinked, a `browser-host` script naming Homebrew's sesh points at
nothing, so the extension only works after the `browser install` above.

## Building and testing

- Go 1.27+, and on macOS Xcode's command line tools: Touch ID and the screen
  lock check are built with cgo.
- `go build ./...`, then test only the packages you changed while you work
  (`go test ./internal/tui/`). CI runs everything, and the race detector in
  three parts. It leaves Argon2id uninstrumented, for speed, which needs a Go
  experiment turned off too, or it reports false races:

  ```bash
  GOEXPERIMENT=nosizespecializedmalloc go test -race -gcflags='golang.org/x/crypto/argon2=-race=false' ./internal/...
  ```

  A plain `go test -race` works as well, more slowly.
- `make dev/setup/hooks` installs the pre-commit hook: goimports and
  `go build ./...`, then go vet and golangci-lint on the packages a commit
  touches. `make audit` tidies, formats, vets, lints and tests everything, and
  rewrites files as it goes.
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
