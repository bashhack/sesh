<p align="center">
  <img src="./docs/assets/sesh_logo.png" alt="sesh logo" width="300">
</p>

<div align="center">

[![Tests](https://github.com/bashhack/sesh/actions/workflows/ci.yml/badge.svg)](https://github.com/bashhack/sesh/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/bashhack/sesh/graph/badge.svg?token=Y3K7R3MHXH)](https://codecov.io/gh/bashhack/sesh)
[![Go Reference](https://pkg.go.dev/badge/github.com/bashhack/sesh)](https://pkg.go.dev/github.com/bashhack/sesh)
[![Go Report Card](https://goreportcard.com/badge/github.com/bashhack/sesh)](https://goreportcard.com/report/github.com/bashhack/sesh)

</div>

# sesh — A terminal-first authentication toolkit for secure credential workflows

> A developer-friendly CLI that brings AWS MFA, TOTP authentication, and secure password management to your terminal, backed by an encrypted vault.

## Purpose

I was tired of relying on browser extensions or native desktop apps from corporate vendors—tools that often feel like security theater while quietly harvesting data. I needed something lightweight, security-conscious, and that respects user privacy.

In particular, I wanted fast, secure MFA support directly in the terminal—both for AWS console access and for web-based TOTP forms. I was frustrated by how tightly MFA workflows are coupled to mobile devices, and I wanted to break free from that dependency.

**sesh fills that gap.** It's simple, scriptable, and works well for:
- AWS CLI + console MFA workflows
- Web-based MFA flows where a TOTP secret is available
- Secure storage for passwords, API keys, notes and files

While sesh overlaps a bit with tools like aws-vault, it goes further by offering a general-purpose CLI-based authentication and credential management experience—no mobile device, no browser, no bloat. Your security, your control, your terminal.

## Features

- **Terminal App** — `sesh ui`: search every entry as you type, copy with Enter, and edit, file, and look after the vault, in one screen
- **Encrypted Vault** — Secrets live in an encrypted SQLite vault (AES-256-GCM, Argon2id) unlocked with your master password, on macOS and Linux alike. No setup: the first command creates it
- **Master-Password Agent** — A per-user background agent holds the key so you type the password once; it locks itself when idle, after 8 hours, when the computer sleeps or (on macOS) its screen locks, and when you quit `sesh ui`, and is hardened against memory inspection ([Using the sesh agent](docs/USAGE_AND_CONFIGURATION.md#using-the-sesh-agent))
- **Recovery Key** — Optional: a code you write down when the vault is created; if you forget the master password, `sesh recover` uses it to set a new one. No server involved, and sesh keeps no copy
- **Touch ID Unlock (macOS)** — Unlock the agent with your fingerprint instead of the master password, through a Secure Enclave key (nothing in the Keychain); the password always works as a fallback
- **Config File** — Optional `~/.config/sesh/config.toml`; `sesh config` shows every setting and where it came from, and `sesh config set` changes one
- **Automatic Backups** — A copy of the encrypted vault each day, the newest 7 kept (`sesh backup`, `sesh restore`)
- **Encrypted Export** — Entries protected by a password of their own, to move them to another machine (`sesh export`; `sesh import --from sesh` reads it)
- **Import** — From Bitwarden, KeePass, Chrome, Firefox, Safari, Google Authenticator and LastPass Authenticator (`sesh import`)
- **Trash and History** — A deleted entry stays in the trash for 30 days, and each entry keeps its earlier secrets, so either can be brought back
- **Folders and Tags** — Put entries in folders and tag them, and narrow lists and searches by them
- **Health and Checks** — `sesh health` finds weak, reused and old passwords; `sesh doctor` checks the setup and that every entry can be read
- **Password Manager** — Store and retrieve passwords, API keys, TOTP secrets, secure notes, and files kept whole (a kubeconfig, a TLS key), each with a URL, encrypted notes, and custom fields, and find them by any part of a service or user name or the URL's host
- **Secrets for commands** — `sesh run` puts vault values in a command's environment and hides them in its output; `sesh inject` fills a config template; `sesh git-credential` gives git a site's password as its credential helper
- **Terminal-First Workflow** — Authenticate without leaving the terminal
- **Shell Completion** — Tab completion for commands, flags, and their values in bash, zsh, and fish (`sesh completion zsh`)
- **Smart TOTP Handling** — Generate current and next codes, handle time window edge cases automatically. Supports non-standard configs (SHA-256/SHA-512, 8 digits, custom periods) extracted from QR codes
- **Clipboard Auto-Clear** — Clipboard is automatically cleared 30 seconds after copying secrets (configurable: `clipboard_timeout`)
- **AWS Sign-in Shell** — `sesh aws` opens a shell with the session's credentials and helper commands; they leave with the shell when it exits
- **QR Codes** — Set up TOTP by selecting the QR code on screen (macOS) or from a screenshot or photo (`--qr-image`); move a key to your phone with `sesh show --qr`
- **Passphrases** — `sesh generate --words 6` makes a passphrase from the [EFF's long word list](https://www.eff.org/dice) (CC BY 4.0), as `--generate` does when storing a password
- **AWS Profiles and Several Accounts** — `sesh aws --profile production`; several accounts on one site, told apart by username
- **Audit Logging** — Every secret read (except the TOTP codes `sesh ui` draws), change and deletion is logged; review it with `sesh audit`. Events are kept 90 days by default (`audit.retention_days`)

## Installation

> **Platform:** macOS and Linux. The vault, encrypted and unlocked with your master password, works the same on both and needs no setup. Touch ID unlock is macOS-only.

```bash
# Option 1: Install with Homebrew (macOS and Linux)
brew install bashhack/sesh/sesh
# Note: Homebrew adds sesh to your PATH, and installs its shell completion
# for bash, zsh and fish (turn on Homebrew's completion to use it)

# Option 2: Download a pre-built binary: macOS (zip) or Linux (tar.gz),
# for x86_64 or arm64
# Visit: https://github.com/bashhack/sesh/releases

# Option 3: Build from source (requires Go 1.27+). `go install …@latest`
# doesn't work: sesh's go.mod replaces two modules with forks.
git clone https://github.com/bashhack/sesh && cd sesh
go build -o ~/go/bin/sesh ./sesh/cmd/sesh   # ~/go/bin needs to be in your PATH
```

## Quick Start

Type `sesh` for every command, or `sesh <command> --help` for one.

```bash
sesh add password github --username alice   # type it (hidden), or pipe it in
sesh add password shop --generate           # a strong one, copied as it's saved
sesh add totp github --qr                   # select the QR code on screen
sesh copy github password                   # its password
sesh copy github totp                       # its TOTP code
sesh ui                                     # search everything; Enter copies
```

The first command creates your vault: it says where, and asks for a master
password, twice. A background agent then keeps it unlocked for a while, so
later commands don't ask again until it locks itself.

### Prerequisites

- **AWS sign-in:** the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), installed and configured with at least one profile.
- **TOTP codes:** nothing more; any service that uses standard TOTP (RFC 6238).
- **Copying on Linux:** `wl-copy` (wl-clipboard) under Wayland, or `xclip` or `xsel` under X11. macOS has one built in.

## Usage

Every command works on the whole vault: passwords, API keys, notes, files and
TOTP entries. An `<entry>` is a few words of its name or username, as `sesh ui`'s
search takes them (`github alice`; a kind word such as `totp` or `note`
narrows), or its ID, such as `password/github/alice`. When several entries
match, sesh asks which at a terminal, and lists them otherwise.

### Finding and using entries

```bash
sesh list                          # every entry
sesh list notes                    # or of a kind: passwords, keys, notes, totp, files
sesh list --folder work --tag dev  # narrowed by folder and tag
sesh search github                 # by any part of a name, username, or site
sesh copy github password          # copy the password (the clipboard clears after 30s)
sesh copy github --username        # or --url, or --field pin
sesh get openai                    # print it, for a pipe
sesh code github                   # a TOTP code, and how long it has left
sesh show github --reveal          # URL, notes, fields, folder and tags
sesh open github                   # its URL, in the browser
```

Add `--json` to `list`, `search`, `get`, `code`, `show` or `health` for output a program reads.

### Adding and changing entries

```bash
sesh add password github --username alice --url https://github.com/login
sesh add key openai                # an API key
sesh add file kubeconfig --from ~/.kube/config   # a file, kept whole
echo "door code 4711" | sesh add note house
sesh add totp github --qr          # or --qr-image shot.png, or type the key, or paste an otpauth:// link
sesh show totp github --qr         # its key as a QR code, to scan with a phone
sesh edit github --rename github-work
sesh edit github --field recovery-email=alice@example.com --secret-field pin
sesh edit github --notes --editor
sesh generate --length 32          # a new password, stored nowhere
sesh generate --words 6            # or a passphrase
sesh trash github                  # into the trash; sesh trash lists and restores
sesh history github                # earlier secrets: --show N, --clip N, --restore N
sesh folder move work github       # and sesh tag add urgent github
```

### Secrets for commands

```bash
sesh run --env OPENAI_API_KEY=sesh://api_key/openai -- python app.py
sesh run --env-file .env -- npm start      # .env holds NAME=sesh://... references, no secrets
sesh run --env KUBECONFIG=sesh://file/kubeconfig -- kubectl get pods   # a file entry, as a file
sesh inject -i config.yml.tpl -o config.yml
git config --global credential.helper '!sesh git-credential'   # git's HTTPS passwords from sesh
```

### Bringing entries over, and taking them out

```bash
sesh import --from google-authenticator IMG_1234.png   # its "Transfer accounts" QR codes
sesh import --from bitwarden bitwarden_export.json
sesh import --from keepass Passwords.xml
sesh import --from lastpass-authenticator accounts.json
sesh import --from chrome "Chrome Passwords.csv"       # also firefox, safari
sesh export --file backup.enc       # encrypted with a password of its own
sesh import --from sesh backup.enc  # back in, on this machine or another
```

Each import shows what it found, and what's already in the vault, before it asks.

### AWS

```bash
sesh aws setup                     # store a profile's MFA key: from a QR code, or typed
sesh aws                           # sign in: a shell with the session's credentials
sesh aws --profile production
sesh aws --no-subshell             # print the credentials, to eval
sesh aws --clip                    # copy the MFA code, for the AWS console
```

For a profile that signs in with [`aws login`](https://docs.aws.amazon.com/signin/latest/userguide/command-line-sign-in.html) or SSO, `sesh aws` signs in when the session has ended, with the MFA code on the clipboard, and opens the shell with `AWS_PROFILE` set, so the AWS CLI keeps the credentials fresh.

`sesh aws` opens your own shell, with your usual setup, plus the session's credentials and:
- `(sesh:aws)` before your prompt;
- `sesh_status` (the session, and a check of the AWS connection), `verify_aws`, and `sesh_help`;
- `SESH_ACTIVE=1` and `SESH_SERVICE=aws`, with the standard `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`;
- `exit` or Ctrl-D to leave.

### The vault and keeping it safe

```bash
sesh config                        # every setting, and where it comes from
sesh config set clipboard_timeout 15s  # change one in the config file
sesh init                          # choose where the vault lives (optional)
sesh lock                          # lock now: the next command asks for the master password
sesh passwd                        # change the master password (every entry is re-encrypted)
sesh recovery new                  # a recovery key, in case you forget it
sesh touchid enable                # unlock with your fingerprint (macOS)
sesh backup                        # sesh also backs up on its own (backup.every_days)
sesh backup list                   # the backups; sesh backup delete <name> deletes one
sesh health                        # weak, reused and old passwords
sesh doctor                        # check the setup, and that everything reads
```

For scripts, `SESH_MASTER_PASSWORD` gives the master password without a prompt;
it exposes the password to the process environment, so keep it to CI. See
[Using the sesh agent](docs/USAGE_AND_CONFIGURATION.md#using-the-sesh-agent) for
how the agent starts, locks, and stops.

## Documentation

- [Usage & Configuration](docs/USAGE_AND_CONFIGURATION.md) — Start here for setup prerequisites, example output, and daily workflows
- [Security Model](docs/SECURITY_MODEL.md) — Threat model, what sesh protects and what it doesn't
- [Architecture Overview](docs/ARCHITECTURE.md) — Technical design for contributors

## Development

### Prerequisites
- Go 1.27+
- macOS or Linux (Touch ID unlock is macOS-only)
- Make (optional — provides convenience targets, but `go build ./sesh/cmd/sesh` works directly)
- On macOS, Xcode's command line tools: Touch ID unlock and locking when the screen locks are built with cgo, and a build without a C compiler quietly has neither. Linux builds are pure Go

### Building
```bash
# Clone repository
git clone https://github.com/bashhack/sesh.git
cd sesh

# Build binary
make build

# Run tests
make test

# Generate coverage
make coverage

# Tidy, format, vet, lint and test (rewrites files)
make audit
```

## License

MIT License - see [LICENSE](LICENSE) for details.
