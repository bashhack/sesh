<p align="center">
  <img src="./docs/assets/sesh_logo.png" alt="sesh logo" width="300">
</p>

<div align="center">

[![Tests](https://github.com/bashhack/sesh/actions/workflows/ci.yml/badge.svg)](https://github.com/bashhack/sesh/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/bashhack/sesh/graph/badge.svg?token=Y3K7R3MHXH)](https://codecov.io/gh/bashhack/sesh)
[![Go Reference](https://pkg.go.dev/badge/github.com/bashhack/sesh)](https://pkg.go.dev/github.com/bashhack/sesh)
[![Go Report Card](https://goreportcard.com/badge/github.com/bashhack/sesh)](https://goreportcard.com/report/github.com/bashhack/sesh)
![CodeRabbit Reviews](https://img.shields.io/coderabbit/prs/github/bashhack/sesh?utm_source=oss&utm_medium=github&utm_campaign=bashhack%2Fsesh&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

</div>

# sesh — An extensible terminal-first authentication toolkit for secure credential workflows

> A developer-friendly CLI that brings AWS MFA, TOTP authentication, and secure password management to your terminal, backed by an encrypted vault.

## Purpose

I was tired of relying on browser extensions or native desktop apps from corporate vendors—tools that often feel like security theater while quietly harvesting data. I needed something lightweight, security-conscious, and that respects user privacy.

In particular, I wanted fast, secure MFA support directly in the terminal—both for AWS console access and for web-based TOTP forms. I was frustrated by how tightly MFA workflows are coupled to mobile devices, and I wanted to break free from that dependency.

**sesh fills that gap.** It's simple, scriptable, and works well for:
- AWS CLI + console MFA workflows
- Web-based MFA flows where a TOTP secret is available
- Secure storage for passwords, API keys, and notes

While sesh overlaps a bit with tools like aws-vault, it goes further by offering a general-purpose CLI-based authentication and credential management experience—no mobile device, no browser, no bloat. Your security, your control, your terminal.

## Features

- **Terminal App** — `sesh ui`: search every entry as you type, copy with Enter, and edit, file, and look after the vault, in one screen
- **Encrypted Vault by Default** — Secrets live in an encrypted SQLite vault (AES-256-GCM, Argon2id) unlocked with your master password, on macOS and Linux alike. No setup: the first command creates it
- **Master-Password Agent** — A per-user background agent holds the key so you type the password once; it locks itself when idle and is hardened against memory inspection ([Using the sesh agent](docs/USAGE_AND_CONFIGURATION.md#using-the-sesh-agent))
- **Recovery Key** — Optional: a code you write down when the vault is created; if you forget the master password, `sesh recover` uses it to set a new one. No server involved, and sesh keeps no copy
- **Touch ID Unlock (macOS)** — Unlock the agent with your fingerprint instead of the master password, through a Secure Enclave key (nothing in the Keychain); the password always works as a fallback
- **Config File** — Optional `~/.config/sesh/config.toml`; `sesh config` shows every setting and where it came from, and `sesh config set` changes one
- **Encrypted Export** — Portable backups protected by a password of their own, safe to move between machines (`sesh export`)
- **Password Manager** — Store and retrieve passwords, API keys, TOTP secrets, secure notes, and files kept whole (a kubeconfig, a TLS key), each with a URL, encrypted notes, and custom fields, and find them by any part of a service or user name or the URL's host
- **Secrets for commands** — `sesh run` puts vault values in a command's environment and hides them in its output; `sesh inject` fills a config template; `sesh git-credential` gives git a site's password as its credential helper
- **Terminal-First Workflow** — Authenticate without leaving the terminal
- **Shell Completion** — Tab completion for commands, flags, and their values in bash, zsh, and fish (`sesh completion zsh`)
- **Smart TOTP Handling** — Generate current and next codes, handle time window edge cases automatically. Supports non-standard configs (SHA-256/SHA-512, 8 digits, custom periods) extracted from QR codes
- **Clipboard Auto-Clear** — Clipboard is automatically cleared 30 seconds after copying secrets (configurable: `clipboard_timeout`)
- **Intelligent Subshell** — Isolate credentials in secure environments with built-in helper commands
- **QR Codes** — Set up TOTP by selecting the QR code on screen (macOS) or from a screenshot or photo (`--qr-image`); move a key to your phone with `sesh show --qr`
- **Passphrases** — `sesh generate --words 6` makes a passphrase from the [EFF's long word list](https://www.eff.org/dice) (CC BY 4.0), as `--generate` does when storing a password
- **Multiple Profile Support** — Manage dev/prod environments and multiple accounts per service
- **Audit Logging** — Every access, modification, and deletion is logged; review it with `sesh audit`. Events are kept 90 days by default (`audit.retention_days`)

## Installation

> **Platform:** macOS and Linux. The vault, encrypted and unlocked with your master password, works the same on both and needs no setup. Touch ID unlock is macOS-only.

```bash
# Option 1: Install with Homebrew (macOS)
brew install bashhack/sesh/sesh
# Note: Homebrew automatically adds sesh to your PATH, so it's ready to use immediately

# Option 2: Install using Go (requires Go 1.27+)
go install github.com/bashhack/sesh/sesh/cmd/sesh@latest
# Note: Ensure your Go bin directory (typically $HOME/go/bin) is in your PATH
# You can add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):
# export PATH=$PATH:$HOME/go/bin

# Option 3: Download pre-built binary
# Visit: https://github.com/bashhack/sesh/releases
```

## Quick Start

Type `sesh` for every command, or `sesh <command> --help` for one.

```bash
sesh add password github --username alice   # type it (hidden), or pipe it in
sesh add password shop --generate           # a strong one, copied as it's saved
sesh add totp github --qr                   # select the QR code on screen
sesh copy github                            # its password, or a TOTP entry's code
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

Every command works on the whole vault: passwords, API keys, notes and TOTP
entries. An `<entry>` is a few words of its name or username, as `sesh ui`'s
search takes them (`github alice`; a kind word such as `totp` or `note`
narrows), or its ID, such as `password/github/alice`. When several entries
match, sesh asks which at a terminal, and lists them otherwise.

### Finding and using entries

```bash
sesh list                          # every entry
sesh list notes                    # or of a kind: passwords, keys, notes, totp
sesh list --folder work --tag dev  # narrowed by folder and tag
sesh search github                 # by any part of a name, username, or site
sesh copy github alice             # copy the password (the clipboard clears after 30s)
sesh copy github --username        # or --url, or --field pin
sesh get openai                    # print it, for a pipe
sesh code github                   # a TOTP code, and how long it has left
sesh show github --reveal          # URL, notes, fields, folder and tags
sesh open github                   # its URL, in the browser
```

Add `--json` to `list`, `search`, `get`, `code` or `show` for output a program reads.

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

`sesh aws` opens a shell with the session's credentials and:
- a prompt that shows the session, such as `(sesh:aws) $`;
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

# Run all checks
make audit
```

## License

MIT License - see [LICENSE](LICENSE) for details.
