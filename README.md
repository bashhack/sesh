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

- **Extensible Plugin Architecture** — Add new authentication providers with a single interface
- **Encrypted Vault by Default** — Secrets live in an encrypted SQLite vault (AES-256-GCM, Argon2id) unlocked with your master password, on macOS and Linux alike. No setup: the first command creates it
- **Master-Password Agent** — A per-user background agent holds the key so you type the password once; it locks itself when idle and is hardened against memory inspection ([Using the sesh agent](docs/USAGE_AND_CONFIGURATION.md#using-the-sesh-agent))
- **Recovery Key** — Optional: a code you write down when the vault is created; if you forget the master password, `sesh recover` uses it to set a new one. No server involved, and sesh keeps no copy
- **Touch ID Unlock (macOS)** — Unlock the agent with your fingerprint instead of the master password, through a Secure Enclave key (nothing in the Keychain); the password always works as a fallback
- **Config File** — Optional `~/.config/sesh/config.toml`; `sesh config` shows every setting and where it came from
- **Encrypted Export** — Portable backups protected by a password, safe to transfer between machines (`--format encrypted`)
- **Password Manager** — Store and retrieve passwords, API keys, TOTP secrets, and secure notes, each with a URL, encrypted notes, and custom fields, and find them by any part of a service or user name or the URL's host
- **Terminal-First Workflow** — Authenticate without leaving the terminal
- **Shell Completion** — Tab completion for commands, flags, and their values in bash, zsh, and fish (`sesh completion zsh`)
- **Smart TOTP Handling** — Generate current and next codes, handle time window edge cases automatically. Supports non-standard configs (SHA-256/SHA-512, 8 digits, custom periods) extracted from QR codes
- **Clipboard Auto-Clear** — Clipboard is automatically cleared 30 seconds after copying secrets (configurable: `clipboard_timeout`)
- **Intelligent Subshell** — Isolate credentials in secure environments with built-in helper commands
- **QR Code Scanning** — Set up TOTP by selecting the QR code region on screen
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

Start by setting up your first provider entry.

### Prerequisites

- **For AWS provider:** [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) must be installed and configured with at least one profile.
- **For TOTP provider:** No additional dependencies — works with any service that supports standard TOTP (RFC 6238).
- **For Password provider:** No additional dependencies.
- **For `-clip` on Linux:** `wl-copy` (wl-clipboard) under Wayland, or `xclip` or `xsel` under X11. macOS has one built in.

### Setup Wizards

Each available `-setup` guides you through configuration for a given provider:

```bash
# Setup AWS MFA
sesh -service aws -setup

# Setup TOTP service
sesh -service totp -setup
```

Features:
- Interactive QR code scanning (select the QR code region on screen)
- Manual secret entry fallback
- Automatic secret validation
- Step-by-step instructions


## Usage

### Available Service Providers

#### AWS Provider (`-service aws`)
Manages AWS CLI authentication with MFA support. Without flags, launches a secure subshell with temporary credentials.

```bash
# Access provider-specific help
sesh -service aws -help

# Launch secure subshell (default)
sesh -service aws

# Copy TOTP code(s) for AWS Web Console
sesh -service aws -clip

# Use specific AWS profile
sesh -service aws -profile production

# Print credentials instead of subshell
sesh -service aws -no-subshell

# List all AWS entries
sesh -service aws -list

# Delete an AWS entry
sesh -service aws -delete <entry-id>
```

#### TOTP Provider (`-service totp`)
Generic TOTP provider for any service (GitHub, Google, Slack, etc.).

```bash
# Access provider-specific help
sesh -service totp -help

# Copy code to clipboard
sesh -service totp -service-name github -clip

# Use specific profile (for multiple accounts)
sesh -service totp -service-name github -profile work

# List all TOTP entries
sesh -service totp -list

# Delete a TOTP entry
sesh -service totp -delete <entry-id>
```

#### Password Provider (`-service password`)
Secure password manager for passwords, API keys, TOTP secrets, and secure notes.

```bash
# Access provider-specific help
sesh -service password -help

# Generate a password, store it, and copy to clipboard
sesh -service password -action generate -service-name github -username alice -clip

# Generate without symbols, custom length
sesh -service password -action generate -service-name stripe -username alice -no-symbols -length 32

# Store a password manually (interactive prompt)
sesh -service password -action store -service-name github -username alice

# Retrieve a password
sesh -service password -action get -service-name github -username alice -show

# Copy password to clipboard
sesh -service password -action get -service-name github -username alice -clip

# Store and generate TOTP codes
sesh -service password -action totp-store -service-name github -username alice
sesh -service password -action totp-generate -service-name github -username alice
sesh -service password -action totp-generate -service-name github -username alice -clip   # copy the code

# A URL, notes, and custom fields (plain, or secret and encrypted)
sesh edit password/github/alice --url https://github.com/login --field recovery-email=alice@example.com --secret-field pin
sesh edit password/github/alice --notes --editor
sesh show password/github/alice            # secrets hidden; --reveal shows them
sesh -service password -action get -service-name github -username alice -field pin -clip

# Search across all entries
sesh -service password -action search -query github

# List all entries (with optional filters)
sesh -service password -list
sesh -service password -list -entry-type api_key
sesh -service password -list -sort updated_at -limit 10

# Delete an entry
sesh -service password -delete <entry-id>

# Export all entries to JSON file
sesh -service password -action export -file backup.json

# Export API keys only as CSV
sesh -service password -action export -format csv -entry-type api_key -file keys.csv

# Import from file
sesh -service password -action import -file backup.json
sesh -service password -action import -file data.csv -format csv -on-conflict skip

# JSON output
sesh -service password -action get -service-name github -username alice -format json
sesh -service password -action search -query github -format json
```

### Subshell Features (AWS)

When you run `sesh -service aws`, you enter a secure subshell with:

#### Visual Indicators
- Custom prompt showing active sesh session (e.g., `(sesh:aws) $`)
- Credential expiry countdown via `sesh_status` command

#### Built-in Commands
- `sesh_status` — Show session details and test AWS connection
- `verify_aws` — Quick AWS authentication check
- `sesh_help` — Display available subshell commands
- `exit` or `Ctrl+D` — Leave the secure environment

#### Environment Variables
- `SESH_ACTIVE=1` — Detect a sesh session in scripts
- `SESH_SERVICE=aws` — Which provider is active
- Standard AWS credential variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)


### Quick Reference

#### Global Options
```bash
-service <provider>              # Required for provider operations (aws, totp, password)
-list-services                   # Show available providers (no -service needed)
-version                         # Display version info
-help                            # Show help
```

#### Common Operations
```bash
-list                           # List entries for service
-delete <id>                    # Delete entry by ID
-setup                          # Run setup wizard
-clip                           # Copy to clipboard
```

#### AWS-Specific Options
```bash
-profile <name>                 # AWS profile (default: $AWS_PROFILE)
-no-subshell                    # Print exports instead of subshell
-force                          # Delete without asking
```

#### TOTP-Specific Options
```bash
-service-name <name>            # Service name (github, google, etc.) [REQUIRED]
-profile <name>                 # Account profile (work, personal, etc.)
-force                          # Delete without asking
```

#### Password-Specific Options
```bash
-action <action>                # store, get, generate, search, export, import, totp-store, totp-generate
-service-name <name>            # Service name
-username <name>                # Username for the service
-entry-type <type>              # password, api_key, totp, secure_note (filter for -list)
-query <text>                   # Search query (for -action search)
-format <format>                # Output format: table (default), json
-show                           # Display password instead of clipboard hint
-field <name>                   # With get: a field, url, or notes instead of the secret
                                # With store: set a field, name=value (repeat for more)
-secret-field <name>            # With store: set a secret field, typed hidden
-url <url>                      # With store: the entry's web address
-notes [-editor]                # With store: notes, from stdin or $EDITOR
-file <path>                    # File path for export/import (default: stdout/stdin)
-on-conflict <strategy>         # Import conflict: skip, overwrite (default: error)
-force                          # Skip confirmation prompts
-length <n>                     # Generated password length (default 24)
-no-symbols                     # Exclude symbols from generated passwords
-sort <field>                   # Sort by: service, created_at, updated_at
-limit <n>                      # Limit results
-offset <n>                     # Skip first N results
```

#### Storage
```bash
# Default: an encrypted vault unlocked with your master password (macOS and Linux)
sesh -service password -list
# → the first command explains what it's creating, asks for a new master
#   password twice, and unlocks the background sesh agent, so later commands
#   don't prompt until the agent locks itself

# Optional guided setup: choose where secrets live, create the vault
sesh init

# See every setting and where it came from
sesh config

# Non-interactive (CI/scripting — exposes password to process env)
SESH_MASTER_PASSWORD=... sesh -service password -list

# Change your master password (every entry is re-encrypted)
sesh --rekey
```

See [Using the sesh agent](docs/USAGE_AND_CONFIGURATION.md#using-the-sesh-agent) for how the agent starts, locks, and stops. It needs no management; `sesh agent status`, `lock`, and `stop` are there if you want them.

#### Encrypted Export / Import
```bash
# Export to a portable password-encrypted file (uses Argon2id + AES-256-GCM)
sesh -service password -action export -format encrypted -file backup.enc
# → prompts for password (twice for confirmation)

# Import an encrypted backup
sesh -service password -action import -format encrypted -file backup.enc
# → prompts for password
```

## Documentation

- [Usage & Configuration](docs/USAGE_AND_CONFIGURATION.md) — Start here for setup prerequisites, example output, and daily workflows
- [Security Model](docs/SECURITY_MODEL.md) — Threat model, what sesh protects and what it doesn't
- [Architecture Overview](docs/ARCHITECTURE.md) — Technical design for contributors
- [Plugin Development](docs/PLUGIN_DEVELOPMENT.md) — Step-by-step guide to building new providers

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
