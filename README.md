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

> A developer-friendly CLI that brings AWS MFA, TOTP authentication, and secure password management to your terminal, backed by macOS Keychain or an encrypted SQLite store.

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
- **Dual Storage Backends** — macOS Keychain (default) or encrypted SQLite with AES-256-GCM and Argon2id key derivation (`SESH_BACKEND=sqlite`)
- **Two Key Sources for SQLite** — macOS Keychain (default) or user-supplied master password (`SESH_KEY_SOURCE=password`) for fully cross-platform, keychain-free operation
- **Encrypted Export** — Portable backups protected by a password, safe to transfer between machines (`--format encrypted`)
- **Password Manager** — Store and retrieve passwords, API keys, TOTP secrets, and secure notes with full-text search
- **Terminal-First Workflow** — Authenticate without leaving the terminal
- **Smart TOTP Handling** — Generate current and next codes, handle time window edge cases automatically. Supports non-standard configs (SHA-256/SHA-512, 8 digits, custom periods) extracted from QR codes
- **Clipboard Auto-Clear** — Clipboard is automatically cleared 30 seconds after copying secrets
- **Intelligent Subshell** — Isolate credentials in secure environments with built-in helper commands
- **QR Code Scanning** — Set up TOTP by selecting the QR code region on screen
- **Multiple Profile Support** — Manage dev/prod environments and multiple accounts per service
- **Audit Logging** — Every access, modification, and deletion is logged for security review

## Installation

> **Platform:** The default backend (macOS Keychain) requires macOS. The SQLite backend (`SESH_BACKEND=sqlite`) uses pure-Go encryption and works on macOS, Linux, and Windows. By default it still stores the encryption key in the macOS Keychain, but setting `SESH_KEY_SOURCE=password` enables a master-password mode that is fully keychain-free and works on any platform.

```bash
# Option 1: Install with Homebrew (macOS)
brew install bashhack/sesh/sesh
# Note: Homebrew automatically adds sesh to your PATH, so it's ready to use immediately

# Option 2: Install using Go (requires Go 1.25+)
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
- **For Password provider:** No additional dependencies. Uses the SQLite backend automatically when `SESH_BACKEND=sqlite` is set, or the system keychain otherwise.

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
sesh -service password -action generate -service-name github -username alice -no-symbols -length 32

# Store a password manually (interactive prompt)
sesh -service password -action store -service-name github -username alice

# Retrieve a password
sesh -service password -action get -service-name github -username alice -show

# Copy password to clipboard
sesh -service password -action get -service-name github -username alice -clip

# Store and generate TOTP codes
sesh -service password -action totp-store -service-name github -username alice
sesh -service password -action totp-generate -service-name github -username alice

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
```

#### TOTP-Specific Options
```bash
-service-name <name>            # Service name (github, google, etc.) [REQUIRED]
-profile <name>                 # Account profile (work, personal, etc.)
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
-file <path>                    # File path for export/import (default: stdout/stdin)
-on-conflict <strategy>         # Import conflict: skip, overwrite (default: error)
-force                          # Skip confirmation prompts
-length <n>                     # Generated password length (default 24)
-no-symbols                     # Exclude symbols from generated passwords
-sort <field>                   # Sort by: service, created_at, updated_at
-limit <n>                      # Limit results
-offset <n>                     # Skip first N results
```

#### Storage Backend
```bash
# Default: macOS Keychain
sesh -service aws

# SQLite backend (AES-256-GCM encrypted, Argon2id key derivation)
SESH_BACKEND=sqlite sesh -service password -list
```

#### Key Source (SQLite backend only)
```bash
# Default: master key stored in macOS Keychain (keychain-assisted)
SESH_BACKEND=sqlite sesh -service password -list

# Master password: key derived from passphrase, no keychain needed (cross-platform)
SESH_BACKEND=sqlite SESH_KEY_SOURCE=password sesh -service password -list
# → prompts for master password; first run asks twice for confirmation

# Non-interactive (CI/scripting — exposes password to process env)
SESH_BACKEND=sqlite SESH_KEY_SOURCE=password SESH_MASTER_PASSWORD=... sesh -service password -list
```

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
- Go 1.25+
- macOS (for Keychain integration; SQLite backend works cross-platform)
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
