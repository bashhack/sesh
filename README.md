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

> A developer-friendly CLI that brings AWS MFA and TOTP authentication to your terminal, backed by macOS Keychain security.

## Purpose

I was tired of relying on browser extensions or native desktop apps from corporate vendors—tools that often feel like security theater while quietly harvesting data. I needed something lightweight, security-conscious, and that respects user privacy.

In particular, I wanted fast, secure MFA support directly in the terminal—both for AWS console access and for web-based TOTP forms. I was frustrated by how tightly MFA workflows are coupled to mobile devices, and I wanted to break free from that dependency.

**sesh fills that gap.** It's simple, scriptable, and works well for both:
- AWS CLI + console MFA workflows
- Web-based MFA flows where a TOTP secret is available

While sesh overlaps a bit with tools like aws-vault, it goes further by offering a general-purpose CLI-based TOTP experience—no mobile device, no browser, no bloat. Your security, your control, your terminal.

## Features

- **Extensible Plugin Architecture** — Add new authentication providers with a single interface
- **Secure by Design** — Store all secrets in macOS Keychain with binary path restrictions
- **Terminal-First Workflow** — Authenticate without leaving the terminal
- **Smart TOTP Handling** — Generate current and next codes, handle time window edge cases automatically
- **Intelligent Subshell** — Isolate credentials in secure environments with built-in helper commands
- **QR Code Scanning** — Set up TOTP by selecting the QR code region on screen
- **Multiple Profile Support** — Manage dev/prod environments and multiple accounts per service

## Installation

> **Platform:** sesh requires macOS. It uses the macOS Keychain for secret storage and the system `security` command for access control. Linux and Windows support is planned for a future release.

```bash
# Option 1: Install with Homebrew (macOS)
brew install bashhack/sesh/sesh
# Note: Homebrew automatically adds sesh to your PATH, so it's ready to use immediately

# Option 2: Install using Go (requires Go 1.24+)
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
-service <provider>              # Service provider (aws, totp) [REQUIRED]
-list-services                   # Show available providers
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

## Documentation

- [Usage & Configuration](docs/USAGE_AND_CONFIGURATION.md) — Start here for setup prerequisites, example output, and daily workflows
- [Security Model](docs/SECURITY_MODEL.md) — Threat model, what sesh protects and what it doesn't
- [Architecture Overview](docs/ARCHITECTURE.md) — Technical design for contributors
- [Plugin Development](docs/PLUGIN_DEVELOPMENT.md) — Step-by-step guide to building new providers

## Development

### Prerequisites
- Go 1.24+
- macOS (for Keychain integration)
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
