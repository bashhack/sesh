<p align="center">
  <img src="./assets/gitbak_retro_logo.png" alt="gitbak logo" width="300">
</p>

<div align="center">
[![Tests](https://github.com/bashhack/gitbak/actions/workflows/ci.yml/badge.svg)](https://github.com/bashhack/gitbak/actions/workflows/ci.yml)


# sesh — An extensible terminal-first authentication toolkit for secure credential workflows

> A powerful CLI tool that manages secure authentication workflows for AWS, TOTP services, and beyond. Built with an extensible plugin architecture, sesh provides seamless credential management with macOS Keychain integration.

## 🎯 Purpose

I was tired of relying on browser extensions or native desktop apps from corporate vendors—tools that often feel like security theater while quietly harvesting data. I needed something lightweight, security-conscious, and that respects user privacy.

In particular, I wanted fast, secure MFA support directly in the terminal—both for AWS console access and for web-based TOTP forms. I was frustrated by how tightly MFA workflows are coupled to mobile devices, and I wanted to break free from that dependency.

**sesh fills that gap.** It's simple, scriptable, and works seamlessly for both:
- AWS CLI + console MFA workflows
- Web-based MFA flows where a TOTP secret is available

While sesh overlaps a bit with tools like aws-vault, it goes further by offering a general-purpose CLI-based TOTP experience—no mobile device, no browser, no bloat. Your security, your control, your terminal.

## 🌟 Features

- **Extensible Plugin Architecture** — Easy to add new authentication providers
-️ **Secure by Design** — All secrets stored in macOS Keychain with binary-level access control
- **Terminal-First Workflow** — Optimized for developers who live in the terminal
- **Smart TOTP Handling** — Generates current and next codes, handles edge cases automatically
- **Intelligent Subshell** — Isolated credential environments with built-in helper commands
- **QR Code Scanning** — Set up TOTP services directly from screenshots
- **Multiple Profile Support** — Manage dev/prod environments and multiple accounts per service

## 🚀 Quick Start

```bash
# Install via Homebrew
brew install bashhack/tap/sesh

# First-time setup for AWS
sesh --service aws --setup

# Launch secure AWS subshell
sesh --service aws

# Generate TOTP codes for any service
sesh --service totp --service-name github
```

## 📦 Installation

### Homebrew (Recommended)

```bash
brew install bashhack/tap/sesh
```

### Quick Install Script

```bash
curl -sSL https://raw.githubusercontent.com/bashhack/sesh/main/install.sh | bash
```

### Build from Source

```bash
git clone https://github.com/bashhack/sesh.git
cd sesh
make install
```

## 🎯 Usage Guide

### Available Service Providers

#### AWS Provider (`--service aws`)
Manages AWS CLI authentication with MFA support. By default, launches a secure subshell with temporary credentials.

```bash
# Launch secure subshell (default)
sesh --service aws

# Use specific AWS profile
sesh --service aws --profile production

# Print credentials instead of subshell
sesh --service aws --no-subshell

# List all AWS entries
sesh --service aws --list

# Delete an AWS entry
sesh --service aws --delete <entry-id>
```

#### TOTP Provider (`--service totp`)
Generic TOTP provider for any service (GitHub, Google, Slack, etc.).

```bash
# Generate TOTP code
sesh --service totp --service-name github

# Copy code to clipboard
sesh --service totp --service-name github --clip

# Use specific profile (for multiple accounts)
sesh --service totp --service-name github --profile work

# Setup new TOTP service
sesh --service totp --setup

# List all TOTP entries
sesh --service totp --list
```

### 🐚 Subshell Features (AWS)

When you run `sesh --service aws`, you enter a secure subshell with:

#### Visual Indicators
- Custom prompt showing active sesh session
- Credential expiry countdown
- Visual confirmation of secure environment

#### Built-in Commands
- `sesh_status` — Show session details and test AWS connection
- `verify_aws` — Quick AWS authentication check
- `sesh_help` — Display available subshell commands
- `exit` or `Ctrl+D` — Leave the secure environment

#### Environment Variables
- `SESH_ACTIVE=1` — Indicates active sesh session
- `SESH_SERVICE=aws` — Current service provider
- `SESH_EXPIRY` — Unix timestamp of credential expiration
- Standard AWS credential variables (`AWS_ACCESS_KEY_ID`, etc.)

### 🧙 Setup Wizards

Interactive setup guides you through configuration:

```bash
# Setup AWS MFA
sesh --service aws --setup

# Setup new TOTP service
sesh --service totp --setup
```

Features:
- QR code scanning via screenshot
- Manual secret entry fallback
- Automatic secret validation
- Step-by-step instructions

### 📋 Entry Management

List and manage stored credentials:

```bash
# List all entries for a service
sesh --service aws --list
sesh --service totp --list

# Delete specific entry
sesh --service aws --delete <entry-id>
sesh --service totp --delete <entry-id>
```

### 🎯 Command Reference

#### Global Options
```bash
--service, -service <provider>    # Service provider (aws, totp) [REQUIRED]
--list-services                   # Show available providers
--version                         # Display version info
--help                           # Show help
```

#### Common Operations
```bash
--list                           # List entries for service
--delete <id>                    # Delete entry by ID
--setup                          # Run setup wizard
--clip                           # Copy to clipboard
```

#### AWS-Specific Options
```bash
--profile <name>                 # AWS profile (default: $AWS_PROFILE)
--no-subshell                    # Print exports instead of subshell
```

#### TOTP-Specific Options
```bash
--service-name <name>            # Service name (github, google, etc.) [REQUIRED]
--profile <name>                 # Account profile (work, personal, etc.)
```

## 🔒 Security Model

### Keychain Integration
- All secrets stored in macOS Keychain
- Access restricted to sesh binary only
- Automatic permission management
- No plaintext storage

### Memory Security
- Secure memory zeroing after use
- Minimal secret exposure time
- Defensive copying throughout

### Credential Isolation
- Subshells provide isolated environments
- Credentials cleared on exit
- No persistent environment pollution

## 🛠️ Development

### Prerequisites
- Go 1.20+
- macOS (for Keychain integration)
- Make

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

### Architecture

sesh uses a plugin-based architecture:

```
sesh/
├── internal/
│   ├── provider/          # Plugin infrastructure
│   │   ├── registry.go    # Provider registration
│   │   ├── aws/          # AWS provider
│   │   └── totp/         # TOTP provider
│   ├── keychain/         # macOS Keychain integration
│   ├── totp/             # TOTP generation
│   ├── subshell/         # Subshell management
│   └── setup/            # Setup wizards
└── sesh/cmd/sesh/        # CLI application
```

### Extending sesh

To add a new provider:
1. Implement the `ServiceProvider` interface
2. Register with the provider registry
3. Add setup handler if needed

See [Plugin Development Guide](docs/PLUGIN_DEVELOPMENT.md) for details.

## 📚 Documentation

- [Quick Start Guide](docs/QUICK_START.md)
- [Advanced Usage](docs/ADVANCED_USAGE.md)
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Plugin Development](docs/PLUGIN_DEVELOPMENT.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Built with love by the open source community. Special thanks to all contributors who help make sesh better!
