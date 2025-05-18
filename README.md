# 🛠️ sesh — AWS Credential Helper with MFA

|              Build              |          Tests           |          Coverage           |                                                                                                                         Review                                                                                                                         |
|:-------------------------------:|:------------------------:|:---------------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| [![Build Status](https://github.com/bashhack/sesh/actions/workflows/ci.yml/badge.svg)](https://github.com/bashhack/sesh/actions/workflows/ci.yml) | [![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/bashhack/sesh/actions/workflows/ci.yml) | [![codecov](https://codecov.io/gh/bashhack/sesh/graph/badge.svg?token=Y3K7R3MHXH)](https://codecov.io/gh/bashhack/sesh) | ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/bashhack/sesh?utm_source=oss&utm_medium=github&utm_campaign=bashhack%2Fsesh&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews) |


A lightweight CLI tool that generates AWS session credentials using MFA via TOTP codes, stored securely in macOS Keychain.

## Quick Start

```bash
# Install
brew install bashhack/tap/sesh
# or
curl -sSL https://raw.githubusercontent.com/bashhack/sesh/main/install.sh | bash

# First-time setup (only once)
sesh --service aws --setup

# Use sesh to launch a secure subshell with AWS credentials
sesh --service aws

# Or generate TOTP codes for other services
sesh --service totp --service-name github
```

## Features

- 🔐 **Secure** — MFA secrets stored in macOS Keychain
- 🚀 **Fast** — Written in Go with minimal dependencies
- 💡 **Simple** — Easy to use subshell environment for AWS credentials
- 🧙 **User-friendly** — Includes setup wizard with `--setup`
- 🖥️ **macOS native** — Designed for macOS with Keychain integration
- 🔄 **Multi-service** — Support for AWS and TOTP services

## Installation

### Option 1: Homebrew (recommended)

```bash
brew install bashhack/tap/sesh
```

### Option 2: Curl installer

```bash
curl -sSL https://raw.githubusercontent.com/bashhack/sesh/main/install.sh | bash
```

### Option 3: Manual Installation

```bash
# Clone the repository
git clone https://github.com/bashhack/sesh.git
cd sesh

# Build and install
make install
```

## User Guide

### First-time Setup

Run the setup wizard to guide you through creating a virtual MFA device:

```bash
sesh --setup
```

The setup wizard will:

1. Guide you through creating a virtual MFA device in the AWS Console
2. Generate two consecutive MFA codes needed for AWS setup (no additional authenticator app needed!)
3. Securely store your MFA secret in macOS Keychain
4. Provide next steps to get started

### Shell Integration

To enable shell integration (recommended), add this line to your shell's configuration file (`.bashrc`, `.zshrc`, etc.):

```bash
source "$(dirname $(which sesh))/../share/sesh/sesh.sh"
```

Then restart your terminal or run:

```bash
source "$(dirname $(which sesh))/../share/sesh/sesh.sh"
```

With shell integration active, you can simply type:

```bash
sesh
```

And your AWS credentials will be automatically exported to your environment.

### Daily Usage

#### With Shell Integration (recommended)

```bash
# Use default AWS profile
sesh

# Use a specific AWS profile
sesh --profile dev

# View version information
sesh --version

# Show help
sesh --help
```

#### Without Shell Integration

If you prefer not to use shell integration, use the traditional method:

```bash
# Use default AWS profile
eval "$(sesh)"

# Use a specific AWS profile
eval "$(sesh --profile dev)"
```

### Command-line Options

- `--profile NAME` — Use a specific AWS profile (default: `AWS_PROFILE` env var)
- `--serial ARN` — Specify MFA device ARN (default: auto-detected)
- `--keychain-user NAME` — Specify keychain username (default: current user)
- `--keychain-name NAME` — Specify keychain service name (default: `sesh-mfa`)
- `--setup` — Run the first-time setup wizard
- `--version` — Display version information
- `--help` — Show command-line options

### Environment Variables

- `AWS_PROFILE` — Default AWS profile to use
- `SESH_MFA_SERIAL` — MFA device serial number/ARN
- `SESH_KEYCHAIN_USER` — macOS Keychain username
- `SESH_KEYCHAIN_NAME` — macOS Keychain service name

## How It Works

1. **Retrieve MFA Secret**:
   - Gets your TOTP secret from macOS Keychain using the `security` command
   - Auto-detects your username if not specified

2. **Generate TOTP Code**:
   - Generates a time-based one-time password (TOTP) from your secret

3. **Get AWS Session Token**:
   - Calls `aws sts get-session-token` with your TOTP code
   - Acquires temporary AWS credentials

4. **Export Credentials**:
   - Outputs credentials as environment variables
   - Shows expiration time and remaining validity

## Troubleshooting

### "No MFA devices found"

Ensure you have an MFA device associated with your AWS account. If you do, try specifying the device ARN directly:

```bash
sesh --serial arn:aws:iam::123456789012:mfa/username
```

### "Could not retrieve TOTP secret from Keychain"

Your MFA secret might not be properly stored in Keychain. Run the setup again:

```bash
sesh --setup
```

### "AWS CLI not found"

Sesh requires the AWS CLI to be installed. Install it with:

```bash
brew install awscli
```

### Shell integration not working

Make sure you've added the source line to your shell configuration file and restarted your terminal:

```bash
source "$(dirname $(which sesh))/../share/sesh/sesh.sh"
```

## Development

### Requirements

- Go 1.20 or later
- macOS for testing Keychain integration

### Building from source

```bash
# Clone the repository
git clone https://github.com/bashhack/sesh.git
cd sesh

# Build the binary
make build

# Run tests
make test

# Run tests with coverage report
make coverage

# Verify code quality
make audit

# Install locally
make install
```

### Project Structure

- `/cmd/sesh/main.go` — CLI entrypoint, flag parsing
- `/internal/aws/` — AWS CLI interactions
- `/internal/keychain/` — macOS Keychain integration
- `/internal/totp/` — TOTP code generation
- `/internal/setup/` — Interactive setup wizard
- `/shell/` — Shell integration scripts

## License

MIT
