# Sesh Development Scripts

This directory contains utility scripts to help with local development and testing of the `sesh` CLI tool. These scripts allow you to test AWS and TOTP flows without needing real AWS credentials or actual TOTP-enabled services.

**Use a scratch vault.** The flows below add entries to whatever vault sesh opens, so point it at a throwaway one first:

```bash
export SESH_DB_PATH=/tmp/sesh-dev/passwords.db
```

**QR codes on screen** are read only on macOS (`--qr`). On Linux, save a screenshot of the code and give it with `--qr-image shot.png`.

## Scripts Overview

### 🔐 `mock-totp-service.go`
**Purpose**: Simulates an external TOTP service (like GitHub, Google, etc.) for testing the TOTP setup flow.

**Usage**:
```bash
# Generate a test TOTP QR code for default service
go run mock-totp-service.go

# Generate for a specific service
go run mock-totp-service.go GitHub

# Generate for a service with custom account
go run mock-totp-service.go Datadog ops@company.com
```

**What it does**:
- Generates a valid TOTP secret
- Displays a QR code in the terminal
- Shows the secret key for manual entry
- Provides setup/test commands for `sesh`

**When to use**: When testing the `sesh add totp --qr` flow without setting up a real TOTP service.

### 🌐 `mock-aws-cli.go`
**Purpose**: Simulates the AWS CLI for testing AWS MFA setup without real AWS credentials.

**Usage**:
```bash
# First build it
go build -o mock-bin/aws mock-aws-cli.go

# Then add to PATH (before real aws)
export PATH="$(pwd)/mock-bin:$PATH"

# Now sesh will use the mock AWS CLI
sesh aws setup
```

**What it does**:
- Responds to AWS CLI commands (`sts get-caller-identity`, `iam list-mfa-devices`, etc.)
- Returns realistic JSON responses
- Validates MFA token format
- Supports error testing via environment variables

**Supported commands**:
- `aws sts get-caller-identity` - Returns mock user identity
- `aws sts get-session-token` - Generates mock temporary credentials
- `aws iam list-mfa-devices` - Lists mock MFA devices
- `aws configure get region` - Returns mock region

### 🚀 `setup-mock-aws.sh`
**Purpose**: Automates the setup of the mock AWS CLI for easy testing.

**Usage**:
```bash
./setup-mock-aws.sh
```

**What it does**:
- Builds the mock AWS CLI
- Creates `mock-bin` directory
- Provides copy-paste commands to update PATH
- Shows usage instructions
- Explains how to test error scenarios

### 🧪 `agent-smoke.sh` and `pty-run.py`
**Purpose**: An end-to-end check of the sesh agent with a real binary, in a temporary HOME: creating a vault, unlocking at a terminal, reads the agent serves, its wire format, and locking and stopping it. CI runs it on macOS and Linux.

**Usage** (from the repository root):
```bash
make agent-smoke                      # builds sesh, then runs scripts/agent-smoke.sh build/sesh
```

`pty-run.py` is its helper: it runs a command in a pseudo-terminal and types the password when the command asks for it.

### 📐 `fieldalignment_check.sh`
**Purpose**: Lists struct fields that could be reordered to use less memory, without changing any file (it works on a copy). Run it with `make lint/fieldalignment` from the repository root.

## Testing Workflows

### Testing AWS Setup Without Real AWS
```bash
# 1. Setup mock AWS CLI
./setup-mock-aws.sh
export PATH="$(pwd)/mock-bin:$PATH"

# 2. Run AWS setup
sesh aws setup

# 3. When prompted for QR code, in another terminal:
go run mock-totp-service.go AWS

# 4. Test credential generation
sesh aws
```

### Testing TOTP Setup
```bash
# 1. Generate a mock TOTP service
go run mock-totp-service.go GitHub

# 2. In another terminal: select the code on screen; it's named GitHub, from the code
sesh add totp --qr
# (or: sesh add totp GitHub, and type the key it shows)

# 3. Test TOTP generation
sesh code GitHub
```

### Testing Error Scenarios
```bash
# Simulate an expired token in get-caller-identity, which sesh aws setup
# calls, as do sesh_status and verify_aws inside sesh aws's shell
export MOCK_AWS_FAIL=true
sesh aws setup

# Simulate no MFA devices
export MOCK_AWS_NO_MFA=true
sesh aws setup

# Reset to normal
unset MOCK_AWS_FAIL MOCK_AWS_NO_MFA
```

## Notes

### Why These Scripts?
- **Fast iteration**: Test changes without real AWS setup
- **Consistent testing**: Same mock data every time
- **Error testing**: Simulate various failure modes
- **No credentials needed**: Test without exposing real secrets

### Building Mock Scripts
The `scripts/` directory has its own `go.mod` so it is a separate module from the root. This keeps dev-only dependencies (like `go-qrcode`) out of the production binary and ensures `go build ./...` from the root never enters this directory.

The Go mocks are run from inside the `scripts/` directory; `agent-smoke.sh` and `fieldalignment_check.sh` from the repository root, through `make`:
```bash
cd scripts

# Run directly
go run mock-totp-service.go

# Build the mock AWS CLI
go build -o mock-bin/aws mock-aws-cli.go
```

### Cleanup
Remember to remove the mock AWS from your PATH when done!

```bash
# Remove mock from PATH
export PATH=${PATH#$(pwd)/mock-bin:}

# Verify real AWS is back
which aws  # Should show /usr/local/bin/aws or similar
```
