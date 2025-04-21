# Quick Start Guide for sesh

This guide will get you up and running with sesh in under 5 minutes.

## Step 1: Installation

Choose one of these methods:

```bash
# Option 1: Homebrew (recommended)
brew install bashhack/tap/sesh

# Option 2: Direct download
curl -sSL https://raw.githubusercontent.com/bashhack/sesh/main/install.sh | bash
```

## Step 2: First-time Setup

### For AWS Authentication

Run the setup wizard:

```bash
sesh --setup
```

Follow the on-screen instructions to:
1. Create a virtual MFA device in AWS Console
2. Store the MFA secret in your macOS Keychain

### For Generic TOTP Services

You can also set up sesh for any service that uses TOTP:

```bash
sesh --service totp --setup
```

Follow the prompts to:
1. Enter a name for the service (e.g., "github")
2. Optionally provide a profile name (for multiple accounts)
3. Enter the TOTP secret key

## Step 3: Enable Shell Integration

Add this line to your shell configuration file (`.zshrc`, `.bashrc`, etc.):

```bash
# Add sesh shell integration
source "$(dirname $(which sesh))/../share/sesh/sesh.sh"
```

Then reload your shell:

```bash
source ~/.zshrc  # or ~/.bashrc
```

## Step 4: Daily Use

### For AWS Authentication

```bash
# Default AWS profile
sesh

# Or with a specific profile
sesh --profile dev
```

### For Generic TOTP Services

```bash
# Generate TOTP code for a service
sesh --service totp --service-name github

# Copy TOTP code to clipboard
sesh --service totp --service-name github --clip

# For multiple accounts with the same service
sesh --service totp --service-name github --profile work --clip
```

### Managing Your Entries

```bash
# List all available service providers
sesh --list-services

# List all entries for a service
sesh --service totp --list

# Delete an entry (use the ID shown in list)
sesh --service totp --delete "sesh-totp-github:yourusername"
```

## Next Steps

- Read the full [README.md](../README.md) for more details
- Check out the [Troubleshooting Guide](TROUBLESHOOTING.md) if you encounter issues
- See [ADVANCED_USAGE.md](ADVANCED_USAGE.md) for more features