# Advanced Usage Guide for sesh

This guide covers advanced features and usage patterns for sesh.

## Plugin Architecture

Sesh now features a modular plugin architecture that supports multiple service providers. The `--service` flag selects which provider to use:

```bash
# List available service providers
sesh --list-services

# Use AWS (default)
sesh

# Use generic TOTP provider
sesh --service totp --service-name github
```

## Multiple AWS Profiles

Sesh can work with multiple AWS profiles:

```bash
# Use default profile
sesh

# Use development profile
sesh --profile dev

# Use production profile
sesh --profile prod
```

### Profile Aliases

You can create shell aliases for commonly used profiles:

```bash
# Add to your .zshrc or .bashrc
alias sesh-dev="sesh --profile dev"
alias sesh-prod="sesh --profile prod"
```

## Generic TOTP Provider

The generic TOTP provider can generate codes for any service that uses TOTP-based two-factor authentication:

```bash
# Set up a new service
sesh --service totp --setup

# Generate code for a service
sesh --service totp --service-name github

# Copy code to clipboard
sesh --service totp --service-name github --clip
```

### Multiple Accounts per Service

You can manage multiple accounts for the same service using profiles:

```bash
# Set up different profiles
sesh --service totp --setup
# When prompted, use the same service name but different profile names

# Use a specific profile
sesh --service totp --service-name github --profile work
```

## Managing Entries

Sesh provides commands to manage your keychain entries:

```bash
# List all entries for AWS
sesh --list

# List all entries for generic TOTP
sesh --service totp --list

# Delete an entry (use the ID shown in list output)
sesh --service totp --delete "sesh-totp-github:yourusername"
```

## Clipboard Integration

You can copy TOTP codes directly to your clipboard:

```bash
# Copy AWS session token to clipboard
sesh --clip

# Copy TOTP code to clipboard
sesh --service totp --service-name github --clip
```

## Session Duration and Refresh

AWS STS session tokens created by sesh have a default duration of 12 hours. The session expiry time is displayed when credentials are generated:

```
# ⏳ Expires at: 2025-04-19 22:59:19 (valid for 0h59m)
```

If your credentials expire, simply run sesh again to generate fresh credentials.

## Integration with Other Tools

### AWS SSO Integration

If you're using AWS SSO, you might need to combine sesh with the SSO login:

```bash
# First log in via SSO
aws sso login --profile sso-dev

# Then use sesh with appropriate role credentials
sesh --profile sso-dev
```

### IDE Integration

For use with IDEs like VS Code or JetBrains:

1. Create a shell script that activates sesh:

```bash
#!/bin/bash
# ~/.local/bin/aws-env.sh

# Run sesh and capture its output
eval "$(sesh --profile dev)"

# Execute the provided command with AWS credentials
exec "$@"
```

2. Make it executable:

```bash
chmod +x ~/.local/bin/aws-env.sh
```

3. Configure your IDE to use this as a shell wrapper

## Custom Keychain Configuration

You can customize which keychain and account are used:

```bash
# Use a different user
sesh --keychain-user admin

# Use a different service name
sesh --keychain-name "aws-mfa-secret"

# Combine both
sesh --keychain-user admin --keychain-name "aws-mfa-secret"
```

## Security Considerations

Sesh takes security seriously:

1. All secrets are stored in the macOS Keychain, protected by your login password
2. Keychain entries are restricted to be accessed only by the sesh binary
3. AWS session credentials are temporary and automatically expire
4. No secrets are ever written to disk or logs

## Environment Variables

You can set default values using environment variables:

```bash
# Add to your .zshrc or .bashrc
export AWS_PROFILE=dev
export SESH_MFA_SERIAL=arn:aws:iam::123456789012:mfa/user
export SESH_KEYCHAIN_USER=admin
export SESH_KEYCHAIN_NAME=custom-mfa-secret
export SESH_TOTP_KEYCHAIN_NAME=custom-totp-prefix

# Now sesh will use these defaults
sesh
```

## Command Reference

| Command | Description |
|---------|-------------|
| `sesh` | Generate AWS credentials using default profile |
| `sesh --profile NAME` | Use a specific AWS profile |
| `sesh --setup` | Run the AWS setup wizard |
| `sesh --service totp --setup` | Run setup for generic TOTP |
| `sesh --service totp --service-name NAME` | Generate TOTP code |
| `sesh --clip` | Copy code to clipboard |
| `sesh --list` | List entries for current service |
| `sesh --list-services` | List available service providers |
| `sesh --delete ID` | Delete a specific entry |
| `sesh --version` | Show version information |
| `sesh --help` | Show help information |