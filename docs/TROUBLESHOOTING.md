# Troubleshooting Guide for sesh

This guide helps you solve common issues with sesh.

## Installation Issues

### "Command not found: sesh"

**Problem**: The sesh binary isn't in your PATH.

**Solutions**:
1. If installed via Homebrew, run: `brew link --overwrite sesh`
2. If installed via script, check installation logs for the binary location
3. Manual fix: `export PATH="$PATH:/path/to/sesh/bin"`

### "Permission denied" during installation

**Problem**: Insufficient permissions to install to system directories.

**Solutions**:
1. Run the installer with sudo: `curl -sSL https://raw.githubusercontent.com/bashhack/sesh/main/install.sh | sudo bash`
2. Install to a user-writable location: `PREFIX=~/bin make install`

## Setup Issues

### "Could not determine current user"

**Problem**: The whoami command failed.

**Solutions**:
1. Manually specify your username: `sesh --keychain-user YOUR_USERNAME`
2. Check if your user environment is correctly configured

### "Failed to store secret in Keychain"

**Problem**: macOS Keychain access denied.

**Solutions**:
1. Run `security add-generic-password -a $(whoami) -s sesh-mfa -w 'YOUR_SECRET'` manually
2. Check Keychain Access app for any restrictions

## Authentication Issues

### "AWS CLI not found"

**Problem**: The AWS CLI isn't installed or isn't in your PATH.

**Solutions**:
1. Install AWS CLI: `brew install awscli`
2. Ensure it's in your PATH: `which aws`

### "No MFA devices found"

**Problem**: Your AWS account doesn't have an MFA device or it can't be detected.

**Solutions**:
1. Create an MFA device in the AWS Console
2. Specify the device ARN manually: `sesh --serial arn:aws:iam::123456789012:mfa/username`

### "Could not retrieve TOTP secret from Keychain"

**Problem**: Your MFA secret isn't stored in Keychain or is inaccessible.

**Solutions**:
1. Run setup again: `sesh --setup`
2. Manually add the secret: `security add-generic-password -a $(whoami) -s sesh-mfa -w 'YOUR_SECRET'`

### "Failed to get session token"

**Problem**: AWS STS call failed.

**Solutions**:
1. Check AWS CLI configuration: `aws configure list`
2. Verify network connectivity to AWS
3. Ensure the MFA code is correct (time synchronization)
4. Check for expired/revoked AWS access keys

## Shell Integration Issues

### "sesh command not functioning as expected"

**Problem**: Shell integration isn't loaded or is conflicting.

**Solutions**:
1. Verify the integration script exists: `ls -l $(dirname $(which sesh))/../share/sesh/sesh.sh`
2. Reload your shell: `source ~/.zshrc` or `source ~/.bashrc`
3. Check for any function name conflicts: `type sesh`

### "Shell function not evaluating credentials"

**Problem**: The shell integration isn't evaluating the output.

**Solutions**:
1. Try without shell integration: `eval "$(command sesh)"`
2. Check for quoting or escaping issues in your shell config

## System-Specific Issues

### "security command not found"

**Problem**: Not running on macOS or security tool isn't available.

**Solutions**:
1. Ensure you're running on macOS (Linux support is planned but not implemented)
2. If on macOS, reinstall Command Line Tools: `xcode-select --install`

## Still Having Problems?

If you're still experiencing issues:

1. Run with verbose logging: `SESH_DEBUG=1 sesh` (if implemented)
2. Check AWS CLI logs: `aws sts get-session-token --serial YOUR_SERIAL --token-code YOUR_CODE --debug`
3. Open an issue on GitHub with the following details:
   - Your operating system and version
   - How you installed sesh
   - Exact error message
   - Steps to reproduce the issue
