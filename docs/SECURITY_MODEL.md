# Security Model

This document describes the security architecture of `sesh` and addresses common security concerns.

## Overview

`sesh` is designed with security as a primary concern, using a security model that:

1. Leverages operating system security primitives rather than custom implementations
2. Minimizes attack surface by avoiding unnecessary dependencies
3. Uses ephemeral credentials with clear expiration policies  
4. Never persists sensitive information to disk outside of secure storage
5. Follows the principle of least privilege

## Credential Storage

### TOTP Secret Storage

`sesh` stores MFA secrets in the macOS Keychain, which provides several important security benefits:

- **Hardware-backed encryption**: Secrets stored in Keychain are encrypted using keys tied to device hardware
- **Access control enforcement**: macOS controls which applications can access specific Keychain items
- **Permission prompts**: When any application attempts to access a Keychain item, macOS prompts the user for permission if not previously authorized
- **Application binding**: Keychain items can be bound to specific applications by macOS

Compared to alternatives, this approach is significantly more secure than:
- Plain text configuration files
- Environment variables (accessible to all processes of the same user)
- Custom encrypted storage (which would likely have less scrutiny than Apple's implementation)

### Application Access Control

When an application other than `sesh` attempts to access the stored TOTP secret:

1. macOS Keychain detects the access attempt from an unauthorized application
2. The user is prompted with a dialog asking for permission
3. The user must explicitly approve the access
4. Without approval, the secret remains secure

This protection is enforced at the operating system level, not by `sesh` itself, making it robust against various attack vectors.

## TOTP Implementation

The Time-based One-Time Password implementation:

- Uses the established `github.com/pquerna/otp/totp` library
- Generates standard 6-digit codes compatible with AWS MFA
- Only stores the seed/secret in Keychain, never the generated codes
- Generated codes are only used once and never persisted

## AWS Credential Management

Temporary AWS credentials provided by `sesh`:

- Are obtained through AWS STS service using `aws sts get-session-token`
- Have a default validity period determined by AWS:
  - 43,200 seconds (12 hours) for credentials created by IAM users
  - 3,600 seconds (1 hour) for credentials based on account credentials
- Are exported as environment variables in the current shell only
- Are never written to disk or AWS credential files
- Expiration time is clearly displayed to the user
- Are automatically cleaned from the environment before new authentication

## Environment Variable Handling

Security considerations for environment variables:

- AWS credential environment variables are explicitly removed before generating new credentials
- This prevents existing expired/invalid credentials from interfering with authentication
- The environment cleaning is handled within the `aws.GetSessionToken` function
- All environment variable exports are performed in-memory and affect only the current shell session

## CLI Dependency Security

`sesh` uses the AWS CLI for STS operations rather than a direct AWS SDK implementation:

- Leverages AWS CLI's well-tested credential handling and authentication
- Benefits from AWS CLI's security patches and updates
- Adds a dependency on proper AWS CLI installation and configuration
- Uses subprocess execution with proper output capture to avoid command injection

## Security Measures in Code

Several security-focused design decisions are implemented:

- **Clean Environment**: All AWS credential environment variables are cleared before authentication
- **Error Handling**: Comprehensive validation without exposing sensitive details
- **No Secret Logging**: The TOTP secret is never displayed or logged after initial setup
- **Minimal Dependencies**: Relies primarily on Go standard library and a single well-maintained TOTP library
- **Secure Default Configuration**: Sensible defaults for Keychain storage with user override options

## Memory Security and Secret Handling

### The Challenge of Secure String Handling in Go

Go's design makes truly secure string handling impossible due to string immutability. When dealing with sensitive data like TOTP codes, we face inherent limitations:

- **Strings are immutable**: Once created, the underlying memory cannot be modified
- **Garbage collection is non-deterministic**: We cannot control when memory is reclaimed
- **Multiple copies may exist**: String operations often create additional copies in memory

### Our Approach: Defense in Depth

While we cannot achieve perfect memory security with strings, `sesh` implements several measures to minimize exposure:

#### 1. Prefer Bytes Over Strings

Wherever possible, we keep secrets as `[]byte`:
```go
// Good: Secrets stay as bytes
secretBytes, err := p.keychain.GetSecret(...)
currentCode, _, err := p.totp.GenerateConsecutiveCodesBytes(secretBytes)
```

#### 2. Minimize String Conversion Points

We only convert to strings when absolutely necessary (e.g., AWS CLI interface):
```go
// In GetSessionToken - conversion happens at the last moment
codeStr := string(code)
defer secure.SecureZeroString(codeStr)  // Best-effort cleanup
```

#### 3. SecureZeroString: Understanding Its Limitations

The `SecureZeroString` function cannot zero the original string, but it provides value by:

- **Reducing copies**: It zeros the byte slice copy created from the string
- **Documenting intent**: Shows security consciousness in the code
- **Minimizing exposure window**: Fewer accessible copies in memory
- **Following defense-in-depth**: Every layer of protection helps

### Real-World Impact

Consider a TOTP code "123456" in our AWS authentication flow:

**Without SecureZeroString:**
1. TOTP generation creates: `currentCode = "123456"`
2. Conversion creates: `codeBytes = []byte("123456")`
3. AWS auth creates: `codeStr = "123456"`
4. AWS CLI internally copies it again
5. **Result**: 3-4 copies of "123456" may persist in memory

**With SecureZeroString:**
1. Same initial copies are created
2. `SecureZeroString` zeros the working byte slice copy
3. **Result**: 2-3 copies instead of 3-4

While not perfect, this reduces the attack surface for memory dumps or side-channel attacks.

### Key Takeaways

1. **Perfect string security is impossible in Go** - This is a language design trade-off
2. **We minimize exposure** through careful API design and defensive practices
3. **SecureZeroString is honest** - Our comments acknowledge its limitations
4. **Every layer helps** - Like locking doors, imperfect security is better than none

This approach balances Go's language constraints with practical security improvements, following the principle that defense in depth is valuable even when perfect security is unattainable.

## Attack Surface Analysis

The attack surface of `sesh` is limited:

1. **Local Application Access**: An attacker would need local account access to attempt using `sesh`
2. **Keychain Access**: Even with local access, macOS Keychain controls prevent unauthorized access  
3. **Shell Environment**: Environment variables are isolated to the user's shell process
4. **Temporary Credentials**: All generated credentials are time-limited

## Comparison with Other Authentication Methods

### Compared to AWS CLI with Credentials File

`sesh` is more secure than standard AWS CLI configurations because:
- Long-lived credentials are never stored on disk
- TOTP secrets are stored in OS-secured storage rather than user files
- Temporary credentials aren't written to config files that might be backed up or synced

### Compared to Manual TOTP Entry

`sesh` is more secure than manual TOTP entry methods because:
- The TOTP seed is never exposed to the user after initial setup
- No need to access an authenticator app that may have weaker security controls
- Reduces the risk of shoulder-surfing when entering visible TOTP codes

### Compared to Custom Solutions

`sesh` is more secure than many custom solutions because:
- It leverages well-tested macOS security infrastructure
- It follows AWS best practices for temporary credentials
- It implements proper subprocess handling to prevent command injection
- It avoids introducing unnecessary dependencies that could have security vulnerabilities

## Conclusion

`sesh` employs a security model that leverages strong OS-level security primitives rather than implementing custom security mechanisms. By using macOS Keychain for secret storage, temporary AWS credentials, and clean environment handling, it provides a high level of security while maintaining ease of use.

The net security posture of using `sesh` is an improvement over alternative AWS authentication methods for development environments.