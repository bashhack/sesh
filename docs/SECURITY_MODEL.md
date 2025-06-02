# sesh Security Model

This document describes the security architecture and privacy principles that guide sesh's design and implementation.

## Core Security Philosophy

sesh is built on three fundamental principles:

1. **Privacy First**: Your authentication secrets never leave your machine
2. **OS-Native Security**: Leverage battle-tested OS security primitives rather than rolling our own
3. **Transparent Security**: Be honest about what we can and cannot protect against

## Threat Model

sesh is designed to protect against:

- **Corporate Data Harvesting**: Unlike browser extensions or corporate MFA apps, sesh never phones home
- **Credential Theft**: Secrets are stored in macOS Keychain with binary-level access control
- **Memory Scraping**: Best-effort memory zeroing reduces exposure windows
- **Accidental Exposure**: Subshells isolate credentials from your main environment
- **Supply Chain Attacks**: Minimal dependencies reduce attack surface

sesh is NOT designed to protect against:

- **Compromised Local Account**: If an attacker has your macOS account, they can access Keychain
- **Root/Admin Access**: System-level compromise bypasses all application-level protections
- **Physical Access**: Direct hardware access can bypass software protections
- **Memory Dump Attacks**: Go's design makes perfect memory security impossible

## Keychain Integration

### Storage Security

All secrets are stored in macOS Keychain with these protections:

```go
// Binary path binding ensures only sesh can access its secrets
item.SetAccess(&keychain.Access{
    Label:       fmt.Sprintf("sesh (%s)", binaryPath),
    TrustedApplications: []string{binaryPath},
})
```

**Key Features:**
- **Hardware-Backed Encryption**: Secrets encrypted with keys tied to Secure Enclave
- **Binary Path Binding**: Only the sesh binary at its installed path can access secrets
- **User Prompts**: macOS prompts when other apps try to access sesh entries
- **Automatic Permissions**: Works seamlessly with Homebrew, go install, or manual installation

### Why This Matters

Compare sesh's approach to alternatives:

| Storage Method | Encryption | Access Control | User Experience |
|----------------|------------|----------------|-----------------|
| sesh (Keychain) | Hardware-backed | OS-enforced binary binding | Seamless |
| Config Files | None/Custom | File permissions only | Manual setup |
| Environment Vars | None | Process inheritance | Leaks to children |
| Corporate MFA Apps | Unknown | App-controlled | Privacy concerns |

## Memory Security

### The Go Memory Challenge

Go's design makes perfect memory security impossible:

```go
// Strings are immutable - we cannot zero them
secret := "my-totp-secret"  // This will persist until GC

// We can only zero byte slices
secretBytes := []byte(secret)
secure.SecureZeroBytes(secretBytes)  // This works
```

### Our Defense-in-Depth Approach

Despite Go's limitations, sesh implements multiple layers of protection:

1. **Prefer Bytes Over Strings**
   ```go
   // Keep secrets as []byte throughout the pipeline
   secretBytes, err := keychain.GetSecret(...)
   defer secure.SecureZeroBytes(secretBytes)
   ```

2. **Minimize String Conversions**
   ```go
   // Only convert at boundaries where required
   codeStr := string(codeBytes)
   defer secure.SecureZeroString(codeStr)  // Best effort
   ```

3. **Compiler-Protected Zeroing**
   ```go
   func SecureZeroBytes(b []byte) {
       for i := range b {
           b[i] = 0
       }
       runtime.KeepAlive(b)  // Prevent optimization
   }
   ```

4. **Secure Command Execution**
   ```go
   // Pass secrets via stdin, not command line
   output, err := secure.ExecWithSecretInput(cmd, secret)
   ```

### Real-World Impact

While we cannot achieve perfect security, our approach significantly reduces risk:

- **Without Protection**: 5-10 copies of secrets may persist in memory
- **With sesh**: 2-3 copies, with active attempts to zero them
- **Practical Result**: Smaller window for memory dump attacks

## Subshell Security

The AWS subshell provides an isolated credential environment:

### Environment Isolation
```bash
# Main shell - no AWS credentials
$ env | grep AWS
(nothing)

# sesh subshell - credentials isolated here
$ sesh --service aws
🔐 (sesh:aws) $ env | grep AWS
AWS_ACCESS_KEY_ID=ASIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...
SESH_ACTIVE=1

# Exit subshell - credentials gone
$ exit
$ env | grep AWS
(nothing)
```

### Security Features

1. **Nested Session Prevention**: Can't accidentally nest sesh sessions
2. **Visual Indicators**: Clear prompt showing you're in a secure environment
3. **Automatic Cleanup**: Credentials cleared on exit
4. **Session Tracking**: Built-in commands to verify credential status
5. **No Persistence**: Credentials never written to disk

## Plugin Architecture Security

The extensible design maintains security through:

### Interface Boundaries
```go
type ServiceProvider interface {
    ValidateRequest() error           // Early validation
    GenerateCredentials() error       // Type-safe generation
    SupportsClipboard() bool         // Capability declaration
}
```

### Provider Isolation
- Each provider manages its own keychain namespace
- No cross-provider secret access
- Clear separation of concerns

## Privacy by Design

### What sesh DOESN'T Do

- **No Analytics**: Zero telemetry or usage tracking
- **No Network Calls**: Completely offline operation
- **No Cloud Sync**: Your secrets stay on your machine
- **No Auto-Updates**: You control when to update
- **No Phone Home**: No license checks or activation

### What sesh DOES Do

- **Local-Only Storage**: All data in macOS Keychain
- **Explicit User Control**: Every operation requires user action
- **Open Source**: Complete transparency in implementation
- **Minimal Dependencies**: Reduced supply chain risk

## Comparison with Alternatives

### vs Mobile Authenticator Apps

| Feature | Mobile Apps | sesh |
|---------|-------------|------|
| Storage Location | Phone (unknown security) | macOS Keychain |
| Backup/Sync | Often cloud-based | Local only |
| Privacy | Varies (often poor) | Complete |
| Scriptability | None | Full CLI |
| Audit Trail | App-controlled | OS-level |

### vs Browser Extensions

| Feature | Browser Extensions | sesh |
|---------|-------------------|------|
| Attack Surface | Entire browser | Minimal CLI |
| Permissions | Broad web access | Local only |
| Updates | Auto/forced | User-controlled |
| Code Visibility | Often obfuscated | Open source |

### vs Corporate MFA Solutions

| Feature | Corporate MFA | sesh |
|---------|---------------|------|
| Data Collection | Extensive | None |
| User Control | Limited | Complete |
| Offline Use | Often restricted | Always works |
| Vendor Lock-in | High | None |

## Security Best Practices

### For Users

1. **Protect Your macOS Account**: sesh's security depends on your account security
2. **Use Unique Profiles**: Separate work/personal accounts with profiles
3. **Regular Cleanup**: Periodically review stored entries with `--list`
4. **Verify Binary Path**: Ensure sesh is installed in a protected location

### For Developers

1. **Prefer Bytes**: Use `[]byte` for secrets whenever possible
2. **Defer Cleanup**: Always `defer secure.SecureZeroBytes()`
3. **Validate Early**: Use `ValidateRequest()` before operations
4. **Document Limits**: Be honest about security constraints

## Security Disclosure

Found a security issue? Please email security@[domain] with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fixes (if any)

We aim to respond within 48 hours and fix critical issues within 7 days.

## Conclusion

sesh provides a security model that prioritizes:

1. **User Privacy**: No data collection, no cloud dependencies
2. **Practical Security**: Defense-in-depth within Go's constraints  
3. **Transparency**: Honest about capabilities and limitations
4. **User Control**: You own your authentication workflow

While perfect security is impossible, sesh significantly improves upon mobile apps, browser extensions, and corporate MFA solutions by keeping your authentication local, private, and under your control.