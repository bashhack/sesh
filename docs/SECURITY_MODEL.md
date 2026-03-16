# sesh Security Model

This document describes the security architecture and privacy principles that guide sesh's design and implementation.

## Core Security Philosophy

sesh is built on three fundamental principles:

1. **Privacy First**: sesh stores your TOTP secrets locally and never transmits them — only the derived one-time codes leave your machine (via AWS CLI)
2. **OS-Native Security**: Use macOS Keychain rather than rolling our own crypto
3. **Transparent Security**: Be honest about what we can and cannot protect against

## Threat Model

sesh is designed to reduce exposure to:

- **Corporate Data Harvesting**: Unlike browser extensions or corporate MFA apps, sesh never phones home
- **Credential Theft**: Secrets are stored in macOS Keychain with binary-level access control
- **Memory Scraping**: Best-effort memory zeroing reduces exposure windows
- **Accidental Exposure**: Subshells isolate credentials from your main environment
- **Supply Chain Attacks**: Minimal dependencies reduce attack surface

sesh is NOT designed to protect against:

- **Compromised Local Account**: If an attacker has your macOS account, they can access Keychain
- **Root/Admin Access**: System-level compromise bypasses all application-level protections
- **Physical Access**: Direct hardware access can bypass software protections
- **Memory Dump Attacks**: Go's immutable strings mean TOTP codes and some intermediate values persist in memory until GC. Byte slices are zeroed, but string copies from the TOTP library cannot be.
- **Clipboard Managers**: In `-clip` mode, the copied value remains on the clipboard until overwritten. Clipboard managers (Raycast, Alfred, Paste, etc.) may log clipboard history permanently. TOTP codes are short-lived (30-second window), but consider using subshell mode for sensitive environments.
- **Terminal Recording**: Session recording tools (asciinema, iTerm2 logging, tmux capture) and shell history files can capture commands and output. Consider `export HISTFILE=/dev/null` in sensitive contexts.
- **Child Process Visibility**: Once credentials are output (clipboard, stdout, or subshell environment variables), any child process spawned from the shell can access them. This is inherent to how Unix environments work.

## Keychain Integration

### Storage Security

All secrets are stored in macOS Keychain using the system `security` command with binary access restrictions:

```go
// Get the path to the sesh binary (handles Homebrew, go install, etc.)
execPath := constants.GetSeshBinaryPath()

// Use -T flag to restrict access to only the sesh binary
addCmd := fmt.Sprintf("add-generic-password -a %s -s %s -w %s -U -T %s",
    account, service, secretStr, execPath)

// Execute via security -i (interactive mode) to avoid process listing exposure
cmd := execCommand("security", "-i")
err := secure.ExecWithSecretInput(cmd, []byte(addCmd+"\n"))
```

**Key Features:**
- **macOS Keychain Encryption**: Secrets encrypted by the OS keychain subsystem
- **Binary Path Binding**: The `-T` flag ensures only the sesh binary can access secrets without prompting
- **User Prompts**: macOS prompts when other apps try to access sesh entries
- **Automatic Path Detection**: Works with Homebrew, go install, or manual installation

### Why This Matters

Compare sesh's approach to alternatives:

| Storage Method | Encryption | Access Control | User Experience |
|----------------|------------|----------------|-----------------|
| sesh (Keychain) | OS-level | OS-enforced binary binding | Transparent |
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

### What We Do About It

Go makes this hard, but sesh reduces exposure through several techniques:

1. **Prefer Bytes Over Strings**
   ```go
   // Keep secrets as []byte throughout the pipeline
   secretBytes, err := p.keychain.GetSecret(p.User, serviceKey)
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
   err := secure.ExecWithSecretInput(cmd, secret)
   ```

### Real-World Impact

While we cannot achieve perfect security, our approach significantly reduces risk:

- **Without Protection**: Secrets persist as strings across multiple allocations with no cleanup
- **With sesh**: Secrets are kept as `[]byte`, zeroed after use, and passed via stdin — reducing the exposure window for memory dump attacks

## Subshell Security

The AWS subshell provides an isolated credential environment:

### Environment Isolation
```bash
# Main shell - no AWS credentials
$ env | grep AWS
(nothing)

# sesh subshell - credentials isolated here
$ sesh -service aws
🔐 Secure shell with aws credentials activated. Type 'sesh_help' for more information.
(sesh:aws) $ env | grep AWS
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
5. **Minimal Persistence**: Subshell init files are written to temp files and cleaned up on exit

## Plugin Architecture Security

The extensible design maintains security through:

### Interface Boundaries
```go
type ServiceProvider interface {
    ValidateRequest() error                        // Early validation
    GetCredentials() (Credentials, error)          // Type-safe credential generation
    GetClipboardValue() (Credentials, error)       // Clipboard-optimized output
}
```

### Provider Isolation
- Each provider manages its own keychain namespace
- No cross-provider secret access
- Clear separation of concerns

## Privacy by Design

### What sesh DOESN'T Do

- **No Analytics**: Zero telemetry or usage tracking
- **No Direct Network Calls**: sesh itself makes no network requests (AWS CLI handles STS calls)
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
| Backup/Sync | Often cloud-based | Local only (encrypted backup/export planned) |
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
| Offline Use | Often restricted | TOTP works offline; AWS requires network for STS |
| Vendor Lock-in | High | None |

## Security Best Practices

### For Users

1. **Protect Your macOS Account**: sesh's security depends on your account security
2. **Use Unique Profiles**: Separate work/personal accounts with profiles
3. **Regular Cleanup**: Periodically review stored entries with `-list`
4. **Install in a Protected Location**: The Keychain `-T` flag binds access to sesh's binary path. Install via Homebrew or to a system directory — avoid running from writable locations like `/tmp` where symlink attacks are possible
5. **Understand Mode Tradeoffs**: Subshell mode avoids clipboard exposure but places credentials in environment variables and temp init files. Clipboard mode avoids env var exposure but is visible to clipboard managers. Choose based on your threat model.

### For Developers

1. **Prefer Bytes**: Use `[]byte` for secrets whenever possible
2. **Defer Cleanup**: Always `defer secure.SecureZeroBytes()`
3. **Validate Early**: Use `ValidateRequest()` before operations
4. **Document Limits**: Be honest about security constraints

## Security Disclosure

Found a security issue? Please report it privately via [GitHub's security advisory reporting](https://github.com/bashhack/sesh/security/advisories/new). This creates a private report visible only to maintainers — no public issue is created.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fixes (if any)

I'll aim to respond within 72 hours and aim to fix critical issues within 7 days.

## Conclusion

sesh provides a security model that prioritizes:

1. **User Privacy**: No data collection, no cloud dependencies
2. **Practical Security**: Layered defenses within Go's constraints
3. **Transparency**: Honest about capabilities and limitations
4. **User Control**: You own your authentication workflow

While perfect security is impossible, sesh significantly improves upon mobile apps, browser extensions, and corporate MFA solutions by keeping your authentication local, private, and under your control.
