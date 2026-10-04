# sesh Security Model

This document describes the security architecture and privacy principles that guide sesh's design and implementation.

## Core Security Philosophy

sesh is built on three fundamental principles:

1. **Privacy First**: sesh stores your secrets locally and never transmits them — only derived values (TOTP codes, session tokens) leave your machine
2. **Layered Encryption**: AES-256-GCM with Argon2id key derivation in the default encrypted vault, or the macOS Keychain if you choose it
3. **Transparent Security**: Be honest about what we can and cannot protect against

## Threat Model

sesh is designed to reduce exposure to:

- **Corporate Data Harvesting**: Unlike browser extensions or corporate MFA apps, sesh never phones home
- **Credential Theft**: Secrets are stored in macOS Keychain with binary-level access control
- **Memory Scraping**: Best-effort memory zeroing reduces exposure windows
- **Accidental Exposure**: Subshells isolate credentials from your main environment
- **Supply Chain Attacks**: Minimal dependencies reduce attack surface

sesh is NOT designed to protect against:

- **Compromised Local Account**: If an attacker has your macOS account, they can access Keychain. In master password mode they can also use an unlocked sesh agent; see [Sesh agent](#sesh-agent)
- **Root/Admin Access**: System-level compromise bypasses all application-level protections
- **Physical Access**: Direct hardware access can bypass software protections
- **Memory Dump Attacks**: Go's immutable strings mean TOTP codes and some intermediate values persist in memory until GC. Byte slices are zeroed, but string copies from the TOTP library cannot be.
- **Clipboard Managers**: In `-clip` mode, the copied value is auto-cleared after 30 seconds (if unchanged). However, clipboard managers (Raycast, Alfred, Paste, etc.) may capture the value before it's cleared. Consider disabling clipboard history for sensitive workflows.
- **Terminal Recording**: Session recording tools (asciinema, iTerm2 logging, tmux capture) and shell history files can capture commands and output. Consider `export HISTFILE=/dev/null` in sensitive contexts.
- **Child Process Visibility**: Once credentials are output (clipboard, stdout, or subshell environment variables), any child process spawned from the shell can access them. This is inherent to how Unix environments work.

## Keychain Integration

### Storage Security

sesh supports two storage backends. The default is an encrypted SQLite vault unlocked with your master password, on macOS and Linux. The macOS Keychain backend (`backend = "keychain"`, macOS only) is used only when you choose it.

#### SQLite Store (default)

The SQLite backend provides application-level encryption on top of file-system storage:

- **AES-256-GCM**: Authenticated encryption for every stored entry
- **Per-entry salts**: Each entry derives a unique encryption key from the master key + a random 16-byte salt
- **Argon2id key derivation**: Memory-hard KDF for per-entry key derivation (16 MiB, 1 iteration, 1 thread). The KDF input is the 256-bit high-entropy master key (see below), *not* a user password — so these parameters are chosen for domain separation between entries rather than password stretching, and fall below OWASP's password-KDF minimums by design
- **Two key sources** (`key_source`): the master key is derived from your master password (default), or kept in the macOS Keychain (see below)
- **Vault key check**: the vault stores a constant encrypted with its key (the `vault_key` table), plus the name of the key source that protects it. Every command decrypts the constant before reading or writing any entry, and refuses a key that fails. A mismatched key source setting, a replaced `passwords.key`, or a changed Keychain entry therefore can't write entries the vault's real key can't read. Password mode also refuses to create a new master key next to an existing vault whose `passwords.key` is missing
- **Key versioning**: Schema supports key rotation via `key_version` column and `key_metadata` table (rotation logic planned)
- **FTS5 search**: Full-text search indexes service names, accounts, and descriptions — search queries never touch encrypted data
- **Audit logging**: The `audit_log` table records access, modification, and deletion events with timestamps (never the secrets). `sesh audit` shows it. Events older than `audit.retention_days` (default 90; `0` keeps everything) are removed when the vault is opened, and `sesh audit prune` removes them on demand. It's a record for the user, not tamper-proof: anyone who can write the vault file can change it
- **WAL mode**: Write-ahead logging for safe concurrent reads

##### Master password key source (default)

Derives the master key from a user-supplied passphrase via Argon2id. **No keychain involvement**, so in this mode the SQLite backend runs on Linux as well as macOS.

- **KDF**: Argon2id with `t=3, m=64 MiB, p=4, keyLen=32`. These parameters exceed OWASP 2023 minimums (`t=1, m=47 MiB, p=1`) and make offline brute-force expensive (~200 ms per attempt)
- **Sidecar file** `passwords.key` (next to the DB, 0600 permissions): stores the KDF salt (32 random bytes), algorithm params, and a verification blob. **No secrets.** Same public-info model as bcrypt/scrypt — salt and params are safe to expose
- **Verification blob**: AES-256-GCM encryption of the constant string `"sesh-verify"` using the derived key. On unlock, sesh re-derives the key from the supplied password and tries to decrypt this blob. GCM's authentication tag rejects wrong passwords immediately, without touching any real entries
- **First run**: needs no setup. Before the first prompt, sesh says it's creating a vault, where, and that a forgotten password can't be reset, only worked around with a recovery key. It then asks for the master password twice, generates the salt, derives the key, writes the sidecar, and unlocks the agent with the new password, so the next command doesn't prompt
- **Subsequent runs**: the password is checked by the sesh agent (below). The first command after the agent starts prompts; later commands reuse the agent's key without prompting. If the agent is unavailable, sesh prompts on every run and verifies the password itself
- **Minimum password length**: 8 characters. This is a **floor**, not a recommendation — it exists to reject obvious mistakes (empty input, fat-fingered short strings). With Argon2id at `m=64 MiB, t=3` and an attacker who has the sidecar, an 8-character lowercase-ASCII password is brute-forceable within days on commodity hardware. **Choose a passphrase**: four or more random words from a large wordlist (40+ bits of entropy) gives meaningful resistance; longer is better
- **Non-interactive mode**: `SESH_MASTER_PASSWORD` env var bypasses the prompt (intended for CI/scripts only; exposes the password to the process environment). These runs check the password every time and don't use the agent, so a job never starts one; an agent from your interactive use is unaffected

**Threat model.** An attacker with the DB file and sidecar can attempt offline brute-force using the public salt and params. At ~5 attempts/second, a strong passphrase (four random words from a large wordlist, 40+ bits of entropy) is resistant; a weak password is not. This is the same threat model as any password manager — the strength of the master password bounds the security of everything under it.

**Metadata exposure.** Even without the master password, an attacker with the DB file can read service names, account names, timestamps, and audit log entries — only the encrypted secret values are protected. Full-database encryption (SQLCipher-style) would require a CGo dependency and is not implemented.

##### Touch ID unlock (macOS, optional)

With Touch ID unlock on, the agent can unlock with a fingerprint instead of the master password.

- **Key custody.** A P-256 key is created inside the Secure Enclave with access control `privateKeyUsage | biometryCurrentSet`. The private key never leaves the chip. Only a currently enrolled fingerprint can use it, and adding or removing a fingerprint invalidates it permanently. The key is not stored in the Keychain: sesh keeps its chip-bound handle (useless on any other Mac) in `touchid.key` next to the vault, mode 0600.
- **The wrap.** The agent wraps the vault key to the Secure Enclave public key: one-off P-256 ECDH, HKDF-SHA256, then AES-256-GCM bound to the vault's unlock id. The vault key never leaves the agent to do this. Unwrapping needs the chip to do the ECDH, which shows the system Touch ID sheet ("sesh is trying to unlock your vault"). The agent checks the unwrapped key against the sidecar's verify blob before installing it, exactly as for a password.
- **What changes.** The vault then opens with the master password **or** an enrolled fingerprint on that Mac. The master password is still needed to turn Touch ID unlock on, after fingerprint changes, over SSH, and as the fallback. It's never stored.
- **Fingerprint only, deliberately.** Neither the Mac's login password nor an Apple Watch can approve, so the vault's protection is never reduced to that of the login password.
- **Same-user malware.** A process running as you can make the agent show the Touch ID sheet, but can't approve it. The sheet is system UI that names the program asking. While the agent is unlocked, such a process can already ask it to decrypt; Touch ID doesn't change that.
- **Copies.** `touchid.key`, or the whole vault with it, copied to another machine gains nothing.

##### Keychain key source (`key_source = "keychain"`, macOS only)

The 256-bit master encryption key is stored in the macOS Keychain, combining OS-level access control with application-level encryption. The key is hex-encoded (64 ASCII characters) before storage because the `security` command's tokenizer can't reliably round-trip raw random bytes; the key is decoded on read and zeroed after use.

##### Sesh agent

In password mode, once the vault exists, the first command that needs the key starts a per-user background process (`sesh agent`). The run that creates the vault does not start it. The agent holds the derived key in memory and performs entry encryption and decryption on the CLI's behalf; the key itself never crosses the socket.

- **Socket**: `<user-cache-dir>/sesh/agent.sock` (override with `SESH_AUTH_SOCK`), mode 0600 in a 0700 directory. Both ends check the other's UID (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS): the agent rejects clients run by other users, and the CLI refuses an agent socket owned by another user before sending it anything
- **Unlock**: the CLI prompts, then sends the password and the sidecar's public salt, params, and verify blob to the agent, which derives and checks the key. Unlocks run one at a time
- **Vault binding**: every encrypt/decrypt request names the sidecar it was unlocked for. If the agent has since been unlocked for a different vault, it refuses rather than use the wrong key
- **Environment**: runs with `SESH_MASTER_PASSWORD` set never start or use the agent, and an agent started by another run does not inherit that variable

Where the derived key is, by state:

| State | Where the key lives |
|-------|---------------------|
| No agent (keychain mode, `SESH_MASTER_PASSWORD` runs, or agent unavailable) | In the sesh process, for one command |
| Agent unlocked | In the agent's locked memory page |
| Agent locked | Nowhere: zeroed in place. After an automatic lock the agent also exits; after `sesh agent lock` or SIGUSR1 it keeps running |
| Agent stopped | Nowhere; the next command starts a fresh agent |

What this changes: while the agent is unlocked, **any process running as your user can ask it to decrypt entries**, and `--list` / `--delete` no longer require the password. This is the same trade-off `ssh-agent` makes. The window is bounded:

- **Idle timeout** (default 10 minutes): the agent locks after this long without an unlock, encrypt, or decrypt. Status checks don't count.
- **Max lifetime** (default 8 hours): the agent locks this long after each unlock, however busy it is.
- **On demand**: `sesh agent lock` drops the key, `sesh agent stop` shuts the agent down, and `SIGUSR1` locks it (for example from a screen-lock hook).

Locking zeroes the key. An automatic lock (idle timeout or max lifetime) also shuts the agent down, and so does an agent that nobody unlocks within the idle timeout. A lock you ask for leaves it running. Either way, the next command prompts again.

**Upgrades**: the agent reports a hash of its executable. A `sesh` from any other build stops it and starts its own, so a fix in a new release reaches the agent on the first command after upgrading. Without this, the old agent would keep serving until it stopped.

**Process hardening** (Linux and macOS). Before it accepts any connection, the agent disables core dumps, blocks other processes running as you from attaching a debugger or reading its memory (`PR_SET_DUMPABLE=0` on Linux, `PT_DENY_ATTACH` on macOS), and reserves a page locked into RAM for the key so it is never written to swap. If any of these can't be applied (in practice only the memory lock can fail, when the locked-memory limit is below one page), the agent refuses to start: sesh prints a warning with the agent's reason and prompts for the password on every run instead. Short-lived copies made while encrypting or decrypting stay on the ordinary Go heap, covered by the no-dump/no-attach settings.

**What compromise of each piece gives an attacker:**

1. **The agent's socket** (another process running as you). While the agent is unlocked, it can have any entry decrypted or encrypted. Such a process can also read your database file, so in effect it can read and change every secret in the vault for as long as the agent stays unlocked. It never gets the key itself, so the access ends when the agent locks, times out, or stops. Processes run by other users are refused.
2. **The agent process.** Other processes running as you can't attach a debugger, read its memory, or make it dump core (see process hardening above). root can, and gets the key while the agent is unlocked.
3. **`SESH_AUTH_SOCK`.** It is a path, not a credential. Pointing it at another user's socket gets nothing: the CLI checks the socket owner's UID and refuses before sending anything. A process running as you could point it at a fake agent of its own and receive the password you type, but such a process can already read your terminal and files, so this adds nothing it couldn't already do.
4. **The agent's log.** It records start-up, auto-locks, and errors, never passwords, keys, or secrets.
5. **What the timeouts protect.** They bound how long an unlocked session stays useful, for example on a laptop left unlocked. After a lock the key is zeroed in place. What can remain in the agent's memory are short-lived buffers (the JSON messages that carried a password or a decrypted secret) that Go gives no way to zero; the runtime reuses or frees them later. The no-dump and no-attach settings cover them; the timeouts don't.

Not protected against: root (it can read the agent's memory), physical-memory attacks such as cold boot or DMA, or a process running as you that captures the password as you type it.

#### macOS Keychain backend (`backend = "keychain"`, macOS only)

Secrets are stored using the system `security` command with binary access restrictions:

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

### Encrypted Export

Exports produced with `--format encrypted` are wrapped in a portable envelope that anyone with the password can decrypt on any machine:

- **Argon2id** key derivation with the same parameters as the master-password key source (`t=3, m=64 MiB, p=4`)
- **AES-256-GCM** encryption of the JSON payload using the derived key
- **Random 32-byte salt** per export — the same password produces different ciphertext each time
- **Envelope format** (JSON): `{version, algorithm, salt, params, ciphertext}` — salt and params are public, matching the sidecar model

Unencrypted exports (`--format json`, `--format csv`) write secrets in plaintext and are intended for local scripting. Encrypted exports are the right choice for backups, transferring between machines, or storing in any medium the user doesn't fully trust. Use a strong password — the same brute-force threat model applies as with the master-password key source.

### Switching key sources (`sesh rekey`)

`sesh rekey --to <source>` re-encrypts every entry under a different key source and swaps the result into place atomically. The cryptographic posture during and after a rekey:

- **No plaintext-on-disk window.** Unlike the export-then-import workaround, rekey never writes a plaintext-equivalent file (an encrypted export still sits on disk encrypted only with the export password). All re-encryption happens in-process; only encrypted-at-rest databases ever touch the filesystem.
- **Per-row salt regeneration.** Every entry gets a fresh per-row salt under the new key. Encrypted ciphertext changes for every row even when the plaintext is identical.
- **Recoverable backup.** On success the original database is preserved at `<dbPath>.pre-rekey`. The user is responsible for deleting it once they've verified the new state works (`shred -u` recommended on traditional filesystems).
- **Old key state is preserved deliberately.** When switching keychain → password, the old keychain entry is left in place (now unused); same for the sidecar when switching password → keychain. This gives an additional rollback path and avoids the situation where a partial failure has destroyed the user's only access to a recoverable backup. The summary message points at the manual cleanup paths.
- **The key check moves with the vault.** The new database records its own check value for the new key before the swap, so the check switches in the same rename as the entries. Rekey verifies the source vault's key without writing to it.
- **Refusal-over-overwrite for target state.** If the target's persistent state already exists (a stale sidecar, or a keychain entry left over from a prior switch), rekey refuses and asks the user to clean up manually. The reasoning: silent overwrite of a salt or stored key could destroy access to whatever the user originally had.

### Why This Matters

Compare sesh's approach to alternatives:

| Storage Method | Encryption | Access Control | User Experience |
|----------------|------------|----------------|-----------------|
| sesh (default: SQLite + master password) | AES-256-GCM + Argon2id | File permissions + passphrase; key cached in a per-user agent after unlock | Prompt once per agent session |
| sesh (SQLite + Keychain key, macOS) | AES-256-GCM + Argon2id | File permissions + encryption key in Keychain | Transparent |
| sesh (Keychain backend, macOS) | OS-level (AES-256) | OS-enforced binary binding | Transparent |
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

5. **Hardening the Long-Lived Agent**

   The sesh agent holds the key for minutes or hours, so zeroing alone isn't enough. It also disables core dumps, blocks debugger attach, and keeps the key in memory that is never swapped, and it refuses to start if it can't. See [Sesh agent](#sesh-agent).

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
    // ... (security-relevant methods shown)
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

- **Local-Only Storage**: All data in macOS Keychain or local encrypted SQLite
- **Audit Trail**: Every secret access, modification, and deletion is logged (SQLite backend)
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

I aim to respond within 72 hours and fix critical issues within 7 days.

## Conclusion

sesh provides a security model that prioritizes:

1. **User Privacy**: No data collection, no cloud dependencies
2. **Practical Security**: Layered defenses within Go's constraints
3. **Transparency**: Honest about capabilities and limitations
4. **User Control**: You own your authentication workflow

While perfect security is impossible, sesh significantly improves upon mobile apps, browser extensions, and corporate MFA solutions by keeping your authentication local, private, and under your control.
