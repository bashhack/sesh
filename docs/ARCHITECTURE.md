# sesh Architecture

This document describes the architecture of sesh, an extensible terminal-first authentication toolkit for secure credential workflows.

## Design Philosophy

sesh is built on four core architectural principles:

1. **Plugin-Based Extensibility** - New authentication providers can be added without modifying core code
2. **Security by Design** - Leverage OS security primitives, minimize attack surface, handle memory carefully
3. **Terminal-First UX** - Optimized for CLI workflows with features like subshells and clipboard integration  
4. **Testable Architecture** - Interface-based design enables comprehensive testing without external dependencies

## System Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   CLI Layer     │────▶│   Core Layer     │────▶│ Provider Layer  │
│                 │     │                  │     │                 │
│ • Flag parsing  │     │ • Registry       │     │ • AWS Provider  │
│ • User I/O      │     │ • App logic      │     │ • TOTP Provider │
│ • Subshell      │     │ • Coordination   │     │ • Future...     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                         │
         └───────────────────────┴─────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Infrastructure Layer  │
                    │                         │
                    │ • Keychain (secrets)    │
                    │ • TOTP generation       │
                    │ • Secure memory         │
                    │ • Clipboard             │
                    │ • QR code scanning      │
                    └─────────────────────────┘
```

## Component Architecture

### CLI Layer (`/sesh/cmd/sesh`)

The entry point that handles user interaction:

- **main.go** - Entry point, version injection via ldflags
- **app.go** - Application struct with dependency injection
- **run()** - Command parsing and routing logic

Key responsibilities:
- Parse command-line flags with provider-specific handling
- Route commands to appropriate providers
- Manage subshell lifecycle
- Handle output formatting

### Provider System (`/internal/provider`)

The plugin architecture that makes sesh extensible:

```go
type ServiceProvider interface {
    // Identity
    Name() string
    Description() string
    
    // Configuration
    SetupFlags(fs FlagSet) error
    ValidateRequest() error
    GetFlagInfo() []FlagInfo
    
    // Operations
    GetCredentials() (Credentials, error)
    GetClipboardValue() (Credentials, error)
    ListEntries() ([]ProviderEntry, error)
    DeleteEntry(id string) error
    
    // Setup
    GetSetupHandler() interface{}
}
```

Current providers:
- **AWS Provider** (`/internal/provider/aws`) - AWS CLI + MFA authentication
- **TOTP Provider** (`/internal/provider/totp`) - Generic TOTP for any service

Optional interfaces:
- **SubshellProvider** - For providers that launch custom shell environments
- **SupportsClipboard()** - Indicates clipboard mode support
- **SupportsSubshell()** - Indicates subshell mode support

### Infrastructure Components

#### Keychain Integration (`/internal/keychain`)

Secure storage using macOS Keychain:
- Binary path restrictions via `-T` flag
- Metadata compression with zstd
- Account/service separation for multi-tenancy
- Interactive password entry to avoid process listing

#### TOTP Engine (`/internal/totp`)

Time-based one-time password generation:
- Standard RFC 6238 implementation
- Consecutive code generation for edge cases
- Time window calculations
- Base32 secret validation

#### Secure Memory (`/internal/secure`)

Defense-in-depth memory handling:
- `SecureZeroBytes()` with compiler optimization protection
- Secure command execution with stdin for secrets
- Documented limitations of Go's memory model
- Best-effort string zeroing

#### Subshell (`/internal/subshell`)

Isolated credential environments:
- Shell detection (bash/zsh/sh)
- Custom RC file generation
- Environment variable injection
- Session status tracking
- Nested session prevention

#### Additional Infrastructure

- **Clipboard** (`/internal/clipboard`) - Cross-platform clipboard access
- **QR Code** (`/internal/qrcode`) - Screenshot-based QR scanning
- **Constants** (`/internal/constants`) - Binary path detection, prefixes
- **Password Manager** (`/internal/password`) - Future password storage
- **Environment** (`/internal/env`) - Environment variable helpers

### Setup System (`/internal/setup`)

Interactive configuration wizards:

```go
type SetupHandler interface {
    ServiceName() string
    Setup() error
}
```

Features:
- Provider-specific setup flows
- QR code scanning with fallback
- Secret validation and normalization
- Overwrite protection
- Progress indicators

## Data Flow

### AWS Authentication Flow

```
User ──► CLI ──► AWS Provider ──► Keychain (get secret)
                      │               │
                      │               ▼
                      │          TOTP Engine
                      │               │
                      │               ▼
                      └────► AWS CLI (STS call)
                                     │
                                     ▼
                            Subshell with credentials
```

### TOTP Generation Flow

```
User ──► CLI ──► TOTP Provider ──► Keychain (get secret)
                      │                  │
                      │                  ▼
                      │             TOTP Engine
                      │                  │
                      │                  ▼
                      └────► Clipboard/Display
```

## Security Architecture

### Defense in Depth

1. **Storage Security** - macOS Keychain with binary restrictions
2. **Memory Security** - Best-effort zeroing, byte slice preference
3. **Process Security** - Avoid command-line exposure, use stdin
4. **Session Security** - Isolated subshells, automatic cleanup
5. **Access Security** - No network calls, local-only operation

### Trust Boundaries

- **User ↔ sesh** - Terminal interface, no GUI attack surface
- **sesh ↔ Keychain** - OS-mediated access control
- **sesh ↔ AWS CLI** - Process boundary, stdin for secrets
- **Subshell ↔ Parent** - Environment isolation

## Extensibility Points

### Adding a New Provider

1. Implement `ServiceProvider` interface
2. Add provider-specific flags
3. Create setup handler
4. Register in `app.registerProviders()`

### Provider Capabilities

Providers can optionally support:
- Custom subshells (implement `SubshellProvider`)
- Clipboard mode (implement `SupportsClipboard()`)
- Multiple profiles
- Metadata storage

## Error Handling Strategy

Errors flow up with context:
```go
// Low level - specific error
return fmt.Errorf("keychain access failed: %w", err)

// Provider level - add context  
return fmt.Errorf("failed to get AWS credentials: %w", err)

// App level - user-friendly message
fmt.Fprintf(app.Stderr, "❌ %v\n", err)
```

## Testing Architecture

### Interface-Based Mocking

Every external dependency has an interface:
- `aws.Provider` - Mock AWS CLI calls
- `keychain.Provider` - Mock Keychain access
- `totp.Provider` - Mock TOTP generation

### Test Utilities

- `testutil.MockExecCommand` - Mock external commands
- Mock providers in `/internal/*/mocks/`
- Helper functions for common test scenarios

## Performance Considerations

- Lazy provider initialization
- Minimal dependencies for fast startup
- Efficient metadata storage with compression
- No network calls in critical path

## Future Architecture Considerations

The architecture is designed to support:
- Additional authentication providers (GCP, Azure, etc.)
- Cross-platform keychain abstractions
- Encrypted backup/restore
- Terminal UI mode
- Audit logging

## Conclusion

sesh's architecture prioritizes security, extensibility, and developer experience. The plugin-based design allows growth without complexity, while the security-first approach ensures user trust. By leveraging OS primitives and maintaining clear boundaries, sesh provides a solid foundation for terminal-based authentication workflows.