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
│ /sesh/cmd/sesh  │     │ /internal/       │     │ /internal/      │
│                 │     │                  │     │   provider/     │
│ • Flag parsing  │     │ • Registry       │     │ • AWS Provider  │
│ • User I/O      │     │ • Setup Service  │     │ • TOTP Provider │
│ • Subshell mgmt │     │ • Coordination   │     │ • Future...     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                         │
         └───────────────────────┴─────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Infrastructure Layer  │
                    │      /internal/         │
                    │                         │
                    │ • Keychain (secrets)    │
                    │ • TOTP generation       │
                    │ • Secure memory         │
                    │ • Clipboard             │
                    │ • QR code scanning      │
                    │ • AWS CLI integration   │
                    └─────────────────────────┘
```

## Component Architecture

### CLI Layer (`/sesh/cmd/sesh`)

The entry point that handles user interaction:

- **main.go** - Entry point with version injection via ldflags and the `run()` function for command parsing
- **app.go** - Application struct with dependency injection and provider registration via `registerProviders()`
- **app_subshell.go** - Subshell launching logic with provider validation

Key responsibilities:
- Parse command-line flags with provider-specific handling (in `run()` function)
- Route commands to appropriate providers via the Registry
- Manage subshell lifecycle through `LaunchSubshell()`
- Handle output formatting and error display

### Provider System (`/internal/provider`)

The plugin architecture that makes sesh extensible:

```go
type ServiceProvider interface {
    // Identity
    Name() string
    Description() string
    
    // Configuration
    SetupFlags(fs FlagSet) error
    GetSetupHandler() interface{}
    
    // Operations
    GetCredentials() (Credentials, error)
    GetClipboardValue() (Credentials, error)
    ListEntries() ([]ProviderEntry, error)
    DeleteEntry(id string) error
    
    // Validation
    ValidateRequest() error
    
    // Help
    GetFlagInfo() []FlagInfo
}
```

Current providers:
- **AWS Provider** (`/internal/provider/aws`) - AWS CLI + MFA authentication
- **TOTP Provider** (`/internal/provider/totp`) - Generic TOTP for any service

Additional interfaces:
- **SubshellProvider** - Required for providers that support subshell mode:
  ```go
  type SubshellProvider interface {
      NewSubshellConfig(creds Credentials) interface{}
  }
  ```

Note: Clipboard and subshell support are determined by:
- Subshell: Provider must implement `SubshellProvider` interface
- Clipboard: All providers must implement `GetClipboardValue()` method

### Infrastructure Components

#### Keychain Integration (`/internal/keychain`)

Secure storage using macOS Keychain:
- Binary path restrictions via `-T` flag to limit access to sesh binary only
- Metadata compression with zstd for efficient storage of provider metadata
- Account/service separation for multi-tenancy (e.g., multiple AWS profiles)
- Interactive password entry via stdin to avoid exposure in process listings
- Automatic cleanup of references after secret retrieval

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

- **Clipboard** (`/internal/clipboard`) - Cross-platform clipboard access via pbcopy/xclip/wl-copy
- **QR Code** (`/internal/qrcode`) - Screenshot-based QR scanning using pngpaste and zbarimg
- **Constants** (`/internal/constants`) - Binary path detection via `GetSeshBinaryPath()`, service prefixes
- **AWS** (`/internal/aws`) - AWS CLI wrapper for STS operations and MFA device queries
- **Environment** (`/internal/env`) - Environment variable helpers and manipulation
- **Password Manager** (`/internal/password`) - Placeholder for future password storage features

### Setup System (`/internal/setup`)

Interactive configuration wizards:

```go
type SetupHandler interface {
    ServiceName() string
    Setup() error
}

type SetupService interface {
    RegisterHandler(handler SetupHandler)
    SetupService(serviceName string) error
    GetAvailableServices() []string
}
```

Features:
- Provider-specific setup flows via registered handlers
- QR code scanning with manual fallback
- Secret validation and normalization
- Overwrite protection with user confirmation
- Progress indicators and test code generation

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
                            Credentials returned
                                     │
                      ┌──────────────┴──────────────┐
                      │                             │
                      ▼                             ▼
              Subshell Mode                 Clipboard Mode
              (LaunchSubshell)              (GetClipboardValue)
```

### TOTP Generation Flow

```
User ──► CLI ──► TOTP Provider ──► Keychain (get secret)
                      │                  │
                      │                  ▼
                      │             TOTP Engine
                      │            (RFC 6238)
                      │                  │
                      │                  ▼
                      │          Generate current +
                      │            next codes
                      │                  │
                      └────► Clipboard/Display
                            (with time remaining)
```

## Security Architecture

### Defense in Depth

1. **Storage Security** - macOS Keychain with binary path restrictions (`-T` flag)
2. **Memory Security** - Best-effort zeroing with `runtime.KeepAlive()`, byte slice preference over strings
3. **Process Security** - Secrets via stdin using `ExecWithSecretInput()`, never in command args
4. **Session Security** - Isolated subshells with `SESH_ACTIVE` check, automatic credential cleanup
5. **Access Security** - No direct network calls, all operations through local AWS CLI

### Trust Boundaries

- **User ↔ sesh** - Terminal interface, no GUI attack surface
- **sesh ↔ Keychain** - OS-mediated access control
- **sesh ↔ AWS CLI** - Process boundary, stdin for secrets
- **Subshell ↔ Parent** - Environment isolation

## Extensibility Points

### Adding a New Provider

1. Implement `ServiceProvider` interface in `/internal/provider/yourprovider/`
2. Add provider-specific flags in the `SetupFlags()` method
3. Create setup handler implementing `SetupHandler` in `/internal/setup/`
4. Register both provider and setup handler in `app.registerProviders()` method:
   ```go
   func (a *App) registerProviders() {
       // Create and register provider
       yourProvider := yourprovider.NewProvider(dependencies...)
       a.Registry.RegisterProvider(yourProvider)
       
       // Register setup handler
       a.SetupService.RegisterHandler(setup.NewYourSetupHandler(a.Keychain))
   }
   ```

### Provider Capabilities

Providers can support:
- **Subshell mode**: Implement `SubshellProvider` interface and return a `subshell.Config`
- **Clipboard mode**: Already required via `GetClipboardValue()` method
- **Multiple profiles**: Handle via provider-specific flags (e.g., `--profile`)
- **Metadata storage**: Use keychain metadata service with compression

## Error Handling Strategy

Errors flow up with context using Go's error wrapping:
```go
// Infrastructure level - specific error
return fmt.Errorf("keychain access failed: %w", err)

// Provider level - add service context  
return fmt.Errorf("failed to get AWS credentials for profile %s: %w", profile, err)

// App level - user-friendly display
if err != nil {
    fmt.Fprintf(app.Stderr, "❌ %v\n", err)
    // Additional help for common errors
    if strings.Contains(err.Error(), "provider") && strings.Contains(err.Error(), "not found") {
        fmt.Fprintf(app.Stderr, "\nRun 'sesh --list-services' to see available providers\n")
    }
}
```

## Testing Architecture

### Interface-Based Mocking

Every external dependency has an interface:
- `aws.Provider` - Mock AWS CLI calls
- `keychain.Provider` - Mock Keychain access
- `totp.Provider` - Mock TOTP generation

### Test Utilities

- `testutil.MockExecCommand` - Mock external commands using test helper process pattern
- Mock providers in `/internal/*/mocks/` generated with mockgen
- Helper functions for common test scenarios (e.g., temporary keychains, test credentials)
- Interface-based design enables unit testing without real AWS/Keychain access

## Performance Considerations

- Lazy provider initialization - providers created only when accessed
- Minimal dependencies for fast startup - no heavy frameworks
- Efficient metadata storage with zstd compression for keychain entries
- No network calls in critical path - all network ops delegated to AWS CLI
- Concurrent code generation for TOTP (current + next) to handle time boundaries

## Future Architecture Considerations

The architecture is designed to support:
- Additional authentication providers (GCP, Azure, Okta, etc.)
- Cross-platform keychain abstractions (Linux secret-service, Windows Credential Store)
- Encrypted backup/restore of credentials
- Terminal UI mode using libraries like tview or bubbletea
- Audit logging with structured logs
- Plugin loading from external binaries
- WebAuthn/FIDO2 support for hardware keys

## Directory Structure

```
sesh/
├── sesh/cmd/sesh/         # CLI entry point
│   ├── main.go            # Main function and command parsing
│   ├── app.go             # Application struct and provider registration
│   └── app_subshell.go    # Subshell launching logic
├── internal/              # Internal packages
│   ├── provider/          # Provider system
│   │   ├── interfaces.go  # Core interfaces
│   │   ├── registry.go    # Provider registry
│   │   ├── aws/           # AWS provider implementation
│   │   └── totp/          # TOTP provider implementation
│   ├── aws/               # AWS CLI integration
│   ├── keychain/          # macOS Keychain wrapper
│   ├── totp/              # TOTP engine (RFC 6238)
│   ├── secure/            # Security utilities
│   ├── subshell/          # Subshell management
│   ├── clipboard/         # Clipboard operations
│   ├── qrcode/            # QR code scanning
│   ├── setup/             # Setup wizards
│   └── testutil/          # Testing utilities
└── docs/                  # Documentation
```

## Conclusion

sesh's architecture prioritizes security, extensibility, and developer experience. The plugin-based design allows growth without complexity, while the security-first approach ensures user trust. By leveraging OS primitives and maintaining clear boundaries, sesh provides a solid foundation for terminal-based authentication workflows.