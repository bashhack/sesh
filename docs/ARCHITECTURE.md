# sesh Architecture

This document describes the architecture of sesh, an extensible terminal-first authentication toolkit for secure credential workflows.

## Architectural Principles

sesh's architecture is driven by four core principles that shape every design decision:

### 1. Plugin-Based Extensibility
**Principle**: Authentication providers should be pluggable components, not hardcoded implementations.

**Why**: Organizations use diverse authentication systems. By making providers pluggable:
- New providers can be added without touching core code
- Each provider can evolve independently
- Users only interact with providers they need
- Testing becomes focused and isolated

**How**: The `ServiceProvider` interface defines a contract that all providers must fulfill. The Registry pattern allows dynamic provider discovery and instantiation.

### 2. Security Through Isolation
**Principle**: Each component should have minimal access to what it needs, nothing more.

**Why**: Security breaches often exploit overly-broad permissions. By isolating components:
- Secrets never touch the filesystem or command arguments
- Each provider manages its own secret storage namespace
- Memory exposure windows are minimized
- Attack surface is reduced to essential operations

**How**: Keychain entries are scoped per-provider, secrets flow through stdin pipes, and memory is zeroed after use.

### 3. Terminal-Native Experience
**Principle**: Terminal users shouldn't need to context-switch to graphical tools.

**Why**: Developers live in terminals. Breaking flow to use a GUI or phone:
- Disrupts concentration and productivity
- Introduces friction in automated workflows
- Creates dependency on additional devices
- Complicates scripting and automation

**How**: Subshells provide isolated environments, clipboard integration enables quick pastes, and all operations are scriptable.

### 4. Interface-Driven Design
**Principle**: Every external dependency must be abstracted behind an interface.

**Why**: Direct dependencies create brittle, untestable code. With interfaces:
- Unit tests can mock any external system
- Implementations can be swapped (e.g., different keychain backends)
- Code remains loosely coupled
- Behavior is documented through contracts

**How**: AWS CLI, Keychain, TOTP generation, and even command execution are all behind interfaces with mock implementations.

## Architectural Layers

The architecture follows a strict layering model where dependencies flow downward:

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

### Why This Layering?

**CLI Layer**: Thin and focused on user interaction. This separation means:
- Alternative CLIs could be built (e.g., a TUI version)
- Business logic isn't mixed with presentation
- Testing can focus on user workflows

**Core Layer**: Orchestrates without implementing. This abstraction:
- Keeps provider-specific logic out of the application flow
- Enables consistent behavior across all providers
- Allows for cross-cutting concerns (logging, metrics)

**Provider Layer**: Self-contained authentication modules. This isolation:
- Prevents provider dependencies from leaking
- Allows providers to use different strategies
- Enables parallel development of providers

**Infrastructure Layer**: Shared utilities without business logic. This foundation:
- Prevents code duplication across providers
- Centralizes security-critical operations
- Provides consistent behavior for common tasks

## Component Deep Dive

### CLI Layer: Where Simplicity Meets Power

The CLI layer embodies the Unix philosophy: do one thing well.

**Design Decisions:**

1. **Separation of Concerns**:
   - `main.go` handles argument parsing and routing
   - `app.go` manages application lifecycle and dependencies
   - `app_subshell.go` isolates subshell complexity

2. **Dependency Injection**:
   ```go
   func NewApp(keychainProvider keychain.Provider, versionInfo VersionInfo) *App
   ```
   Why? Testing. Every external dependency can be mocked, making the CLI fully testable.

3. **Provider Registration**:
   ```go
   func (a *App) registerProviders() {
       awsP := awsProvider.NewProvider(a.AWS, a.Keychain, a.TOTP)
       a.Registry.RegisterProvider(awsP)
   }
   ```
   Why? Centralized registration makes provider discovery explicit and debuggable.

### The Power of the Provider Interface

The `ServiceProvider` interface is the heart of sesh's extensibility:

```go
type ServiceProvider interface {
    // Identity - Who are you?
    Name() string
    Description() string
    
    // Configuration - What do you need?
    SetupFlags(fs FlagSet) error
    GetSetupHandler() interface{}
    
    // Operations - What can you do?
    GetCredentials() (Credentials, error)
    GetClipboardValue() (Credentials, error)
    ListEntries() ([]ProviderEntry, error)
    DeleteEntry(id string) error
    
    // Validation - Are we ready?
    ValidateRequest() error
    
    // Help - How do you work?
    GetFlagInfo() []FlagInfo
}
```

**Why This Interface Design?**

1. **Minimal Surface Area**: Every method has a clear, single purpose. No kitchen sink interfaces.

2. **Lifecycle Awareness**: Methods follow the natural flow:
   - Setup flags → Validate request → Get credentials
   - This prevents invalid states and guides implementation

3. **Mode Flexibility**: `GetCredentials()` vs `GetClipboardValue()` allows providers to optimize for different workflows without conditional logic.

4. **Self-Documenting**: `GetFlagInfo()` makes providers introspectable, enabling dynamic help generation.

**The Genius of Optional Interfaces**

Not all providers need subshells. Instead of a bloated base interface:

```go
type SubshellProvider interface {
    NewSubshellConfig(creds Credentials) interface{}
}
```

This pattern (inspired by Go's `io.WriterTo`) means:
- Providers declare capabilities through interface implementation
- Core code uses type assertions to discover features
- New capabilities can be added without breaking existing providers

### Infrastructure: Security-First Building Blocks

Each infrastructure component embodies specific security principles:

#### Keychain Integration: Trust Through OS Primitives

**Why macOS Keychain?**
- Hardware-backed encryption when available
- Process-level access control via `-T` flag
- User-transparent authorization dialogs
- Automatic locking on sleep/screensaver

**Key Design Choice**: Binary path restrictions
```bash
security add-generic-password ... -T /path/to/sesh
```
This means even if another process knows the service name, it cannot access the secret.

#### TOTP Engine: Time as a Security Factor

**Why Generate Two Codes?**
```go
// Current + Next code generation
codes := []string{currentCode, nextCode}
```
Edge case: User copies code at 29 seconds. By the time they paste, it's expired. Providing the next code eliminates this frustration without compromising security.

#### Secure Memory: Paranoid by Design

**The Challenge**: Go's garbage collector moves memory, making true secure erasure impossible.

**Our Approach**: Defense in depth
1. Prefer `[]byte` over `string` (mutable vs immutable)
2. Zero immediately after use
3. Use `runtime.KeepAlive()` to prevent optimization
4. Pass secrets via stdin, never command arguments

**Why This Matters**: Even partial mitigation reduces the window for memory dumps, cold boot attacks, and swap file analysis.

#### Subshell: Isolation Through Process Boundaries

**Design Philosophy**: Credentials should exist in an isolated environment that:
1. Visually indicates its special status (custom prompt)
2. Prevents accidental nesting (`SESH_ACTIVE` check)
3. Cleans up automatically on exit
4. Provides built-in helper functions

**Why Not Just Export Variables?**
- Subshells make the credential lifecycle explicit
- Users can't accidentally pollute their main shell
- Clear entry/exit points for audit logging (future)
- Visual feedback reduces security mistakes

### Setup System: First Impressions Matter

The setup system recognizes that security tools often fail at onboarding.

**Design Principles:**

1. **Progressive Disclosure**: Start with QR scanning (easy path), fall back to manual entry
2. **Immediate Validation**: Verify secrets before storing to prevent frustration
3. **Test Before Trust**: Generate test codes so users can verify setup worked

```go
type SetupHandler interface {
    ServiceName() string
    Setup() error
}
```

**Why So Simple?** Setup is complex enough. The interface shouldn't add cognitive load. Each handler encapsulates:
- Service-specific secret formats
- Validation rules
- Test code generation
- User guidance

**The Service Registry Pattern**:
```go
type SetupService interface {
    RegisterHandler(handler SetupHandler)
    SetupService(serviceName string) error
    GetAvailableServices() []string
}
```

This separation allows:
- Dynamic handler discovery
- Consistent setup experience across providers
- Easy addition of new setup flows

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

## Security Architecture: Trust Nothing, Verify Everything

### Defense in Depth

Each layer assumes the others might fail:

1. **Storage Security**
   - **Threat**: Other processes reading secrets
   - **Defense**: Binary path restrictions (`-T` flag)
   - **Why It Works**: OS kernel enforces access control

2. **Memory Security**
   - **Threat**: Memory dumps, swap files, cold boot attacks
   - **Defense**: Immediate zeroing, byte slice preference
   - **Reality Check**: Go's GC limits our control, but we minimize exposure

3. **Process Security**
   - **Threat**: Secrets visible in `ps`, shell history, or logs
   - **Defense**: Stdin pipes for all secret transmission
   - **Key Insight**: Process arguments are public, stdin is private

4. **Session Security**
   - **Threat**: Credential leakage between sessions
   - **Defense**: Isolated subshells with automatic cleanup
   - **User Benefit**: Clear security boundaries

5. **Access Security**
   - **Threat**: Network interception, MITM attacks
   - **Defense**: No network code - delegate to AWS CLI
   - **Philosophy**: Reuse battle-tested security implementations

### Trust Boundaries

Understanding where trust transitions occur:

```
User Input → [TRUST BOUNDARY] → sesh
    ↓
   sesh → [TRUST BOUNDARY] → macOS Keychain
    ↓
   sesh → [TRUST BOUNDARY] → AWS CLI
    ↓
AWS CLI → [TRUST BOUNDARY] → AWS APIs
```

Each boundary represents:
- A potential attack surface
- A place where validation must occur
- An opportunity for defense in depth

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

## Testing Architecture: Fast, Reliable, Comprehensive

### Why Interfaces Everywhere?

Consider testing AWS authentication without interfaces:
- Need real AWS credentials
- Tests hit actual AWS APIs
- Slow, flaky, expensive
- Can't test error conditions

With interfaces:
```go
type Provider interface {
    GetSessionToken(profile, serial string, code []byte) (Credentials, error)
}
```

Now tests can:
- Run in milliseconds
- Test error paths easily
- Run in parallel
- Work offline

### The Test Helper Pattern

`MockExecCommand` uses Go's test binary as a mock process:

```go
func MockExecCommand(output string, err error) func(string, ...string) *exec.Cmd
```

**Why This Matters**: Testing CLI tools traditionally requires:
- Shipping mock binaries
- Complex PATH manipulation  
- Platform-specific code

The test helper pattern reuses the test binary itself as the mock, eliminating these issues.

### Mock Generation Strategy

Using `mockgen` for consistency:
- Mocks stay in sync with interfaces
- Generated code is predictable
- Reduces boilerplate
- Enables powerful assertions

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