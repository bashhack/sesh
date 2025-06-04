# sesh Architecture

This document describes the architecture of sesh, a terminal-based authentication toolkit.

## Architectural Principles

sesh follows four architectural principles:

### 1. Plugin-Based Extensibility
**Principle**: Authentication providers should be pluggable components, not hardcoded implementations.

**Implementation**: The `ServiceProvider` interface defines a contract that all providers must fulfill. The Registry pattern allows dynamic provider discovery and instantiation. This enables:
- New providers can be added without touching core code
- Each provider can evolve independently
- Users only interact with providers they need
- Testing becomes focused and isolated

### 2. Component Isolation
**Principle**: Each component should have minimal access to what it needs, nothing more.

**Implementation**: Keychain entries are scoped per-provider, secrets flow through stdin pipes, and memory is zeroed after use. This provides:
- Secrets never touch the filesystem or command arguments
- Each provider manages its own secret storage namespace
- Memory exposure windows are minimized
- Attack surface is reduced to essential operations

### 3. Terminal-Based Workflow
**Principle**: Terminal users shouldn't need to context-switch to graphical tools.

**Implementation**: Subshells provide isolated environments, clipboard integration enables quick pastes, and all operations are scriptable. This approach:
- Maintains workflow continuity
- Reduces friction in automated workflows
- Eliminates dependency on additional devices
- Simplifies scripting and automation

### 4. Interface-Driven Design
**Principle**: Every external dependency must be abstracted behind an interface.

**Implementation**: AWS CLI, Keychain, TOTP generation, and command execution are all behind interfaces with mock implementations. This provides:
- Unit tests can mock any external system
- Implementations can be swapped (e.g., different keychain backends)
- Code remains loosely coupled
- Behavior is documented through contracts

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

### Layer Responsibilities

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

### CLI Layer


**Design Decisions:**

1. **Separation of Concerns**:
   - `main.go` handles argument parsing and routing
   - `app.go` manages application lifecycle and dependencies
   - `app_subshell.go` isolates subshell complexity

2. **Dependency Injection**:
   ```go
   func NewApp(keychainProvider keychain.Provider, versionInfo VersionInfo) *App
   ```
   This enables mocking of all external dependencies for comprehensive testing.

3. **Provider Registration**:
   ```go
   func (a *App) registerProviders() {
       awsP := awsProvider.NewProvider(a.AWS, a.Keychain, a.TOTP)
       a.Registry.RegisterProvider(awsP)
   }
   ```
   Centralized registration makes provider discovery explicit and debuggable.

### Provider Interface Design

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

**Interface Design Rationale**

1. **Minimal Surface Area**: Every method has a clear, single purpose. No kitchen sink interfaces.

2. **Lifecycle Awareness**: Methods follow the natural flow:
   - Setup flags → Validate request → Get credentials
   - This prevents invalid states and guides implementation

3. **Mode Flexibility**: `GetCredentials()` vs `GetClipboardValue()` allows providers to optimize for different workflows without conditional logic.

4. **Self-Documenting**: `GetFlagInfo()` makes providers introspectable, enabling dynamic help generation.

**The Rationale of Optional Interfaces**

Not all providers need subshells. Instead of a bloated base interface:

```go
type SubshellProvider interface {
    NewSubshellConfig(creds Credentials) interface{}
}
```

Pattern benefits (similar to Go's `io.WriterTo`):
- Capability declaration via interfaces
- Runtime feature discovery
- Non-breaking capability additions

### Infrastructure Components

Each infrastructure component embodies specific security principles:

#### Keychain Integration

**macOS Keychain Integration**
- Hardware-backed encryption when available
- Process-level access control via `-T` flag
- User-transparent authorization dialogs

**Key Design Choice**: Binary path restrictions
```bash
security add-generic-password ... -T /path/to/sesh
```
This means even if another process knows the service name, it cannot access the secret.

#### TOTP Generation

**Dual Code Generation**
```go
// Current + Next code generation
codes := []string{currentCode, nextCode}
```
Generates current and next codes to handle boundary conditions at 30-second intervals.

#### Memory Management

**Challenge**: Go's garbage collector prevents true secure erasure.

**Approach**:
1. Use `[]byte` over `string` for mutability
2. Zero immediately after use
3. Use `runtime.KeepAlive()` to prevent optimization
4. Pass secrets via stdin

**Benefit**: Reduces the window for memory dumps, cold boot attacks, and swap file analysis.

#### Subshell Implementation

**Design**:
1. Custom prompt for visual indication
2. `SESH_ACTIVE` check prevents nesting
3. Automatic cleanup on exit
4. Built-in helper functions

**Subshell Benefits**
- Makes credential lifecycle explicit
- Prevents pollution of main shell environment
- Provides clear entry/exit points for audit logging
- Visual feedback reduces security mistakes

### Setup System

**Design Principles:**

1. **Progressive Disclosure**: QR scanning with manual entry fallback
2. **Immediate Validation**: Verify secrets before storing
3. **Test Before Trust**: Generate test codes for verification

```go
type SetupHandler interface {
    ServiceName() string
    Setup() error
}
```

**Design**: Each handler encapsulates:
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

Benefits:
- Dynamic handler discovery
- Consistent setup experience
- Easy addition of new setup flows

## Data Flow Architecture

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

**Key Design Insights:**

1. **No Direct AWS API Calls**: sesh delegates to AWS CLI for:
   - Credential caching, region selection, retries
   - Security updates through AWS CLI updates
   - Elimination of AWS SDK dependencies

2. **Mode Branching at the End**: Uniform credential generation with output-specific routing:
   - Consistent security across modes
   - Simplified testing
   - Extensible output modes

### TOTP Data Flow

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

**TOTP Implementation Details:**

1. **Stateless Computation**: TOTP is pure math - time + secret = code
2. **No Network Required**: Everything happens locally
3. **Predictable Timing**: 30-second windows are universal
4. **Dual Code Generation**: Solves for the boundary problem

## Security Architecture

### Defense in Depth

Each layer assumes the others might fail:

1. **Storage Security**
   - **Threat**: Other processes reading secrets
   - **Defense**: Binary path restrictions (`-T` flag)
   - **Enforcement**: OS kernel access control

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

## Extensibility Model

### The Provider Contract

Adding a new provider is deliberately straightforward:

```go
// 1. Define your provider
type YourProvider struct {
    keychain keychain.Provider
    // your fields
}

// 2. Implement ServiceProvider
func (p *YourProvider) GetCredentials() (Credentials, error) {
    // Your auth logic
}

// 3. Register it
func (a *App) registerProviders() {
    a.Registry.RegisterProvider(yourprovider.New(a.Keychain))
}
```

**Implementation Benefits:**
- Clear contract (ServiceProvider interface)
- Dependency injection provides needed services
- Registration is explicit and centralized
- No global state or init() magic

### Capability Evolution

As providers need new features, we can add optional interfaces:

```go
// Today: Basic provider
type ServiceProvider interface { ... }

// Tomorrow: Add audit logging
type AuditableProvider interface {
    GetAuditEvents() []AuditEvent
}

// Future: Hardware key support
type HardwareKeyProvider interface {
    RequiresHardwareKey() bool
    WaitForKeyTouch() error
}
```

This pattern (from Go's io package) means:
- Existing providers keep working
- New features are opt-in
- Type assertions discover capabilities
- No versioning nightmare

## Error Handling

### Error Design Principles

1. **Context Over Codes**: Users need to know *what went wrong* and *how to fix it*
2. **Wrap Don't Replace**: Preserve error chains for debugging
3. **User-Friendly Top Layer**: Technical details in logs, actionable messages to users

### Error Flow Architecture

```go
// Layer 1: Infrastructure (Technical)
return fmt.Errorf("keychain access failed: %w", err)
// Full technical context for debugging

// Layer 2: Provider (Contextual)  
return fmt.Errorf("failed to get AWS credentials for profile %s: %w", profile, err)
// Adds business context

// Layer 3: CLI (Actionable)
if err != nil {
    fmt.Fprintf(app.Stderr, "❌ %v\n", err)
    
    // Provide specific guidance
    switch {
    case strings.Contains(err.Error(), "not found"):
        fmt.Fprintf(app.Stderr, "Try: sesh --service aws --setup\n")
    case strings.Contains(err.Error(), "expired"):
        fmt.Fprintf(app.Stderr, "Your session expired. Run sesh again.\n")
    }
}
```

### Error Message Examples

- Poor: `error: -25300`  
- Better: `keychain access denied: no stored credentials for AWS profile 'prod'`  
- Best: `No AWS credentials found for profile 'prod'. Run: sesh --service aws --setup`

Errors become progressively more actionable as they flow up through layers.

## Testing Strategy

### Interface-Based Testing

Interface-based testing enables:
```go
type Provider interface {
    GetSessionToken(profile, serial string, code []byte) (Credentials, error)
}
```

- Millisecond execution
- Error path testing
- Parallel execution
- Offline operation

### The Test Helper Pattern

`MockExecCommand` uses Go's test binary as a mock process:

```go
func MockExecCommand(output string, err error) func(string, ...string) *exec.Cmd
```

**Test Helper Benefits**: The pattern reuses the test binary itself as the mock, eliminating:
- Shipping mock binaries
- Complex PATH manipulation  
- Platform-specific code

## Performance Characteristics

### Startup Performance

**Target**: Sub-100ms startup time achieved through:

1. **Lazy Loading**: Providers initialize only when selected
   ```go
   // Bad: Initialize everything
   app := NewApp(initAWS(), initTOTP(), initGCP(), ...)
   
   // Good: Initialize on demand
   provider := registry.GetProvider(selectedService)
   ```

2. **Minimal Dependencies**: No framework bloat
   - No ORM for simple keychain operations
   - No heavy CLI framework for flag parsing
   - No logging framework in hot path

3. **Smart Defaults**: Most users have one profile
   - Don't scan all credentials on startup
   - Don't validate until necessary
   - Don't load metadata until requested

### Runtime Performance

**Credential Generation**: Near-instant
- TOTP is pure computation (microseconds)
- AWS CLI calls are the bottleneck (1-2 seconds)
- Keychain access is OS-optimized (milliseconds)

**Metadata Compression (zstd)**
- Handles growth (multiple profiles, services)
- Optimal compression/speed ratio
- Transparent to providers
- Supports future metadata expansion

## Implementation Details

### Directory Structure as Architecture

```
sesh/
├── sesh/cmd/sesh/         # Thin CLI layer - presentation only
├── internal/              # The heart of sesh
│   ├── provider/          # Plugin system - extensibility realized
│   │   ├── interfaces.go  # The contract that enables everything
│   │   ├── registry.go    # Dynamic provider discovery
│   │   └── */             # Self-contained provider implementations
│   ├── keychain/          # Security through OS primitives
│   ├── secure/            # Paranoid practices codified
│   └── */                 # Each package focused on one thing
└── docs/                  # Architecture as documentation
```

### Architecture Benefits

**For Security Engineers:**
- Clear trust boundaries
- Auditable secret flows
- Defense in depth at every layer
- No security through obscurity

**For Developers:**
- Add providers without understanding all of sesh
- Test in isolation
- Clear patterns to follow
- Interfaces make the rules explicit

**For Users:**
- Consistent experience across providers
- Fast and predictable
- Secure by default
- Extensible for their needs

## Summary

sesh isn't just a tool that happens to have good architecture. The architecture IS the product:

- **Extensibility** isn't a feature, it's the foundation
- **Security** isn't added on, it's built in
- **Simplicity** isn't accidental, it's architected
- **Performance** isn't optimized, it's designed

This architecture ensures sesh can grow from two providers to twenty without becoming a mess, can handle new authentication methods without breaking existing ones, and can maintain security properties even as complexity grows.

That's the power of thoughtful architecture: it makes the right thing the easy thing.
