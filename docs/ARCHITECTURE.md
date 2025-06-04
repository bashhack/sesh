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

**The Rationale of Optional Interfaces**

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

## Data Flow: Following the Principle of Least Privilege

### AWS Authentication: A Study in Delegation

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

1. **No Direct AWS API Calls**: sesh never touches AWS APIs directly. Why?
   - AWS CLI handles credential caching, region selection, retries
   - Security updates come from AWS CLI updates
   - No need to manage AWS SDK dependencies

2. **Mode Branching at the End**: Credentials are generated the same way, then routed. This:
   - Ensures consistent security regardless of output mode
   - Simplifies testing (one credential path)
   - Allows future output modes without core changes

### TOTP: Pure Computation, No External Dependencies

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

**Why This Simplicity Works:**

1. **Stateless Computation**: TOTP is pure math - time + secret = code
2. **No Network Required**: Everything happens locally
3. **Predictable Timing**: 30-second windows are universal
4. **Dual Code Generation**: Solves for the boundary problem

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

## Extensibility: Growing Without Breaking

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

**Why This Works:**
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

## Error Philosophy: Fail Fast, Fail Clearly

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

### Why This Matters

Bad error: `error: -25300`  
Good error: `keychain access denied: no stored credentials for AWS profile 'prod'`  
Best error: `No AWS credentials found for profile 'prod'. Run: sesh --service aws --setup`

The architecture ensures errors get progressively more helpful as they flow up.

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

## Performance: Fast Enough to Not Notice

### Startup Performance

**Goal**: Sub-100ms from invocation to action.

**How We Achieve It:**

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

**Why zstd for Metadata?**
- Metadata can grow (multiple profiles, services)
- zstd offers best compression/speed ratio
- Transparent to providers
- Future-proof for richer metadata

## Living Architecture: Principles in Practice

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

### Why This Architecture Matters

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

## The Architecture Is the Product

sesh isn't just a tool that happens to have good architecture. The architecture IS the product:

- **Extensibility** isn't a feature, it's the foundation
- **Security** isn't added on, it's built in
- **Simplicity** isn't accidental, it's architected
- **Performance** isn't optimized, it's designed

This architecture ensures sesh can grow from two providers to twenty without becoming a mess, can handle new authentication methods without breaking existing ones, and can maintain security properties even as complexity grows.

That's the power of thoughtful architecture: it makes the right thing the easy thing.
