# sesh Architecture

This document describes the architecture of sesh, focusing on how it's structured for testability and extensibility.

## Overview

Sesh is designed with the following architectural principles:

- **Plugin-based architecture** for extensibility
- **Interface-based dependency injection** for testability
- **Clear separation of concerns** between components
- **Minimal dependencies** for security and simplicity
- **Consistent error handling** across all operations

## Component Architecture

The system is divided into these main components:

### Plugin Infrastructure (internal/provider)

Responsible for:
- Defining the common interface for all service providers
- Managing registration of available providers
- Dispatching operations to the appropriate provider

Key interfaces:
- `ServiceProvider` defines the contract for all service providers
- `Registry` manages provider registration and selection

### AWS Provider (internal/provider/aws)

Responsible for:
- Getting temporary session tokens from AWS STS
- Finding MFA devices for the current user
- Managing AWS credential environment

Key interfaces:
- `Provider` implements the `ServiceProvider` interface for AWS

### Generic TOTP Provider (internal/provider/totp)

Responsible for:
- Generating TOTP codes for any service
- Supporting multiple profiles per service
- Handling clipboard integration

### macOS Keychain Integration (internal/keychain)

Responsible for:
- Securely storing and retrieving TOTP secrets
- Saving MFA serial numbers for easy retrieval
- Listing and managing keychain entries
- Ensuring access control for stored secrets

Key interfaces:
- `Provider` defines the contract for keychain operations
- `DefaultProvider` is the concrete implementation

### TOTP Generation (internal/totp)

Responsible for:
- Generating time-based one-time passwords
- Handling TOTP secret validation
- Creating consecutive codes for service setup

Key interfaces:
- `Provider` defines the contract for TOTP operations
- `DefaultProvider` is the concrete implementation

### Setup Wizard (internal/setup)

Responsible for:
- Guiding users through first-time configuration
- Saving TOTP secrets securely in keychain
- Supporting setup for different service types

Key interfaces:
- `WizardRunner` defines the contract for setup operations
- `DefaultWizardRunner` is the concrete implementation

### CLI Application (sesh-cli/cmd/sesh)

Responsible for:
- Processing command-line arguments
- Orchestrating the core workflows
- Managing user interaction and output
- Entry management and clipboard integration

Key structures:
- `App` struct holds all dependencies and state
- Methods like `ListEntries`, `DeleteEntry`, and `CopyToClipboard` implement workflow steps

### Clipboard Integration (internal/clipboard)

Responsible for:
- Cross-platform clipboard handling
- Copying generated codes to system clipboard

## Workflow Sequence

The standard AWS workflow follows this sequence:

1. Parse command-line flags and environment variables
2. Select the appropriate service provider
3. Get the MFA serial from various sources
4. Get TOTP secret from keychain
5. Generate TOTP code
6. Get AWS session token using the TOTP code
7. Output credentials in a format that can be evaluated

The generic TOTP workflow follows this sequence:

1. Parse command-line flags and environment variables
2. Select the TOTP provider
3. Get the service name and optional profile
4. Get TOTP secret from keychain
5. Generate TOTP code
6. Display or copy the code to clipboard

## Dependency Injection

The system uses dependency injection throughout:

```go
// App struct shows dependency injection pattern
type App struct {
    Registry    *provider.Registry
    AWS         aws.Provider
    Keychain    keychain.Provider
    TOTP        totp.Provider
    SetupWizard setup.WizardRunner
    ExecLookPath ExecLookPathFunc
    Exit        ExitFunc
    Stdout      io.Writer
    Stderr      io.Writer
    VersionInfo VersionInfo
}

// NewDefaultApp creates a fully wired instance with registered providers
func NewDefaultApp() *App {
    app := &App{
        Registry:    provider.NewRegistry(),
        AWS:         aws.NewDefaultProvider(),
        Keychain:    keychain.NewDefaultProvider(),
        TOTP:        totp.NewDefaultProvider(),
        SetupWizard: setup.DefaultWizardRunner{},
        // ...
    }
    
    // Register providers
    app.registerProviders()
    
    return app
}
```

## Testing Strategy

The architecture supports comprehensive testing through:

- Interface mocks that can be injected for testing
- Abstracted command execution for testing without external dependencies
- Output capturing via io.Writer interfaces
- Service providers with clear interfaces that can be mocked

## Error Handling

Error handling follows a consistent pattern:

1. Low-level functions return errors with context
2. Each component has its own error types when appropriate
3. Application code translates errors into user-friendly messages
4. Helpful troubleshooting steps are provided for common errors

## Project Structure

```
/sesh
├── docs/                       # Documentation
├── go.mod                      # Go module definition
├── internal/                   # Internal packages
│   ├── aws/                    # AWS SDK integration
│   │   ├── interfaces.go       # AWS provider interface
│   │   └── mocks/              # Mocks for testing
│   ├── clipboard/              # Clipboard integration
│   ├── keychain/               # Keychain integration
│   │   ├── interfaces.go       # Keychain provider interface
│   │   └── mocks/              # Mocks for testing
│   ├── provider/               # Plugin architecture
│   │   ├── interfaces.go       # ServiceProvider interface
│   │   ├── registry.go         # Provider registry
│   │   ├── aws/                # AWS provider implementation
│   │   └── totp/               # TOTP provider implementation
│   ├── totp/                   # TOTP generation
│   │   ├── interfaces.go       # TOTP provider interface
│   │   └── mocks/              # Mocks for testing
│   ├── setup/                  # Setup wizard
│   │   ├── interface.go        # WizardRunner interface
│   │   └── mocks/              # Mocks for testing
│   └── testutil/               # Testing utilities
├── sesh-cli/                   # CLI application
│   └── cmd/
│       └── sesh/              # Main CLI code
└── shell/                     # Shell integration scripts
```

## Extension Points

The architecture supports extension through:

1. **New Service Providers** - Implement the `ServiceProvider` interface and register with the Registry
2. **Enhanced Security** - Keychain entries are restricted to the sesh binary path
3. **Additional Clipboard Formats** - Extend clipboard package for other formats
4. **More Entry Management Features** - Extend app methods to support more operations