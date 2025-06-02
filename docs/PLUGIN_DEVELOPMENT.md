# Sesh Plugin Development Guide

This guide explains how to create new service providers for sesh. Whether you're adding support for a new cloud provider, a different authentication service, or any credential management system, this guide will walk you through the process.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Creating a Basic Provider](#creating-a-basic-provider)
3. [Advanced Features](#advanced-features)
4. [Testing Your Provider](#testing-your-provider)
5. [Best Practices](#best-practices)
6. [Example: Minimal TOTP Provider](#example-minimal-totp-provider)

## Architecture Overview

Sesh uses a plugin-based architecture where each service (AWS, TOTP, etc.) is implemented as a provider. All providers must implement the `ServiceProvider` interface and register with the central registry at app init.

### Key Components

1. **ServiceProvider Interface**: Core contract all providers must implement
2. **Registry**: Manages provider registration and lookup
3. **Setup Handlers**: Handle initial configuration for each provider
4. **Keychain Integration**: Secure storage for secrets
5. **Shell Customizers**: Optional subshell support

## Creating a Basic Provider

### Step 1: Create Provider Structure

Create a new package under `internal/provider/yourservice/`:

```go
package yourservice

import (
    "errors"
    "fmt"
    "strings"
    "time"
    
    "github.com/bashhack/sesh/internal/constants"
    "github.com/bashhack/sesh/internal/keychain"
    "github.com/bashhack/sesh/internal/provider"
    "github.com/bashhack/sesh/internal/secure"
)

type Provider struct {
    keychain keychain.Provider
    
    // Provider-specific fields
    serviceName string
    profile     string
}

func NewProvider(kc keychain.Service) *Provider {
    return &Provider{
        keychain: kc,
    }
}
```

### Step 2: Implement Required Methods

#### Basic Identification

```go
func (p *Provider) Name() string {
    return "yourservice"
}

func (p *Provider) Description() string {
    return "Your Service - Brief description of what this provider does"
}
```

#### Flag Setup

```go
func (p *Provider) SetupFlags(fs provider.FlagSet) error {
    fs.StringVar(&p.serviceName, "service-name", "", "Name of the service")
    fs.StringVar(&p.profile, "profile", "", "Profile name (optional)")
    return nil
}

func (p *Provider) GetFlagInfo() []provider.FlagInfo {
    return []provider.FlagInfo{
        {
            Name:        "service-name",
            Type:        "string",
            Description: "Name of the service",
            Required:    true,
        },
        {
            Name:        "profile",
            Type:        "string",
            Description: "Profile name for multiple accounts",
            Required:    false,
        },
    }
}
```

#### Validation

```go
func (p *Provider) ValidateRequest() error {
    if p.serviceName == "" {
        return fmt.Errorf("service name is required")
    }
    
    // Check if credentials exist in keychain
    serviceKey := p.buildServiceKey()
    exists, err := p.keychain.Exists(serviceKey)
    if err != nil {
        return fmt.Errorf("failed to check keychain: %w", err)
    }
    if !exists {
        return fmt.Errorf("no stored credentials found. Run: sesh --setup yourservice")
    }
    
    return nil
}
```

#### Credential Generation

```go
func (p *Provider) GetCredentials() (provider.Credentials, error) {
    // Retrieve secret from keychain
    serviceKey := p.buildServiceKey()
    secret, err := p.keychain.Get(serviceKey)
    if err != nil {
        return provider.Credentials{}, err
    }
    defer secure.SecureZeroBytes(secret)
    
    // Generate credentials (example: environment variables)
    creds := provider.Credentials{
        Provider: p.Name(),
        Variables: map[string]string{
            "YOUR_SERVICE_TOKEN": string(secret),
        },
        DisplayInfo: fmt.Sprintf("✅ %s credentials loaded", p.serviceName),
    }
    
    return creds, nil
}

func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
    // For clipboard mode, return just the value to copy
    serviceKey := p.buildServiceKey()
    secret, err := p.keychain.Get(serviceKey)
    if err != nil {
        return provider.Credentials{}, err
    }
    defer secure.SecureZeroBytes(secret)
    
    return provider.Credentials{
        Provider:  p.Name(),
        CopyValue: string(secret),
    }, nil
}
```

#### Entry Management

```go
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
    prefix := constants.YourServicePrefix
    entries, err := p.keychain.ListByPrefix(prefix)
    if err != nil {
        return nil, err
    }
    
    var result []provider.ProviderEntry
    for _, e := range entries {
        serviceName, profile := p.parseServiceKey(e.ServiceKey)
        result = append(result, provider.ProviderEntry{
            ID:          e.ServiceKey,
            ServiceName: serviceName,
            Profile:     profile,
            Provider:    p.Name(),
        })
    }
    
    return result, nil
}

func (p *Provider) DeleteEntry(id string) error {
    // Extract account from ID (remove prefix)
    account := strings.TrimPrefix(id, constants.YourServicePrefix)
    
    // Delete from keychain
    if err := p.keychain.DeleteEntry(account, constants.YourServicePrefix); err != nil {
        return fmt.Errorf("failed to delete entry: %w", err)
    }
    
    // Remove metadata
    // Parse service name from account
    serviceName := account
    if idx := strings.Index(account, "-"); idx > 0 {
        serviceName = account[:idx]
    }
    
    if err := p.keychain.RemoveEntryMetadata(constants.YourServicePrefix, serviceName, account); err != nil {
        return fmt.Errorf("failed to remove metadata: %w", err)
    }
    
    return nil
}
```

### Step 3: Create Setup Handler

Create `internal/setup/yourservice_setup.go`:

```go
type YourServiceSetupHandler struct {
    keychain keychain.Provider
}

func NewYourServiceSetupHandler(kc keychain.Provider) *YourServiceSetupHandler {
    return &YourServiceSetupHandler{keychain: kc}
}

func (h *YourServiceSetupHandler) ServiceName() string {
    return "yourservice"
}

func (h *YourServiceSetupHandler) Setup() error {
    fmt.Println("🔧 Setting up Your Service")
    
    // Get service name
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter service name: ")
    serviceName, _ := reader.ReadString('\n')
    serviceName = strings.TrimSpace(serviceName)
    
    // Get credentials
    fmt.Print("Enter secret/token: ")
    secretBytes, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
    fmt.Println()
    
    // Store in keychain
    account := serviceName // or add profile logic if needed
    if err := h.keychain.SetSecret(account, constants.YourServicePrefix, secretBytes); err != nil {
        return fmt.Errorf("failed to store credentials: %w", err)
    }
    
    // Store metadata
    description := fmt.Sprintf("Your Service credentials for %s", serviceName)
    if err := h.keychain.StoreEntryMetadata(constants.YourServicePrefix, serviceName, account, description); err != nil {
        return fmt.Errorf("failed to store metadata: %w", err)
    }
    
    fmt.Printf("✅ Credentials stored for %s\n", serviceName)
    return nil
}
```

### Step 4: Register Provider

In `sesh/cmd/sesh/app.go`, add to `registerProviders()`:

```go
func (a *App) registerProviders() {
    // ... existing providers ...
    
    // Register your provider
    yourProvider := yourservice.NewProvider(a.Keychain)
    a.Registry.RegisterProvider(yourProvider)
    
    // Register setup handler
    a.SetupService.RegisterHandler(
        setup.NewYourServiceSetupHandler(a.Keychain),
    )
}
```

## Advanced Features

### Additional Capabilities

Providers can support additional features by implementing optional methods:

```go
// Check if this provider supports subshell mode
func (p *Provider) SupportsSubshell() bool {
    return true // or false if not supported
}

// Check if this provider supports clipboard mode  
func (p *Provider) SupportsClipboard() bool {
    return true // or false if not supported
}
```

### Subshell Support

To add subshell support, implement the `SubshellProvider` interface:

```go
func (p *Provider) NewSubshellConfig(creds provider.Credentials) interface{} {
    return &subshell.Config{
        ServiceName: p.Name(),
        EnvVars:     creds.Variables,
        Customizer:  &YourServiceShellCustomizer{},
    }
}

type YourServiceShellCustomizer struct{}

func (c *YourServiceShellCustomizer) GetZshInitScript() string {
    return `
        # Your service specific zsh initialization
        your_service_status() {
            echo "Your service is active"
        }
    `
}

func (c *YourServiceShellCustomizer) GetBashInitScript() string {
    return `
        # Your service specific bash initialization
        your_service_status() {
            echo "Your service is active"
        }
    `
}

func (c *YourServiceShellCustomizer) GetPromptPrefix() string {
    return "yourservice"
}

func (c *YourServiceShellCustomizer) GetWelcomeMessage() string {
    return "🔐 Your Service session activated. Type 'your_service_status' for info."
}
```

### TOTP Integration

If your provider needs TOTP codes:

```go
type Provider struct {
    keychain keychain.Provider
    totp     totp.Provider  // Add TOTP service
}

func (p *Provider) GetCredentials() (provider.Credentials, error) {
    // Get TOTP secret
    account := p.serviceName
    secret, err := p.keychain.GetSecret(account, constants.YourServicePrefix)
    if err != nil {
        return provider.Credentials{}, err
    }
    defer secure.SecureZeroBytes(secret)
    
    // Generate TOTP code
    code, _, err := p.totp.GenerateCodeBytes(secret, time.Now())
    if err != nil {
        return provider.Credentials{}, err
    }
    
    // Use code in credentials...
}
```

## Testing Your Provider

### Unit Tests

Create `provider_test.go`:

```go
func TestProvider_GetCredentials(t *testing.T) {
    // Create mock keychain
    mockKC := &MockKeychain{
        data: map[string][]byte{
            "sesh-yourservice-test": []byte("secret123"),
        },
    }
    
    // Create provider
    p := NewProvider(mockKC)
    p.serviceName = "test"
    
    // Test credential generation
    creds, err := p.GetCredentials()
    assert.NoError(t, err)
    assert.Equal(t, "yourservice", creds.Provider)
    assert.NotEmpty(t, creds.Variables["YOUR_SERVICE_TOKEN"])
}
```

### Integration Tests

Test with actual keychain:

```go
func TestProvider_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    kc := keychain.NewService()
    p := NewProvider(kc)
    
    // Test full workflow
    // ...
}
```

## Best Practices

### Security

1. **Always zero sensitive data**: Use `secure.SecureZeroBytes()`
2. **Work with byte slices**: Don't convert secrets to strings unnecessarily
3. **Validate early**: Check credentials exist before expensive operations
4. **Clear clipboard data**: If implementing clipboard support

### User Experience

1. **Clear error messages**: Include setup instructions in errors
2. **Interactive setup**: Guide users through configuration
3. **Profile support**: Allow multiple accounts/configurations
4. **Consistent naming**: Follow existing patterns for flags and commands

### Code Organization

1. **Single responsibility**: Keep provider focused on one service
2. **Dependency injection**: Accept interfaces, not concrete types
3. **Error wrapping**: Use `fmt.Errorf` with `%w` for error context
4. **Constants**: Define prefixes and keys in constants package

## Example: Minimal TOTP Provider

Here's a complete minimal example for a generic TOTP service:

```go
package simple

import (
    "fmt"
    "strings"
    "time"
    
    "github.com/bashhack/sesh/internal/provider"
    "github.com/bashhack/sesh/internal/keychain"
    "github.com/bashhack/sesh/internal/totp"
    "github.com/bashhack/sesh/internal/secure"
)

type Provider struct {
    keychain    keychain.Provider
    totp        totp.Provider
    serviceName string
}

func NewProvider(kc keychain.Provider, totp totp.Provider) *Provider {
    return &Provider{
        keychain: kc,
        totp:     totp,
    }
}

func (p *Provider) Name() string { return "simple" }
func (p *Provider) Description() string { return "Simple TOTP provider" }

func (p *Provider) SetupFlags(fs provider.FlagSet) error {
    fs.StringVar(&p.serviceName, "service", "", "Service name")
    return nil
}

func (p *Provider) GetFlagInfo() []provider.FlagInfo {
    return []provider.FlagInfo{
        {Name: "service", Type: "string", Description: "Service name", Required: true},
    }
}

func (p *Provider) ValidateRequest() error {
    if p.serviceName == "" {
        return fmt.Errorf("service name required")
    }
    return nil
}

func (p *Provider) GetCredentials() (provider.Credentials, error) {
    return provider.Credentials{}, fmt.Errorf("not implemented")
}

func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
    account := p.serviceName
    secret, err := p.keychain.GetSecret(account, "sesh-simple-")
    if err != nil {
        return provider.Credentials{}, err
    }
    defer secure.SecureZeroBytes(secret)
    
    // Generate current and next TOTP codes
    currentCode, nextCode, err := p.totp.GenerateConsecutiveCodesBytes(secret)
    if err != nil {
        return provider.Credentials{}, err
    }
    
    // Calculate time remaining
    now := time.Now()
    secondsLeft := 30 - (now.Unix() % 30)
    
    return provider.CreateClipboardCredentials(
        p.Name(),
        string(currentCode),
        string(nextCode),
        secondsLeft,
        "TOTP code",
        p.serviceName,
    )
}

func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
    // Load metadata for all entries
    metadata, err := p.keychain.LoadEntryMetadata("sesh-simple-")
    if err != nil {
        return nil, err
    }
    
    var result []provider.ProviderEntry
    for _, meta := range metadata {
        result = append(result, provider.ProviderEntry{
            ID:          fmt.Sprintf("sesh-simple-%s", meta.Account),
            Name:        meta.Service,
            Description: meta.Description,
        })
    }
    
    return result, nil
}

func (p *Provider) DeleteEntry(id string) error {
    account := strings.TrimPrefix(id, "sesh-simple-")
    
    // Delete from keychain
    if err := p.keychain.DeleteEntry(account, "sesh-simple-"); err != nil {
        return fmt.Errorf("failed to delete entry: %w", err)
    }
    
    // Remove metadata
    serviceName := p.serviceName
    if err := p.keychain.RemoveEntryMetadata("sesh-simple-", serviceName, account); err != nil {
        return fmt.Errorf("failed to remove metadata: %w", err)
    }
    
    return nil
}

func (p *Provider) SupportsSubshell() bool {
    return false // Simple TOTP provider doesn't need subshell
}

func (p *Provider) SupportsClipboard() bool {
    return true // TOTP codes are perfect for clipboard
}

func (p *Provider) GetSetupHandler() interface{} {
    return &SimpleSetupHandler{keychain: p.keychain}
}
```

## Next Steps

1. Review existing providers for patterns and conventions
2. Start with a minimal implementation
3. Add tests as you go
4. Submit a PR with your new provider

For questions or help, please open an issue on GitHub.
