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

Sesh uses a plugin-based architecture where each service (AWS, TOTP, etc.) is implemented as a provider. All providers implement the `ServiceProvider` interface and are registered with the central registry.

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
    "github.com/bashhack/sesh/internal/provider"
    "github.com/bashhack/sesh/internal/keychain"
)

type Provider struct {
    keychain keychain.Service
    
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
    return p.keychain.Delete(id)
}
```

### Step 3: Create Setup Handler

Create `internal/setup/yourservice_setup.go`:

```go
type YourServiceSetupHandler struct {
    keychain keychain.Service
}

func NewYourServiceSetupHandler(kc keychain.Service) *YourServiceSetupHandler {
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
    serviceKey := fmt.Sprintf("%s%s", constants.YourServicePrefix, serviceName)
    if err := h.keychain.Store(serviceKey, secretBytes); err != nil {
        return fmt.Errorf("failed to store credentials: %w", err)
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
    keychain keychain.Service
    totp     totp.Service  // Add TOTP service
}

func (p *Provider) GetCredentials() (provider.Credentials, error) {
    // Get TOTP secret
    secret, err := p.keychain.Get(serviceKey)
    if err != nil {
        return provider.Credentials{}, err
    }
    defer secure.SecureZeroBytes(secret)
    
    // Generate TOTP code
    code, err := p.totp.GenerateTOTPCode(string(secret))
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
    "github.com/bashhack/sesh/internal/provider"
    "github.com/bashhack/sesh/internal/keychain"
    "github.com/bashhack/sesh/internal/totp"
    "github.com/bashhack/sesh/internal/secure"
)

type Provider struct {
    keychain    keychain.Service
    totp        totp.Service
    serviceName string
}

func NewProvider(kc keychain.Service, totp totp.Service) *Provider {
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
    serviceKey := fmt.Sprintf("sesh-simple-%s", p.serviceName)
    secret, err := p.keychain.Get(serviceKey)
    if err != nil {
        return provider.Credentials{}, err
    }
    defer secure.SecureZeroBytes(secret)
    
    code, err := p.totp.GenerateTOTPCode(string(secret))
    if err != nil {
        return provider.Credentials{}, err
    }
    
    return provider.Credentials{
        Provider:  p.Name(),
        CopyValue: code,
    }, nil
}

func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
    // Implementation...
}

func (p *Provider) DeleteEntry(id string) error {
    return p.keychain.Delete(id)
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