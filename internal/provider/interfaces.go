package provider

import (
	"fmt"
	"time"
)

// FlagSet defines the interface for registering flags
type FlagSet interface {
	StringVar(p *string, name string, value string, usage string)
	BoolVar(p *bool, name string, value bool, usage string)
}

// ServiceProvider defines the interface that all service providers must implement
type ServiceProvider interface {
	// Name returns the name of the provider (aws, github, gcp, etc.)
	Name() string

	// Description returns a human-readable description of the provider
	Description() string

	// SetupFlags adds provider-specific flags to the given FlagSet
	// The provided flagset will be an interface that won't have nil checks
	SetupFlags(fs FlagSet) error

	// GetSetupHandler returns a setup handler for this provider
	GetSetupHandler() interface{}

	// GetCredentials retrieves credentials using TOTP
	GetCredentials() (Credentials, error)

	// GetClipboardValue retrieves a value suitable for copying to clipboard
	// This allows providers to optimize for clipboard mode (e.g., AWS only generating TOTP codes)
	GetClipboardValue() (Credentials, error)

	// ListEntries returns the list of entries for this provider
	ListEntries() ([]ProviderEntry, error)

	// DeleteEntry deletes an entry from the keychain
	DeleteEntry(id string) error
}

// SubshellProvider is an optional interface that providers can implement
// if they support launching a customized subshell environment
type SubshellProvider interface {
	// NewSubshellConfig creates a configuration for the subshell package
	// based on the provided credentials
	NewSubshellConfig(creds Credentials) interface{}
}

// ProviderEntry represents an entry for a specific provider
type ProviderEntry struct {
	Name        string // Entry name (e.g. AWS Profile or GCP Project)
	Description string // Human-readable description
	ID          string // Internal identifier
}

// Credentials represents generic credentials returned by a provider
type Credentials struct {
	Provider         string            // Provider name
	Expiry           time.Time         // When these credentials expire
	Variables        map[string]string // Environment variables to set
	DisplayInfo      string            // Human-readable display information
	CopyValue        string            // Value to copy to clipboard if requested
	MFAAuthenticated bool              // Whether these credentials were authenticated with MFA
}

// FormatClipboardDisplayInfo creates the standard clipboard-mode display format
// Example: "Current: 123456  |  Next: 789012  |  Time left: 15s\n🔑 AWS MFA code for profile work"
func FormatClipboardDisplayInfo(currentCode, nextCode string, secondsLeft int64, actionType, serviceDesc string) string {
	return fmt.Sprintf("Current: %s  |  Next: %s  |  Time left: %ds\n🔑 %s for %s",
		currentCode, nextCode, secondsLeft, actionType, serviceDesc)
}

// FormatRegularDisplayInfo creates the standard regular-mode display format  
// Example: "🔑 AWS credentials for profile work"
func FormatRegularDisplayInfo(actionType, serviceDesc string) string {
	return fmt.Sprintf("🔑 %s for %s", actionType, serviceDesc)
}

// CreateClipboardCredentials creates standardized clipboard-mode credentials
func CreateClipboardCredentials(providerName, currentCode, nextCode string, secondsLeft int64, actionType, serviceDesc string) Credentials {
	// Calculate when this code expires (30 seconds from now, rounded to nearest 30s boundary)
	now := time.Now().Unix()
	validUntil := time.Unix(((now/30)+1)*30, 0)

	return Credentials{
		Provider:         providerName,
		Expiry:           validUntil,
		Variables:        map[string]string{}, // Empty map for clipboard mode
		DisplayInfo:      FormatClipboardDisplayInfo(currentCode, nextCode, secondsLeft, actionType, serviceDesc),
		CopyValue:        currentCode,
		MFAAuthenticated: false, // Clipboard mode doesn't authenticate with backend services
	}
}
