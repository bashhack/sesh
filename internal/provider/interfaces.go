// Package provider defines the interface and registry for credential providers.
package provider

import (
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/env"
)

// FlagSet defines the interface for registering flags
type FlagSet interface {
	StringVar(p *string, name string, value string, usage string)
	BoolVar(p *bool, name string, value bool, usage string)
	IntVar(p *int, name string, value int, usage string)
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
	GetSetupHandler() any

	// GetCredentials retrieves credentials using TOTP
	GetCredentials() (Credentials, error)

	// GetClipboardValue retrieves a value suitable for copying to clipboard.
	// This allows providers to optimize for clipboard mode (e.g., AWS skips STS
	// authentication and only generates the TOTP code).
	//
	// On success, the returned Credentials must have CopyValue set to a non-empty
	// string and ClipboardDescription set to a short label (e.g., "TOTP code").
	//
	// TOTP-based providers should use CreateClipboardCredentials, which handles
	// CopyValue, ClipboardDescription, DisplayInfo, and Expiry automatically.
	// Non-TOTP providers (e.g., password managers) should populate CopyValue and
	// ClipboardDescription directly.
	GetClipboardValue() (Credentials, error)

	// ListEntries returns the list of entries for this provider
	ListEntries() ([]ProviderEntry, error)

	// DeleteEntry deletes an entry from the keychain
	DeleteEntry(id string) error

	// ValidateRequest performs early validation of the request
	// This should check:
	// - Invalid flag combinations for this provider
	// - Whether required keychain entries exist
	// - Any other provider-specific validation
	// This allows fail-fast behavior before expensive operations
	ValidateRequest() error

	// GetFlagInfo returns information about provider-specific flags for help text
	GetFlagInfo() []FlagInfo
}

// FlagInfo describes a provider-specific flag
type FlagInfo struct {
	Name        string
	Type        string // "string", "bool", etc.
	Description string
	Required    bool
}

// SubshellDecider is an optional interface that providers can implement
// to indicate whether they prefer subshell mode over printing credentials.
type SubshellDecider interface {
	ShouldUseSubshell() bool
}

// SubshellProvider is an optional interface that providers can implement
// if they support launching a customized subshell environment
type SubshellProvider interface {
	// NewSubshellConfig creates a configuration for the subshell package
	// based on the provided credentials
	NewSubshellConfig(creds *Credentials) any
}

// ProviderEntry represents an entry for a specific provider
type ProviderEntry struct {
	Name        string // Entry name (e.g. AWS Profile or GCP Project)
	Description string // Human-readable description
	ID          string // Internal identifier
}

// Clock provides testable time. Embed in provider structs and override Now in tests.
type Clock struct {
	Now func() time.Time
}

// TimeNow returns the current time, using Now if set, otherwise time.Now.
func (c *Clock) TimeNow() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// SecondsLeftInWindow returns seconds remaining in the current 30-second TOTP window.
func (c *Clock) SecondsLeftInWindow() int64 {
	return 30 - (c.TimeNow().Unix() % 30)
}

// KeyUser provides lazy-initialized OS user lookup. Embed in provider structs
// alongside a keyUser string field set during SetupFlags.
type KeyUser struct {
	User string
}

// EnsureUser sets User to the current OS user if it is empty.
func (k *KeyUser) EnsureUser() error {
	if k.User != "" {
		return nil
	}
	var err error
	k.User, err = env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	return nil
}

// ParseEntryID splits an entry ID of the form "service:account" into its parts.
func ParseEntryID(id string) (service, account string, err error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid entry ID format: expected 'service:account', got %q", id)
	}
	return parts[0], parts[1], nil
}

// Credentials represents generic credentials returned by a provider
type Credentials struct {
	Provider             string            // Provider name
	Expiry               time.Time         // When these credentials expire
	Variables            map[string]string // Environment variables to set
	DisplayInfo          string            // Human-readable display information
	CopyValue            string            // Value to copy to clipboard; must be non-empty when returned by GetClipboardValue
	ClipboardDescription string            // Short label for CopyValue (e.g. "TOTP code", "password"); used in CLI output
	MFAAuthenticated     bool              // Whether these credentials were authenticated with MFA
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

// CreateClipboardCredentials creates standardized clipboard-mode credentials for
// TOTP-based providers. It sets CopyValue to the current code, computes Expiry
// from the 30-second TOTP window, and formats DisplayInfo with both codes and
// time remaining. Non-TOTP providers should build Credentials directly.
func CreateClipboardCredentials(providerName, currentCode, nextCode string, secondsLeft int64, actionType, serviceDesc string) Credentials {
	// Calculate when this code expires (30 seconds from now, rounded to nearest 30s boundary)
	now := time.Now().Unix()
	validUntil := time.Unix(((now/30)+1)*30, 0)

	return Credentials{
		Provider:             providerName,
		Expiry:               validUntil,
		Variables:            map[string]string{}, // Empty map for clipboard mode
		DisplayInfo:          FormatClipboardDisplayInfo(currentCode, nextCode, secondsLeft, actionType, serviceDesc),
		CopyValue:            currentCode,
		ClipboardDescription: actionType,
		MFAAuthenticated:     false, // Clipboard mode doesn't authenticate with backend services
	}
}
