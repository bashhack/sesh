package provider

import (
	"flag"
	"time"
)

// ServiceProvider defines the interface that all service providers must implement
type ServiceProvider interface {
	// Name returns the name of the provider (aws, github, gcp, etc.)
	Name() string
	
	// Description returns a human-readable description of the provider
	Description() string
	
	// SetupFlags adds provider-specific flags to the given FlagSet
	SetupFlags(fs *flag.FlagSet)
	
	// Setup runs the setup wizard for this provider
	Setup() error
	
	// GetCredentials retrieves credentials using TOTP
	GetCredentials() (Credentials, error)
	
	// ListEntries returns the list of entries for this provider
	ListEntries() ([]ProviderEntry, error)
	
	// DeleteEntry deletes an entry from the keychain
	DeleteEntry(id string) error
}

// ProviderEntry represents an entry for a specific provider
type ProviderEntry struct {
	Name        string // Entry name (e.g. AWS Profile or GCP Project)
	Description string // Human-readable description
	ID          string // Internal identifier
}

// Credentials represents generic credentials returned by a provider
type Credentials struct {
	Provider    string            // Provider name
	Expiry      time.Time         // When these credentials expire
	Variables   map[string]string // Environment variables to set
	DisplayInfo string            // Human-readable display information
	CopyValue   string            // Value to copy to clipboard if requested
}