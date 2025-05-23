// Package password provides secure password management functionality
// leveraging the existing keychain and security infrastructure.
package password

import (
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
)

// EntryType represents the type of password entry
type EntryType string

const (
	EntryTypePassword EntryType = "password"
	EntryTypeAPIKey   EntryType = "api_key"
	EntryTypeTOTP     EntryType = "totp"
	EntryTypeNote     EntryType = "secure_note"
)

// Entry represents a password manager entry
type Entry struct {
	ID          string            `json:"id"`
	Service     string            `json:"service"`
	Username    string            `json:"username,omitempty"`
	Type        EntryType         `json:"type"`
	Description string            `json:"description,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Manager provides secure password management operations
type Manager struct {
	keychain keychain.Provider
	user     string
}

// NewManager creates a new password manager instance
func NewManager(keychainProvider keychain.Provider, user string) *Manager {
	return &Manager{
		keychain: keychainProvider,
		user:     user,
	}
}

// StorePassword securely stores a password entry
func (m *Manager) StorePassword(service, username string, password []byte, entryType EntryType) error {
	// Create defensive copy
	passwordCopy := make([]byte, len(password))
	copy(passwordCopy, password)
	defer secure.SecureZeroBytes(passwordCopy)

	// Generate service key for keychain storage
	serviceKey := m.generateServiceKey(service, username, entryType)

	// Store the password securely
	err := m.keychain.SetSecret(m.user, serviceKey, passwordCopy)
	if err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	// Store metadata for organization
	description := fmt.Sprintf("%s for %s", entryType, service)
	if username != "" {
		description = fmt.Sprintf("%s (%s) for %s", entryType, username, service)
	}

	err = m.keychain.StoreEntryMetadata("sesh-password", serviceKey, m.user, description)
	if err != nil {
		// Non-fatal - password is stored, just metadata failed
		fmt.Printf("Warning: Failed to store metadata for %s\n", serviceKey)
	}

	return nil
}

// GetPassword retrieves a password securely
func (m *Manager) GetPassword(service, username string, entryType EntryType) ([]byte, error) {
	serviceKey := m.generateServiceKey(service, username, entryType)

	passwordBytes, err := m.keychain.GetSecret(m.user, serviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve password: %w", err)
	}

	// Return the bytes directly - caller is responsible for zeroing
	return passwordBytes, nil
}

// StorePasswordString is a convenience method for string passwords
func (m *Manager) StorePasswordString(service, username, password string, entryType EntryType) error {
	passwordBytes := []byte(password)
	defer secure.SecureZeroBytes(passwordBytes)
	
	return m.StorePassword(service, username, passwordBytes, entryType)
}

// GetPasswordString retrieves a password as a string (less secure)
func (m *Manager) GetPasswordString(service, username string, entryType EntryType) (string, error) {
	passwordBytes, err := m.GetPassword(service, username, entryType)
	if err != nil {
		return "", err
	}
	defer secure.SecureZeroBytes(passwordBytes)

	return string(passwordBytes), nil
}

// StoreTOTPSecret stores a TOTP secret with validation
func (m *Manager) StoreTOTPSecret(service, username, secret string) error {
	// Validate and normalize the TOTP secret
	normalizedSecret, err := totp.ValidateAndNormalizeSecret(secret)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}

	return m.StorePasswordString(service, username, normalizedSecret, EntryTypeTOTP)
}

// GenerateTOTPCode generates a TOTP code for a stored secret
func (m *Manager) GenerateTOTPCode(service, username string) (string, error) {
	secretBytes, err := m.GetPassword(service, username, EntryTypeTOTP)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}
	defer secure.SecureZeroBytes(secretBytes)

	// Use the secure TOTP generation
	code, err := totp.GenerateBytes(secretBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	return code, nil
}

// ListEntries returns all password entries
func (m *Manager) ListEntries() ([]Entry, error) {
	keychainEntries, err := m.keychain.ListEntries("sesh-password")
	if err != nil {
		return nil, fmt.Errorf("failed to list entries: %w", err)
	}

	entries := make([]Entry, 0, len(keychainEntries))
	for _, kEntry := range keychainEntries {
		entry, err := m.parseEntry(kEntry)
		if err != nil {
			// Skip invalid entries but don't fail completely
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// DeleteEntry removes a password entry
func (m *Manager) DeleteEntry(service, username string, entryType EntryType) error {
	serviceKey := m.generateServiceKey(service, username, entryType)
	
	err := m.keychain.DeleteEntry(m.user, serviceKey)
	if err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}

	return nil
}

// generateServiceKey creates a unique service key for keychain storage
func (m *Manager) generateServiceKey(service, username string, entryType EntryType) string {
	if username == "" {
		return fmt.Sprintf("sesh-password-%s-%s", entryType, service)
	}
	return fmt.Sprintf("sesh-password-%s-%s-%s", entryType, service, username)
}

// parseEntry converts a keychain entry to a password manager entry
func (m *Manager) parseEntry(kEntry keychain.KeychainEntry) (Entry, error) {
	// This is a simplified parser - in a real implementation you'd store
	// structured metadata and parse it properly
	entry := Entry{
		ID:          kEntry.Service + ":" + kEntry.Account,
		Service:     kEntry.Service,
		Description: kEntry.Description,
		CreatedAt:   time.Now(), // Would be stored in metadata
		UpdatedAt:   time.Now(), // Would be stored in metadata
		Type:        EntryTypePassword, // Would be parsed from service key
	}

	return entry, nil
}