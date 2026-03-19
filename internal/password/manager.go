// Package password provides secure password management functionality
// leveraging the existing keychain and security infrastructure.
package password

import (
	"fmt"
	"log"
	"time"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keyformat"
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

var validEntryTypes = map[EntryType]bool{
	EntryTypePassword: true,
	EntryTypeAPIKey:   true,
	EntryTypeTOTP:     true,
	EntryTypeNote:     true,
}

// Entry represents a password manager entry
type Entry struct {
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	ID          string            `json:"id"`
	Service     string            `json:"service"`
	Username    string            `json:"username,omitempty"`
	Type        EntryType         `json:"type"`
	Description string            `json:"description,omitempty"`
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
	serviceKey, err := m.generateServiceKey(service, username, entryType)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}

	// Store the password securely
	err = m.keychain.SetSecret(m.user, serviceKey, passwordCopy)
	if err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	// Store metadata for organization
	description := fmt.Sprintf("%s for %s", entryType, service)
	if username != "" {
		description = fmt.Sprintf("%s (%s) for %s", entryType, username, service)
	}

	err = m.keychain.StoreEntryMetadata(constants.PasswordServicePrefix, serviceKey, m.user, description)
	if err != nil {
		// Non-fatal - password is stored, just metadata failed
		log.Printf("warning: failed to store metadata for %s: %v", serviceKey, err)
	}

	return nil
}

// GetPassword retrieves a password securely
func (m *Manager) GetPassword(service, username string, entryType EntryType) ([]byte, error) {
	serviceKey, err := m.generateServiceKey(service, username, entryType)
	if err != nil {
		return nil, fmt.Errorf("failed to build service key: %w", err)
	}

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
	keychainEntries, err := m.keychain.ListEntries(constants.PasswordServicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list entries: %w", err)
	}

	// Load metadata once for timestamp lookup
	metaEntries, err := m.keychain.LoadEntryMetadata(constants.PasswordServicePrefix)
	if err != nil {
		metaEntries = nil
	}
	metaByKey := make(map[string]keychain.KeychainEntryMeta, len(metaEntries))
	for _, meta := range metaEntries {
		metaByKey[meta.Service+":"+meta.Account] = meta
	}

	entries := make([]Entry, 0, len(keychainEntries))
	for _, kEntry := range keychainEntries {
		entry, err := m.parseEntry(kEntry, metaByKey)
		if err != nil {
			// Skip invalid entries but don't fail completely
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// DeleteEntry removes a password entry and its metadata
func (m *Manager) DeleteEntry(service, username string, entryType EntryType) error {
	serviceKey, err := m.generateServiceKey(service, username, entryType)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}

	err = m.keychain.DeleteEntry(m.user, serviceKey)
	if err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}

	err = m.keychain.RemoveEntryMetadata(constants.PasswordServicePrefix, serviceKey, m.user)
	if err != nil {
		// Non-fatal - entry is deleted, just metadata cleanup failed
		log.Printf("warning: failed to remove metadata for %s: %v", serviceKey, err)
	}

	return nil
}

// generateServiceKey creates a unique service key for keychain storage.
// Format: sesh-password/{type}/{service}[/{username}]
func (m *Manager) generateServiceKey(service, username string, entryType EntryType) (string, error) {
	segments := []string{string(entryType), service}
	if username != "" {
		segments = append(segments, username)
	}
	return keyformat.Build(constants.PasswordServicePrefix, segments...)
}

// parseEntry converts a keychain entry to a password manager entry.
func (m *Manager) parseEntry(kEntry keychain.KeychainEntry, metaByKey map[string]keychain.KeychainEntryMeta) (Entry, error) {
	if kEntry.Account != m.user {
		return Entry{}, fmt.Errorf("entry belongs to another account: %s", kEntry.Account)
	}

	segments, err := keyformat.Parse(kEntry.Service, constants.PasswordServicePrefix)
	if err != nil {
		return Entry{}, err
	}

	if len(segments) < 2 {
		return Entry{}, fmt.Errorf("invalid service key: expected at least 2 segments, got %d", len(segments))
	}

	entryType := EntryType(segments[0])
	if !validEntryTypes[entryType] {
		return Entry{}, fmt.Errorf("unknown entry type: %s", segments[0])
	}

	service := segments[1]
	var username string
	if len(segments) >= 3 {
		username = segments[2]
	}

	key := kEntry.Service + ":" + kEntry.Account
	entry := Entry{
		ID:          key,
		Service:     service,
		Username:    username,
		Type:        entryType,
		Description: kEntry.Description,
	}

	if meta, ok := metaByKey[key]; ok {
		entry.CreatedAt = meta.CreatedAt
		entry.UpdatedAt = meta.UpdatedAt
	}

	return entry, nil
}
