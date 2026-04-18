// Package password provides secure password management functionality
// leveraging the existing keychain and security infrastructure.
package password

import (
	"fmt"
	"log"
	"sort"
	"strings"
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
	// EntryTypePassword represents a stored password entry.
	EntryTypePassword EntryType = "password"
	// EntryTypeAPIKey represents an API key entry.
	EntryTypeAPIKey EntryType = "api_key"
	// EntryTypeTOTP represents a TOTP secret entry.
	EntryTypeTOTP EntryType = "totp"
	// EntryTypeNote represents a secure note entry.
	EntryTypeNote EntryType = "secure_note"
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

// StoreOption configures optional behavior of StorePassword / StorePasswordString.
type StoreOption func(*storeOptions)

type storeOptions struct {
	createdAt time.Time
	updatedAt time.Time
}

// WithTimestamps preserves the given create/update timestamps on backends
// that implement keychain.TimestampedStore (the SQLite store does; the
// macOS keychain backend does not — there the option is silently ignored
// and the current time is used). A zero-valued time.Time on either
// argument is treated as "unset" and falls back to the current time for
// that field.
func WithTimestamps(createdAt, updatedAt time.Time) StoreOption {
	return func(o *storeOptions) {
		o.createdAt = createdAt
		o.updatedAt = updatedAt
	}
}

// StorePassword securely stores a password entry.
func (m *Manager) StorePassword(service, username string, password []byte, entryType EntryType, opts ...StoreOption) error {
	var so storeOptions
	for _, opt := range opts {
		opt(&so)
	}

	// Create defensive copy
	passwordCopy := make([]byte, len(password))
	copy(passwordCopy, password)
	defer secure.SecureZeroBytes(passwordCopy)

	// Generate service key for keychain storage
	serviceKey, err := m.generateServiceKey(service, username, entryType)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}

	preserveTimestamps := !so.createdAt.IsZero() || !so.updatedAt.IsZero()
	ts, timestampAware := m.keychain.(keychain.TimestampedStore)

	// Resolve zero fields at this boundary so the WithTimestamps contract
	// ("zero = use now") is honored by Manager itself, independent of any
	// normalization a specific TimestampedStore implementation does.
	createdAt, updatedAt := so.createdAt, so.updatedAt
	if preserveTimestamps {
		now := time.Now().UTC()
		if createdAt.IsZero() {
			createdAt = now
		}
		if updatedAt.IsZero() {
			updatedAt = now
		}
	}

	// Store the password securely.
	if timestampAware && preserveTimestamps {
		err = ts.SetSecretAt(m.user, serviceKey, passwordCopy, createdAt, updatedAt)
	} else {
		err = m.keychain.SetSecret(m.user, serviceKey, passwordCopy)
	}
	if err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	// Store metadata for organization. Use the timestamp-aware path when
	// available so the description write doesn't clobber the preserved
	// updated_at.
	description := fmt.Sprintf("%s for %s", entryType, service)
	if username != "" {
		description = fmt.Sprintf("%s (%s) for %s", entryType, username, service)
	}

	if timestampAware && preserveTimestamps {
		err = ts.SetDescriptionAt(serviceKey, m.user, description, updatedAt)
	} else {
		err = m.keychain.SetDescription(serviceKey, m.user, description)
	}
	if err != nil {
		// Non-fatal - password is stored, just description failed
		log.Printf("warning: failed to store description for %s: %v", serviceKey, err)
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
func (m *Manager) StorePasswordString(service, username, password string, entryType EntryType, opts ...StoreOption) error {
	passwordBytes := []byte(password)
	defer secure.SecureZeroBytes(passwordBytes)

	return m.StorePassword(service, username, passwordBytes, entryType, opts...)
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

// StoreTOTPSecret stores a TOTP secret with validation.
func (m *Manager) StoreTOTPSecret(service, username, secret string) error {
	return m.StoreTOTPSecretWithParams(service, username, secret, totp.Params{})
}

// StoreTOTPSecretWithParams stores a TOTP secret with validation and optional
// non-standard parameters (algorithm, digits, period, issuer).
func (m *Manager) StoreTOTPSecretWithParams(service, username, secret string, params totp.Params) error {
	normalizedSecret, err := totp.ValidateAndNormalizeSecret(secret)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}

	if err := m.StorePasswordString(service, username, normalizedSecret, EntryTypeTOTP); err != nil {
		return err
	}

	// For non-default params, the description carries algorithm/digits/
	// period needed to regenerate correct codes later — it is load-bearing
	// metadata, not a cosmetic label. Failures must surface; otherwise the
	// entry persists with defaults and silently produces wrong codes.
	desc := params.MarshalDescription()
	if desc != "" {
		serviceKey, err := m.generateServiceKey(service, username, EntryTypeTOTP)
		if err != nil {
			return fmt.Errorf("stored TOTP secret but failed to build service key for params: %w", err)
		}
		if descErr := m.keychain.SetDescription(serviceKey, m.user, desc); descErr != nil {
			return fmt.Errorf("stored TOTP secret but failed to persist params (subsequent codes would fall back to defaults): %w", descErr)
		}
	}

	return nil
}

// GetTOTPParams retrieves stored TOTP parameters for an entry.
func (m *Manager) GetTOTPParams(service, username string) totp.Params {
	serviceKey, err := m.generateServiceKey(service, username, EntryTypeTOTP)
	if err != nil {
		return totp.Params{}
	}

	entries, err := m.keychain.ListEntries(serviceKey)
	if err != nil || len(entries) == 0 {
		return totp.Params{}
	}
	// ListEntries is a prefix query in the SQLite backend — verify the
	// first entry matches the exact (service, account) we read the secret
	// under, so neither a prefix sibling nor a cross-user entry can spoof
	// the params.
	if entries[0].Service != serviceKey || entries[0].Account != m.user {
		return totp.Params{}
	}

	return totp.ParseParams(entries[0].Description)
}

// GenerateTOTPCode generates a TOTP code for a stored secret,
// using any stored non-standard parameters (algorithm, digits, period).
func (m *Manager) GenerateTOTPCode(service, username string) (string, error) {
	secretBytes, err := m.GetPassword(service, username, EntryTypeTOTP)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}
	defer secure.SecureZeroBytes(secretBytes)

	params := m.GetTOTPParams(service, username)

	current, _, err := totp.GenerateConsecutiveCodesBytesWithParams(secretBytes, params)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	return current, nil
}

// ListEntries returns all password entries
func (m *Manager) ListEntries() ([]Entry, error) {
	keychainEntries, err := m.keychain.ListEntries(constants.PasswordServicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list entries: %w", err)
	}

	entries := make([]Entry, 0, len(keychainEntries))
	for _, kEntry := range keychainEntries {
		entry, err := m.parseEntry(&kEntry)
		if err != nil {
			// Skip invalid entries but don't fail completely
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// GetPasswordsByService returns password entries (EntryTypePassword only)
// for a given service name. Use ListEntriesFiltered directly if the caller
// needs other types.
func (m *Manager) GetPasswordsByService(service string) ([]Entry, error) {
	return m.ListEntriesFiltered(ListFilter{Service: service, EntryType: EntryTypePassword})
}

// EntryExists reports whether an entry is stored at (service, username,
// entryType) without reading or decrypting the secret. Use this for
// existence probes (e.g. overwrite prompts, migration conflict checks)
// instead of GetPassword + zero — cheaper, never touches plaintext, and
// returns a clean tri-state (exists / absent / backend error).
func (m *Manager) EntryExists(service, username string, entryType EntryType) (bool, error) {
	serviceKey, err := m.generateServiceKey(service, username, entryType)
	if err != nil {
		return false, fmt.Errorf("failed to build service key: %w", err)
	}
	entries, err := m.keychain.ListEntries(serviceKey)
	if err != nil {
		return false, fmt.Errorf("failed to list entries: %w", err)
	}
	// ListEntries is a prefix query in the SQLite backend — require exact
	// (service, account) match so a sibling like "github/alice" vs
	// "github/alicia" or a cross-user entry can't register as a hit.
	for _, e := range entries {
		if e.Service == serviceKey && e.Account == m.user {
			return true, nil
		}
	}
	return false, nil
}

// SortField controls the sort order of listed entries.
type SortField string

const (
	SortByService   SortField = "service"
	SortByCreatedAt SortField = "created_at"
	SortByUpdatedAt SortField = "updated_at"
)

// ListFilter controls which entries are returned and in what order.
type ListFilter struct {
	EntryType EntryType // empty means all types
	Service   string    // empty means all services
	SortBy    SortField // empty defaults to SortByService
	Limit     int       // 0 means no limit
	Offset    int
}

// ListEntriesFiltered returns entries matching the given filter.
func (m *Manager) ListEntriesFiltered(filter ListFilter) ([]Entry, error) {
	entries, err := m.ListEntries()
	if err != nil {
		return nil, err
	}

	// Filter
	filtered := make([]Entry, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if filter.EntryType != "" && e.Type != filter.EntryType {
			continue
		}
		if filter.Service != "" && !strings.EqualFold(e.Service, filter.Service) {
			continue
		}
		filtered = append(filtered, *e)
	}

	// Sort. Both backends should guarantee non-zero timestamps (macOS
	// metadata sets them on store; the SQLite schema has DEFAULT
	// CURRENT_TIMESTAMP), so a zero value here implies the underlying
	// store was tampered with or an older metadata record deserialized
	// without the fields. Fall back to service order in that case so a
	// single corrupt entry doesn't anchor the whole list to epoch.
	switch filter.SortBy {
	case SortByCreatedAt:
		sort.Slice(filtered, func(i, j int) bool {
			if filtered[i].CreatedAt.IsZero() || filtered[j].CreatedAt.IsZero() {
				return filtered[i].Service < filtered[j].Service
			}
			return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
		})
	case SortByUpdatedAt:
		sort.Slice(filtered, func(i, j int) bool {
			if filtered[i].UpdatedAt.IsZero() || filtered[j].UpdatedAt.IsZero() {
				return filtered[i].Service < filtered[j].Service
			}
			return filtered[i].UpdatedAt.Before(filtered[j].UpdatedAt)
		})
	default:
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Service < filtered[j].Service })
	}

	// Paginate
	if filter.Offset > 0 {
		if filter.Offset >= len(filtered) {
			return []Entry{}, nil
		}
		filtered = filtered[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(filtered) {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// Searcher is an optional interface that credential stores can implement
// to provide full-text search. The SQLite store implements this via FTS5.
type Searcher interface {
	SearchEntries(query string) ([]keychain.KeychainEntry, error)
}

// SearchEntries returns entries where the query matches service, username, or description.
// If the underlying store supports FTS (implements Searcher), it is used for ranked results.
// Otherwise, falls back to in-memory case-insensitive substring matching.
func (m *Manager) SearchEntries(query string) ([]Entry, error) {
	if searcher, ok := m.keychain.(Searcher); ok {
		kEntries, err := searcher.SearchEntries(query)
		if err != nil {
			return nil, fmt.Errorf("search failed: %w", err)
		}
		entries := make([]Entry, 0, len(kEntries))
		for _, kEntry := range kEntries {
			entry, err := m.parseEntry(&kEntry)
			if err != nil {
				continue
			}
			entries = append(entries, entry)
		}
		return entries, nil
	}

	// Fallback: in-memory substring matching
	entries, err := m.ListEntries()
	if err != nil {
		return nil, err
	}

	q := strings.ToLower(query)
	var results []Entry
	for i := range entries {
		e := &entries[i]
		if strings.Contains(strings.ToLower(e.Service), q) ||
			strings.Contains(strings.ToLower(e.Username), q) ||
			strings.Contains(strings.ToLower(e.Description), q) {
			results = append(results, *e)
		}
	}
	return results, nil
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
func (m *Manager) parseEntry(kEntry *keychain.KeychainEntry) (Entry, error) {
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

	return Entry{
		ID:          kEntry.Service + ":" + kEntry.Account,
		Service:     service,
		Username:    username,
		Type:        entryType,
		Description: kEntry.Description,
		CreatedAt:   kEntry.CreatedAt,
		UpdatedAt:   kEntry.UpdatedAt,
	}, nil
}
