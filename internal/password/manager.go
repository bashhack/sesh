// Package password is sesh's password manager: passwords, API keys, TOTP
// secrets, and secure notes, kept in a vault.Store.
package password

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// EntryType is an entry's kind.
type EntryType = vault.Kind

// The kinds of entry.
const (
	EntryTypePassword = vault.KindPassword
	EntryTypeAPIKey   = vault.KindAPIKey
	EntryTypeTOTP     = vault.KindTOTP
	EntryTypeNote     = vault.KindNote
)

// Entry is a listed entry, without its secret.
type Entry struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// ID is the entry's key in text form: what --delete takes.
	ID       string    `json:"id"`
	Service  string    `json:"service"`
	Username string    `json:"username,omitempty"`
	Type     EntryType `json:"type"`
}

func entryFrom(e *vault.Entry) Entry {
	return Entry{
		ID:        e.Key.String(),
		Service:   e.Service,
		Username:  e.Username,
		Type:      e.Kind,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
}

// Manager provides the password manager's operations on a vault.
type Manager struct {
	store vault.Store
}

// NewManager returns a Manager for store.
func NewManager(store vault.Store) *Manager {
	return &Manager{store: store}
}

func key(service, username string, entryType EntryType) vault.Key {
	return vault.Key{Kind: entryType, Service: service, Username: username}
}

// StorePassword creates the entry or replaces its secret.
func (m *Manager) StorePassword(service, username string, password []byte, entryType EntryType) error {
	secret := bytes.Clone(password)
	defer secure.SecureZeroBytes(secret)
	if err := m.store.Put(key(service, username, entryType), secret); err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}
	return nil
}

// GetPassword returns the entry's secret, which the caller zeroes.
func (m *Manager) GetPassword(service, username string, entryType EntryType) ([]byte, error) {
	secret, err := m.store.Get(key(service, username, entryType))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve password: %w", err)
	}
	return secret, nil
}

// StorePasswordString is StorePassword for a string.
func (m *Manager) StorePasswordString(service, username, password string, entryType EntryType) error {
	secret := []byte(password)
	defer secure.SecureZeroBytes(secret)
	return m.StorePassword(service, username, secret, entryType)
}

// GetPasswordString is GetPassword as a string, which can't be zeroed.
func (m *Manager) GetPasswordString(service, username string, entryType EntryType) (string, error) {
	secret, err := m.GetPassword(service, username, entryType)
	if err != nil {
		return "", err
	}
	defer secure.SecureZeroBytes(secret)
	return string(secret), nil
}

// StoreTOTPSecret stores a TOTP secret with the usual code settings.
func (m *Manager) StoreTOTPSecret(service, username, secret string) error {
	return m.StoreTOTPSecretWithParams(service, username, secret, totp.Params{})
}

// StoreTOTPSecretWithParams checks and stores a TOTP secret with its code
// settings (algorithm, digits, period, issuer). The settings decide which
// codes are right, so failing to store them is an error.
func (m *Manager) StoreTOTPSecretWithParams(service, username, secret string, params totp.Params) error {
	normalized, err := totp.ValidateAndNormalizeSecret(secret)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}
	k := key(service, username, EntryTypeTOTP)
	if err := m.StorePasswordString(service, username, normalized, EntryTypeTOTP); err != nil {
		return err
	}
	e, err := m.store.Lookup(k)
	if err != nil {
		return fmt.Errorf("stored the TOTP secret but couldn't read its settings: %w", err)
	}
	e.Settings.TOTP = params
	if err := m.store.SetSettings(k, e.Settings); err != nil {
		return fmt.Errorf("stored the TOTP secret but couldn't store its code settings (codes would use the defaults): %w", err)
	}
	return nil
}

// GetTOTPParams returns a TOTP entry's code settings; zero for an entry
// with the usual ones, or none.
func (m *Manager) GetTOTPParams(service, username string) totp.Params {
	e, err := m.store.Lookup(key(service, username, EntryTypeTOTP))
	if err != nil {
		return totp.Params{}
	}
	return e.Settings.TOTP
}

// GenerateTOTPCode returns the current code for a stored TOTP secret,
// using its code settings.
func (m *Manager) GenerateTOTPCode(service, username string) (string, error) {
	secret, err := m.GetPassword(service, username, EntryTypeTOTP)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}
	defer secure.SecureZeroBytes(secret)

	current, _, err := totp.GenerateConsecutiveCodesBytesWithParams(secret, m.GetTOTPParams(service, username))
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return current, nil
}

// ListEntries returns every entry.
func (m *Manager) ListEntries() ([]Entry, error) {
	stored, err := m.store.List(vault.Filter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list entries: %w", err)
	}
	entries := make([]Entry, len(stored))
	for i := range stored {
		entries[i] = entryFrom(&stored[i])
	}
	return entries, nil
}

// GetPasswordsByService returns the password entries (EntryTypePassword
// only) for a service name. Use ListEntriesFiltered for other kinds.
func (m *Manager) GetPasswordsByService(service string) ([]Entry, error) {
	return m.ListEntriesFiltered(ListFilter{Service: service, EntryType: EntryTypePassword})
}

// EntryExists reports whether the entry exists, without reading its secret.
func (m *Manager) EntryExists(service, username string, entryType EntryType) (bool, error) {
	_, err := m.store.Lookup(key(service, username, entryType))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, vault.ErrNotFound):
		return false, nil
	default:
		return false, fmt.Errorf("failed to look up entry: %w", err)
	}
}

// SortField controls the sort order of listed entries.
type SortField string

// The sort orders.
const (
	SortByService   SortField = "service"
	SortByCreatedAt SortField = "created_at"
	SortByUpdatedAt SortField = "updated_at"
)

// ListFilter controls which entries are returned and in what order.
type ListFilter struct {
	EntryType EntryType // empty means all types
	Service   string    // empty means all services; matched ignoring case
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

	switch filter.SortBy {
	case SortByCreatedAt:
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].CreatedAt.Before(filtered[j].CreatedAt) })
	case SortByUpdatedAt:
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].UpdatedAt.Before(filtered[j].UpdatedAt) })
	default:
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Service < filtered[j].Service })
	}

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

// DeleteEntry removes the entry.
func (m *Manager) DeleteEntry(service, username string, entryType EntryType) error {
	if err := m.store.Delete(key(service, username, entryType)); err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}
	return nil
}
