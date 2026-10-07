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
	Folder   string    `json:"folder,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
}

func entryFrom(e *vault.Entry) Entry {
	return Entry{
		ID:        e.Key.String(),
		Service:   e.Service,
		Username:  e.Username,
		Type:      e.Kind,
		Folder:    e.Folder,
		Tags:      e.Tags,
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

// StorePassword creates the entry or replaces its secret, filing it as
// filing says.
func (m *Manager) StorePassword(service, username string, password []byte, entryType EntryType, filing vault.Filing) error {
	secret := bytes.Clone(password)
	defer secure.SecureZeroBytes(secret)
	k := key(service, username, entryType)
	if filing.IsZero() {
		if err := m.store.Put(k, secret); err != nil {
			return fmt.Errorf("failed to store password: %w", err)
		}
		return nil
	}
	e, err := m.existingOrNew(k)
	if err != nil {
		return err
	}
	filing.Apply(&e)
	if err := m.store.Save(&e, secret); err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}
	return nil
}

// existingOrNew is the entry at k, to be saved again with its settings,
// folder, tags, and creation time, or a new one when there's none.
func (m *Manager) existingOrNew(k vault.Key) (vault.Entry, error) {
	e, err := m.store.Lookup(k)
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return vault.Entry{Key: k}, nil
	case err != nil:
		return vault.Entry{}, fmt.Errorf("failed to check for an existing entry: %w", err)
	}
	e.UpdatedAt = time.Time{}
	return e, nil
}

// GetPassword returns the entry's secret, which the caller zeroes.
func (m *Manager) GetPassword(service, username string, entryType EntryType) ([]byte, error) {
	k := key(service, username, entryType)
	secret, err := m.store.Get(k)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve password: %w", m.withCaseHint(err, k))
	}
	return secret, nil
}

// LookupEntry returns the entry without its secret.
func (m *Manager) LookupEntry(service, username string, entryType EntryType) (Entry, error) {
	k := key(service, username, entryType)
	e, err := m.store.Lookup(k)
	if err != nil {
		return Entry{}, fmt.Errorf("failed to look up entry: %w", m.withCaseHint(err, k))
	}
	return entryFrom(&e), nil
}

// StorePasswordString is StorePassword for a string.
func (m *Manager) StorePasswordString(service, username, password string, entryType EntryType) error {
	secret := []byte(password)
	defer secure.SecureZeroBytes(secret)
	return m.StorePassword(service, username, secret, entryType, vault.Filing{})
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
	return m.StoreTOTPSecretWithParams(service, username, secret, totp.Params{}, vault.Filing{})
}

// StoreTOTPSecretWithParams checks and stores a TOTP secret with its code
// settings (algorithm, digits, period, issuer), in one write: the settings
// decide which codes are right, so the secret is never stored without
// them. An entry being replaced keeps its other settings, its folder and
// tags (unless filing changes them), and its creation time.
func (m *Manager) StoreTOTPSecretWithParams(service, username, secret string, params totp.Params, filing vault.Filing) error {
	normalized, err := totp.ValidateAndNormalizeSecret(secret)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}
	e, err := m.existingOrNew(key(service, username, EntryTypeTOTP))
	if err != nil {
		return err
	}
	e.Settings.TOTP = params
	filing.Apply(&e)
	plain := []byte(normalized)
	defer secure.SecureZeroBytes(plain)
	if err := m.store.Save(&e, plain); err != nil {
		return fmt.Errorf("failed to store the TOTP secret: %w", err)
	}
	return nil
}

// GenerateTOTPCode returns the current code for a stored TOTP secret,
// using its code settings.
func (m *Manager) GenerateTOTPCode(service, username string) (string, error) {
	secret, err := m.GetPassword(service, username, EntryTypeTOTP)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}
	defer secure.SecureZeroBytes(secret)

	// The code settings decide which codes are right, so not reading them
	// is an error, not the defaults.
	e, err := m.store.Lookup(key(service, username, EntryTypeTOTP))
	if err != nil {
		return "", fmt.Errorf("failed to read the TOTP code settings: %w", err)
	}
	current, _, err := totp.GenerateConsecutiveCodesBytesWithParams(secret, e.Settings.TOTP)
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
	err := m.store.Exists(key(service, username, entryType))
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

// CaseHint suggests the entries in store that k misses only by case: "did
// you mean …? Names are case-sensitive", or "" when there are none.
func CaseHint(store vault.Store, k vault.Key) string {
	twins, err := NewManager(store).CaseTwins(k)
	if err != nil || len(twins) == 0 {
		return ""
	}
	ids := make([]string, len(twins))
	for i, t := range twins {
		ids[i] = t.String()
	}
	return fmt.Sprintf("did you mean %s? Names are case-sensitive", strings.Join(ids, " or "))
}

// DeleteEntry removes the entry.
func (m *Manager) DeleteEntry(service, username string, entryType EntryType) error {
	if err := m.store.Delete(key(service, username, entryType)); err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}
	return nil
}

// CaseTwins returns the entries of k's kind whose service name and username
// match k's ignoring case, other than k itself. Names are case-sensitive,
// so these are what a name typed in another case misses, or duplicates.
func (m *Manager) CaseTwins(k vault.Key) ([]vault.Key, error) {
	entries, err := m.store.List(vault.Filter{Kind: k.Kind})
	if err != nil {
		return nil, err
	}
	var twins []vault.Key
	for i := range entries {
		e := entries[i].Key
		if e != k && strings.EqualFold(e.Service, k.Service) && strings.EqualFold(e.Username, k.Username) {
			twins = append(twins, e)
		}
	}
	return twins, nil
}

// EntryName names k the way --list does: "github", or "github (alice)".
func EntryName(k vault.Key) string {
	if k.Username == "" {
		return k.Service
	}
	return fmt.Sprintf("%s (%s)", k.Service, k.Username)
}

// withCaseHint adds to a not-found err the entries k may have meant, when
// some differ from it only in case.
func (m *Manager) withCaseHint(err error, k vault.Key) error {
	if !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	twins, terr := m.CaseTwins(k)
	if terr != nil || len(twins) == 0 {
		return err
	}
	names := make([]string, len(twins))
	for i, t := range twins {
		names[i] = EntryName(t)
	}
	return fmt.Errorf("%w; did you mean %s? Names are case-sensitive", err, strings.Join(names, " or "))
}
