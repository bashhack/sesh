package vault

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
)

// MemStore is a Store in memory, for tests.
type MemStore struct {
	entries map[Key]memEntry
	// Now returns the time to stamp entries with; tests may replace it.
	Now func() time.Time
	mu  sync.Mutex
}

type memEntry struct {
	secret []byte
	entry  Entry
}

var _ Store = (*MemStore)(nil)

// entryCopy is e's entry, sharing nothing with it.
func (e *memEntry) entryCopy() Entry {
	c := e.entry
	c.Tags = slices.Clone(c.Tags)
	return c
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{entries: map[Key]memEntry{}, Now: func() time.Time { return time.Now().UTC() }}
}

func notFound(k Key) error {
	return fmt.Errorf("%w: %s", ErrNotFound, k)
}

// Get implements Store.
func (m *MemStore) Get(k Key) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[k]
	if !ok {
		return nil, notFound(k)
	}
	return bytes.Clone(e.secret), nil
}

// Put implements Store.
func (m *MemStore) Put(k Key, secret []byte) error {
	if err := k.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	e, ok := m.entries[k]
	if !ok {
		e.entry = Entry{Key: k, CreatedAt: now}
	}
	e.entry.UpdatedAt = now
	e.secret = bytes.Clone(secret)
	m.entries[k] = e
	return nil
}

// Save implements Store.
func (m *MemStore) Save(e *Entry, secret []byte) error {
	if err := e.Key.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := CheckFolder(e.Folder); err != nil {
		return err
	}
	for _, t := range e.Tags {
		if err := CheckTag(t); err != nil {
			return err
		}
	}
	now := m.Now()
	saved := *e
	saved.Tags = NormalizeTags(e.Tags)
	if saved.CreatedAt.IsZero() {
		saved.CreatedAt = now
	}
	if saved.UpdatedAt.IsZero() {
		saved.UpdatedAt = now
	}
	m.entries[e.Key] = memEntry{entry: saved, secret: bytes.Clone(secret)}
	return nil
}

// SetSettings implements Store.
func (m *MemStore) SetSettings(k Key, s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[k]
	if !ok {
		return notFound(k)
	}
	e.entry.Settings = s
	e.entry.UpdatedAt = m.Now()
	m.entries[k] = e
	return nil
}

// Lookup implements Store.
func (m *MemStore) Lookup(k Key) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[k]
	if !ok {
		return Entry{}, notFound(k)
	}
	return e.entryCopy(), nil
}

// Exists implements Store.
func (m *MemStore) Exists(k Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[k]; !ok {
		return notFound(k)
	}
	return nil
}

// List implements Store.
func (m *MemStore) List(f Filter) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for k := range m.entries {
		me := m.entries[k]
		if e := me.entryCopy(); f.Matches(&e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.Less(out[j].Key) })
	return out, nil
}

// DeleteMany implements Store.
func (m *MemStore) DeleteMany(keys []Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		if _, ok := m.entries[k]; !ok {
			return notFound(k)
		}
	}
	for _, k := range keys {
		delete(m.entries, k)
	}
	return nil
}

// Delete implements Store.
func (m *MemStore) Delete(k Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[k]; !ok {
		return notFound(k)
	}
	delete(m.entries, k)
	return nil
}
