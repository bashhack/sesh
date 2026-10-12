// Package tui is sesh ui: a search over every entry, copying a secret or
// a code with Enter, with TOTP entries' codes drawn as they change.
//
// It stays open, so it locks itself: after the agent's idle timeout, past
// its longest unlock, or when the vault locks or changes under it, it
// wipes what it holds and asks for the master password again, drawing the
// field itself.
package tui

import (
	"errors"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// ErrLocked is a vault that can't be read any more until it's unlocked
// again: the agent locked, or the vault's key changed. Vault methods
// return one made by Locked.
var ErrLocked = errors.New("locked")

// Locked is ErrLocked, saying why in a sentence the locked screen shows.
func Locked(why string) error { return &lockedError{why: why} }

type lockedError struct{ why string }

func (e *lockedError) Error() string        { return e.why }
func (e *lockedError) Is(target error) bool { return target == ErrLocked }

// ErrWrongPassword is a password Unlock refused.
var ErrWrongPassword = errors.New("wrong password")

// maxAttempts is how many wrong passwords in a row end the app, as a
// command's prompt allows.
const maxAttempts = 3

// Vault is what the app reads, while unlocked.
type Vault interface {
	// Search is the entries matching query, best first, as sesh's search
	// ranks them; every entry for "".
	Search(query string) ([]vault.Entry, error)
	// Secret is k's secret, read as the audit log records: for reading.
	// The caller wipes it.
	Secret(k vault.Key, reading string) ([]byte, error)
	// CodeKey is the TOTP entry k's key, for drawing its codes, which the
	// audit log doesn't record. The caller wipes it.
	CodeKey(k vault.Key) ([]byte, error)
	// Changed says whether the vault may have changed since it last asked.
	Changed() (bool, error)
	Close() error
}

// Options are what the app works with.
type Options struct {
	Vault Vault
	// Unlock opens the vault again with password, which it wipes;
	// ErrWrongPassword when it's wrong.
	Unlock func(password []byte) (Vault, error)
	// TouchID opens the vault again with a fingerprint; nil when it isn't
	// set up.
	TouchID func() (Vault, error)
	// Copy puts text on the clipboard, cleared after ClearAfter.
	Copy       func(text string) error
	Now        func() time.Time
	ClearAfter time.Duration
	// IdleTimeout locks after this long without a key pressed, and
	// MaxLifetime this long after unlocking, as the agent does; 0 never.
	IdleTimeout, MaxLifetime time.Duration
}

// Model is the app. Its methods take a pointer: the one Model is the
// program's, and Close is called on it after the program ends.
type Model struct {
	lastKey, unlockedAt time.Time
	statusUntil         time.Time

	v       Vault // nil while locked
	quitErr error

	// keys are TOTP keys held for drawing codes, wiped on lock and exit;
	// pending are being read, and failed couldn't be.
	failed  map[vault.Key]bool
	keys    map[vault.Key][]byte
	pending map[vault.Key]bool

	// every is the clock, a tick each whole second; tests replace it.
	every func() tea.Cmd

	lockedWhy string // why it's locked, while it is
	status    string
	password  []byte // typed on the locked screen

	rows  []vault.Entry
	query []rune

	opts Options

	// epoch counts unlocks: a message from before the last lock or unlock
	// is dropped. searches counts searches: only the latest's results are
	// shown.
	epoch, searches int

	width, height int
	wrong         int
	top, sel      int
	unlocking     bool
}

// New is the app, unlocked with opts.Vault.
func New(opts Options) *Model {
	now := opts.Now()
	return &Model{
		opts: opts, v: opts.Vault,
		keys: map[vault.Key][]byte{}, pending: map[vault.Key]bool{}, failed: map[vault.Key]bool{},
		lastKey: now, unlockedAt: now,
		width: 80, height: 24,
		every: tick,
	}
}

// Err is why the app ended, when it wasn't asked to: too many wrong
// passwords, or the vault couldn't be read.
func (m *Model) Err() error { return m.quitErr }

// Close wipes what the app holds and closes the vault.
func (m *Model) Close() {
	m.wipe()
	secure.SecureZeroBytes(m.password)
	m.password = nil
	if m.v != nil {
		m.v.Close() //nolint:errcheck,gosec // nothing more to do with the vault
		m.v = nil
	}
}

// wipe drops the held TOTP keys.
func (m *Model) wipe() {
	for k, key := range m.keys {
		secure.SecureZeroBytes(key)
		delete(m.keys, k)
	}
	clear(m.pending)
	clear(m.failed)
}

// Messages, each from a command started at an epoch.
type (
	tickMsg    time.Time
	resultsMsg struct {
		err    error
		rows   []vault.Entry
		epoch  int
		search int
	}
	keyMsg struct {
		err   error
		k     vault.Key
		key   []byte
		epoch int
	}
	copiedMsg struct {
		err   error
		what  string
		epoch int
	}
	changedMsg struct {
		err     error
		epoch   int
		changed bool
	}
	unlockedMsg struct {
		err error
		v   Vault
	}
)

// Init starts the search for every entry and the clock.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.search(), m.every())
}

// tick fires at the next whole second, when codes and countdowns change.
func tick() tea.Cmd {
	return tea.Every(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// search runs the query as it is now.
func (m *Model) search() tea.Cmd {
	m.searches++
	v, q, epoch, n := m.v, string(m.query), m.epoch, m.searches
	return func() tea.Msg {
		rows, err := v.Search(q)
		return resultsMsg{rows: rows, err: err, epoch: epoch, search: n}
	}
}

// Update handles a message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := m.update(msg)
	return m, cmd
}

// update handles a message, returning what to do next.
func (m *Model) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.scroll()
		return m.readKeys()
	case tea.KeyPressMsg:
		if m.v == nil {
			return m.lockedKey(msg)
		}
		return m.key(msg)
	case tea.PasteMsg:
		if m.v == nil {
			if !m.unlocking {
				m.password = append(m.password, msg.Content...)
			}
			return nil
		}
		m.lastKey = m.opts.Now()
		m.query = append(m.query, []rune(msg.Content)...)
		return m.requery()
	case tickMsg:
		return m.tick()
	case resultsMsg:
		if msg.epoch != m.epoch || msg.search != m.searches || m.v == nil {
			return nil
		}
		if msg.err != nil {
			return m.failure(msg.err)
		}
		m.rows = msg.rows
		m.scroll()
		return m.readKeys()
	case keyMsg:
		if msg.epoch != m.epoch || m.v == nil {
			secure.SecureZeroBytes(msg.key)
			return nil
		}
		delete(m.pending, msg.k)
		if msg.err != nil {
			if errors.Is(msg.err, ErrLocked) {
				return m.lock(lockedReason(msg.err))
			}
			m.failed[msg.k] = true
			return nil
		}
		m.keys[msg.k] = msg.key
		return nil
	case copiedMsg:
		if msg.epoch != m.epoch || m.v == nil {
			return nil
		}
		switch {
		case errors.Is(msg.err, ErrLocked):
			return m.lock(lockedReason(msg.err))
		case msg.err != nil:
			m.say("Couldn't copy it: " + msg.err.Error())
		default:
			m.say(msg.what)
		}
		return nil
	case changedMsg:
		if msg.epoch != m.epoch || m.v == nil {
			return nil
		}
		if msg.err != nil {
			return m.failure(msg.err)
		}
		if msg.changed {
			// Entries may have changed, keys with them: read again.
			m.wipe()
			return m.search()
		}
		return nil
	case unlockedMsg:
		m.unlocking = false
		if msg.err != nil {
			if errors.Is(msg.err, ErrWrongPassword) {
				m.wrong++
				if m.wrong >= maxAttempts {
					m.quitErr = errors.New("wrong master password (after 3 attempts)")
					return tea.Quit
				}
				m.lockedWhy = "Wrong password, try again."
				return nil
			}
			m.lockedWhy = msg.err.Error()
			return nil
		}
		m.v, m.wrong, m.lockedWhy = msg.v, 0, ""
		m.epoch++
		now := m.opts.Now()
		m.lastKey, m.unlockedAt = now, now
		return m.search()
	}
	return nil
}

// tick locks once the idle timeout or the longest unlock has passed, and
// otherwise checks whether another command changed the vault.
func (m *Model) tick() tea.Cmd {
	if m.v == nil {
		return m.every()
	}
	now := m.opts.Now()
	switch {
	case m.opts.IdleTimeout > 0 && now.Sub(m.lastKey) >= m.opts.IdleTimeout:
		return tea.Batch(m.every(), m.lock("Locked after "+m.opts.IdleTimeout.String()+" without use."))
	case m.opts.MaxLifetime > 0 && now.Sub(m.unlockedAt) >= m.opts.MaxLifetime:
		return tea.Batch(m.every(), m.lock("Locked "+m.opts.MaxLifetime.String()+" after unlocking."))
	}
	v, epoch := m.v, m.epoch
	return tea.Batch(m.every(), func() tea.Msg {
		changed, err := v.Changed()
		return changedMsg{changed: changed, err: err, epoch: epoch}
	})
}

// failure is what an error reading the vault does: one that means it's
// locked locks the app; another ends it.
func (m *Model) failure(err error) tea.Cmd {
	if errors.Is(err, ErrLocked) {
		return m.lock(lockedReason(err))
	}
	m.quitErr = err
	return tea.Quit
}

// lockedReason says why the vault locked, from err.
func lockedReason(err error) string {
	if le := (*lockedError)(nil); errors.As(err, &le) {
		return le.why
	}
	return err.Error()
}

// lock wipes what the app holds, closes the vault, and shows the locked
// screen, saying why.
func (m *Model) lock(why string) tea.Cmd {
	m.wipe()
	if m.v != nil {
		m.v.Close() //nolint:errcheck,gosec // the vault is done with
		m.v = nil
	}
	m.epoch++
	m.rows, m.sel, m.top = nil, 0, 0
	m.status = ""
	m.lockedWhy = why
	return nil
}

// say shows what for a few seconds.
func (m *Model) say(what string) {
	m.status = what
	m.statusUntil = m.opts.Now().Add(5 * time.Second)
}
