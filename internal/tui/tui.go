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
	// Check says whether the vault can still be read, without counting as
	// a use of it (ErrLocked when it must be unlocked again), and whether
	// another command may have changed it since the last Check.
	Check() (changed bool, err error)
	// KeepAlive says the vault is still in use, so the agent doesn't lock
	// it for being idle.
	KeepAlive() error
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
	// MaxLifetime this long after the app unlocked, as the agent does; 0
	// never.
	IdleTimeout, MaxLifetime time.Duration
}

// Model is the app. Its methods take a pointer: the one Model is the
// program's, and Close is called on it after the program ends.
type Model struct {
	lastKey, unlockedAt time.Time
	statusUntil         time.Time
	lastKeepAlive       time.Time

	quitErr error

	v *gate // nil while locked

	// keys are TOTP keys held for drawing codes, wiped on lock and exit;
	// pending are being read, and failed couldn't be. codes are the codes
	// shown, each made once a period.
	failed  map[vault.Key]bool
	keys    map[vault.Key][]byte
	pending map[vault.Key]bool
	codes   map[vault.Key]shownCode

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

// shownCode is a TOTP code, and the period it's for.
type shownCode struct {
	text   string
	period int64
}

// New is the app, unlocked with opts.Vault.
func New(opts Options) *Model {
	now := opts.Now()
	return &Model{
		opts: opts, v: newGate(opts.Vault),
		keys: map[vault.Key][]byte{}, pending: map[vault.Key]bool{}, failed: map[vault.Key]bool{},
		codes:   map[vault.Key]shownCode{},
		lastKey: now, unlockedAt: now, lastKeepAlive: now,
		width: 80, height: 24,
		every: tick,
	}
}

// Err is why the app ended, when it wasn't asked to: too many wrong
// passwords, or the vault couldn't be read.
func (m *Model) Err() error { return m.quitErr }

// Close waits for reads still running, wipes what the app holds, and
// closes the vault.
func (m *Model) Close() {
	if m.v != nil {
		m.v.close()
		m.v = nil
	}
	m.wipe()
	secure.SecureZeroBytes(m.password)
	m.password = nil
}

// wipe drops the held TOTP keys, and the codes made from them.
func (m *Model) wipe() {
	for k, key := range m.keys {
		secure.SecureZeroBytes(key)
		delete(m.keys, k)
	}
	clear(m.pending)
	clear(m.failed)
	clear(m.codes)
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
	checkedMsg struct {
		err     error
		epoch   int
		changed bool
	}
	keptAliveMsg struct {
		err   error
		epoch int
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

// read is f run on the open vault, through its gate.
func (m *Model) read(f func(v Vault, closed func() bool) tea.Msg) tea.Cmd {
	g := m.v
	return func() tea.Msg { return g.run(f) }
}

// search runs the query as it is now.
func (m *Model) search() tea.Cmd {
	m.searches++
	q, epoch, n := string(m.query), m.epoch, m.searches
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		rows, err := v.Search(q)
		return resultsMsg{rows: rows, err: err, epoch: epoch, search: n}
	})
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
		return tea.Batch(m.key(msg), m.keepAlive())
	case tea.PasteMsg:
		// A line copied with its end keeps the newline; it's not part of
		// a name or a password.
		text := trimNewlines(msg.Content)
		if m.v == nil {
			if !m.unlocking {
				m.password = appendSecret(m.password, text)
			}
			return nil
		}
		m.lastKey = m.opts.Now()
		m.query = append(m.query, []rune(text)...)
		return tea.Batch(m.requery(), m.keepAlive())
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
		// A key read twice (the vault changed while it was being read)
		// is kept once; the other is wiped.
		if msg.epoch != m.epoch || m.v == nil || m.keys[msg.k] != nil {
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
	case checkedMsg:
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
	case keptAliveMsg:
		if msg.epoch == m.epoch && m.v != nil && errors.Is(msg.err, ErrLocked) {
			return m.lock(lockedReason(msg.err))
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
		m.v, m.wrong, m.lockedWhy = newGate(msg.v), 0, ""
		m.epoch++
		now := m.opts.Now()
		m.lastKey, m.unlockedAt, m.lastKeepAlive = now, now, now
		return m.search()
	}
	return nil
}

// tick locks once the idle timeout or the longest unlock has passed, and
// otherwise checks the vault: that it can still be read, and whether
// another command changed it.
func (m *Model) tick() tea.Cmd {
	if m.v == nil {
		return m.every()
	}
	now := m.opts.Now()
	switch {
	case m.opts.IdleTimeout > 0 && since(now, m.lastKey) >= m.opts.IdleTimeout:
		return tea.Batch(m.every(), m.lock("Locked after "+m.opts.IdleTimeout.String()+" without use."))
	case m.opts.MaxLifetime > 0 && since(now, m.unlockedAt) >= m.opts.MaxLifetime:
		return tea.Batch(m.every(), m.lock("Locked "+m.opts.MaxLifetime.String()+" after unlocking."))
	}
	epoch := m.epoch
	return tea.Batch(m.every(), m.read(func(v Vault, _ func() bool) tea.Msg {
		changed, err := v.Check()
		return checkedMsg{changed: changed, err: err, epoch: epoch}
	}))
}

// since is how long ago t was at now, by the clock that says longer: the
// monotonic clock stops while the computer sleeps, the wall clock doesn't.
func since(now, t time.Time) time.Duration {
	return max(now.Sub(t), now.Round(0).Sub(t.Round(0)))
}

// keepAlive tells the vault it's in use, so the agent's idle timer starts
// again, at most twice in its timeout and once a minute.
func (m *Model) keepAlive() tea.Cmd {
	every := time.Minute
	if m.opts.IdleTimeout > 0 {
		every = min(every, m.opts.IdleTimeout/2)
	}
	now := m.opts.Now()
	if m.v == nil || since(now, m.lastKeepAlive) < every {
		return nil
	}
	m.lastKeepAlive = now
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		return keptAliveMsg{err: v.KeepAlive(), epoch: epoch}
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

// lock waits for reads still running, wipes what the app holds, closes
// the vault, and shows the locked screen, saying why.
func (m *Model) lock(why string) tea.Cmd {
	if m.v != nil {
		m.v.close()
		m.v = nil
	}
	m.wipe()
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
