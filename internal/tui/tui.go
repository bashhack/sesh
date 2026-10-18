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
	"slices"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/health"
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

// ErrExists is a file refused because one is already where it would go:
// asked about, it can be replaced.
var ErrExists = errors.New("exists")

// Exists is ErrExists, saying why.
func Exists(why string) error { return &existsError{why: why} }

type existsError struct{ why string }

func (e *existsError) Error() string        { return e.why }
func (e *existsError) Is(target error) bool { return target == ErrExists }

// ErrRefused is a change refused for good: trying it again can't help.
var ErrRefused = errors.New("refused")

// Refused is ErrRefused, saying why.
func Refused(why string) error { return &refusedError{why: why} }

type refusedError struct{ why string }

func (e *refusedError) Error() string        { return e.why }
func (e *refusedError) Is(target error) bool { return target == ErrRefused }

// Trashed is an entry in the trash.
type Trashed struct {
	DeletedAt time.Time
	Key       vault.Key
	Folder    string
	ID        int64
}

// AuditLog is the newest events of the vault's audit log, the newest
// first, with how many there are in all.
type AuditLog struct {
	Oldest time.Time // when the oldest event of all was
	// Keep says what's removed on its own: "Events older than 365 days
	// are removed automatically (audit.retention_days)."
	Keep   string
	Events []AuditEvent
	Count  int64
}

// AuditEvent is one event of the audit log, as sesh audit says it.
type AuditEvent struct {
	When  time.Time
	Event string // "read", "edit", "delete", …
	What  string // the entry, or the vault, and what of it
}

// ExportOnly narrows an export to a kind, to the entries in a folder (with
// the folders under it), and to those with every one of Tags; each left
// zero narrows nothing.
type ExportOnly struct {
	Kind   vault.Kind
	Folder string
	Tags   []string
}

// ScannedQR is a TOTP entry's otpauth:// link read from a QR code, on
// screen or in an image, with the issuer and account it names.
type ScannedQR struct {
	Issuer, Account string
	Link            []byte
}

// Change is an entry added (Key zero) or changed: To is its name after;
// nil and empty fields leave what the entry has. Secret is the new secret
// (a TOTP entry's key, or an otpauth:// link to read it from); Notes are
// the new notes when SetNotes, written from NotesBase, the notes they
// replace, so a change by another command meanwhile is refused. The
// caller wipes Secret, Notes, NotesBase, and secret fields' values.
type Change struct {
	URL    *string
	Folder *string
	// FileName is a file entry's file's name, given with new content.
	FileName     *string
	Key, To      vault.Key
	Secret       []byte
	Notes        []byte
	NotesBase    []byte
	SetFields    []vault.Field
	RemoveFields []string
	Tags         []string // the entry's tags after, when TagsSet
	TagsSet      bool
	SetNotes     bool
}

// Wipe overwrites what's secret in c.
func (c *Change) Wipe() {
	secure.SecureZeroBytes(c.Secret)
	secure.SecureZeroBytes(c.Notes)
	secure.SecureZeroBytes(c.NotesBase)
	for _, f := range c.SetFields {
		if f.Secret {
			secure.SecureZeroBytes(f.Value)
		}
	}
}

// Folder is a folder, its entries, and those in it and the folders under
// it (Total); "" is the entries in none.
type Folder struct {
	Name           string
	Entries, Total int
}

// Tag is a tag, and how many entries have it.
type Tag struct {
	Name    string
	Entries int
}

// ErrNameTaken is a trash entry restored onto a name another entry has.
var ErrNameTaken = errors.New("another entry has that name")

// Version is one of an entry's earlier secrets, as History lists it: the
// row that names it, whatever number it has as others come and go, and
// when it was replaced (zero when that isn't known).
type Version struct {
	ReplacedAt time.Time
	ID         int64
}

// ErrTrashChanged is an entry chosen from the trash as listed that isn't
// there as it was: put back, deleted, or its id another's now.
var ErrTrashChanged = errors.New("the trash changed meanwhile, so nothing was done: look again")

// ErrHistoryChanged is an earlier secret chosen from a list that another
// command has changed since: it's no longer in the history.
var ErrHistoryChanged = errors.New("its earlier secrets changed meanwhile, so nothing was done: look again, then choose")

// ErrWrongPassword is a password Unlock refused.
var ErrWrongPassword = errors.New("wrong password")

// maxAttempts is how many wrong passwords in a row end the app, as a
// command's prompt allows.
const maxAttempts = 3

// wrongPassword is what the locked screen says after one.
const wrongPassword = "Wrong password, try again."

// Vault is what the app reads, while unlocked.
type Vault interface {
	// Search is the entries matching query, best first, as sesh's search
	// ranks them, every entry for "", and how many entries there are.
	Search(query string) (found []vault.Entry, total int, err error)
	// Secret is k's secret, read as the audit log records: for reading.
	// The caller wipes it.
	Secret(k vault.Key, reading string) ([]byte, error)
	// CodeKey is the TOTP entry k's key, for drawing its codes, which the
	// audit log doesn't record. The caller wipes it.
	CodeKey(k vault.Key) ([]byte, error)
	// Notes is k's notes, or a secure note's text, to show; the audit log
	// records the read. The caller wipes it.
	Notes(k vault.Key) ([]byte, error)
	// SecretFields is k's secret fields with their values, to reveal; the
	// audit log records the read. The caller wipes them.
	SecretFields(k vault.Key) ([]vault.Field, error)
	// Check says whether the vault can still be read, without counting as
	// a use of it (ErrLocked when it must be unlocked again), and whether
	// another command may have changed it since the last Check.
	Check() (changed bool, err error)
	// KeepAlive says the vault is still in use, so the agent doesn't lock
	// it for being idle.
	KeepAlive() error
	// Field is k's secret field name's value, to copy or show; the audit log
	// records the read. The caller wipes it.
	Field(k vault.Key, name string) ([]byte, error)
	// History is k's earlier secrets, the newest first: version 2 is the
	// first.
	History(k vault.Key) ([]Version, error)
	// ReadVersion is k's earlier secret v, to copy (ErrHistoryChanged when
	// it's no longer in the history); the audit log
	// records the read. The caller wipes it.
	ReadVersion(k vault.Key, v Version) ([]byte, error)
	// RestoreVersion makes k's earlier secret v its secret again; the one
	// it replaces is kept. ErrHistoryChanged when v is no longer in the
	// history.
	RestoreVersion(k vault.Key, v Version) error
	// Delete moves k to the trash.
	Delete(k vault.Key) error
	// Trash is the trash's entries, the newest first.
	Trash() ([]Trashed, error)
	// RestoreFromTrash puts the trash's entry t, as Trash listed it, back,
	// under its own name, or as the entry as names when it isn't zero, and
	// says the name it has. ErrNameTaken when another entry has that name;
	// ErrTrashChanged when t isn't in the trash as it was listed.
	RestoreFromTrash(t *Trashed, as vault.Key) (vault.Key, error)
	// RemoveFromTrash deletes the trash's entries listed for good, all or
	// none, and says how many; ErrTrashChanged when one isn't in the trash
	// as it was listed.
	RemoveFromTrash(listed ...Trashed) (int, error)
	// ForgetVersion deletes k's earlier secret v for good; the versions
	// after it move up a number. ErrHistoryChanged as for RestoreVersion.
	ForgetVersion(k vault.Key, v Version) error
	// AuditLog is the newest limit events of the vault's audit log.
	AuditLog(limit int) (AuditLog, error)
	// PruneAudit deletes the audit log's events older than days (0: every
	// one), as sesh audit prune does, and says what it did.
	PruneAudit(days int) (string, error)
	// Health checks the passwords and API keys, as sesh health does: weak,
	// reused, and not changed in oldAfter (0 doesn't check). Reading them
	// is one audit event.
	Health(now time.Time, oldAfter time.Duration) (health.Report, error)
	// Checks runs sesh doctor's checks on the vault, open as it is.
	Checks() (Checks, error)
	// Filing is the folders, with the folders above them, and the tags the
	// vault's entries have, each with how many entries are in it.
	Filing() ([]Folder, []Tag, error)
	// MoveToFolder puts the entries keys name in folder ("" takes them
	// out of theirs), and says how many moved.
	MoveToFolder(keys []vault.Key, folder string) (int, error)
	// AddTag and RemoveTag tag the entries keys name, or take the tag off
	// them, and say how many changed.
	AddTag(keys []vault.Key, tag string) (int, error)
	RemoveTag(keys []vault.Key, tag string) (int, error)
	// DeleteMany moves the entries keys name to the trash, together.
	DeleteMany(keys []vault.Key) error
	// Purge deletes the entries keys name for good, together, skipping
	// the trash.
	Purge(keys []vault.Key) error
	// RenameFolder and RenameTag rename a folder (with the folders under
	// it) or a tag on every entry, and say how many entries changed, and
	// whether the new name was in use already, so the two merged.
	RenameFolder(from, to string) (n int, merged bool, err error)
	RenameTag(from, to string) (n int, merged bool, err error)
	// Save adds an entry (c.Key zero) or changes one, and says the name
	// it has after. ErrNameTaken when the name is another entry's.
	Save(c *Change) (vault.Key, error)
	// Export writes an encrypted export of the entries only allows (every
	// one, when it's zero) to the file to names, with password, which it
	// wipes; a file there is replaced only when replace (ErrExists
	// otherwise). It says what it wrote; none matching is an error, said
	// before the file is touched.
	Export(to string, password []byte, replace bool, only ExportOnly) (string, error)
	// StartImport reads files from source ("bitwarden", "sesh", …) for an
	// import, as sesh import does; password is an export's own, nil until
	// one is asked for with NeedsPassword. The caller closes what it gives.
	StartImport(source string, files []string, password []byte) (Importer, error)
	Close() error
}

// Importer is an import read: planned against the vault, as often as
// what's done with entries the vault has changes, then applied.
type Importer interface {
	// Plan sorts the import's entries against the vault: onConflict is
	// "skip" or "overwrite" for those the vault has, "" for neither yet.
	Plan(onConflict string) (ImportPlan, error)
	// Apply writes the last plan's entries, and says what it did.
	Apply() (string, error)
	// Close wipes what the import read.
	Close()
}

// ImportPlan is what an import would do: said as sesh import says it, the
// entries it writes, and those the vault has already.
type ImportPlan struct {
	Summary string
	// After is what to do once the import is done (delete a plain
	// export), said even when there's nothing to import.
	After          string
	Count, Clashes int
}

// ErrNeedsPassword is an import's export protected by a password, which
// is asked for: NeedsPassword names the export.
var ErrNeedsPassword = errors.New("needs a password")

// NeedsPassword is ErrNeedsPassword, naming the export ("Bitwarden
// export").
func NeedsPassword(what string) error { return &needsPasswordError{what: what} }

type needsPasswordError struct{ what string }

func (e *needsPasswordError) Error() string        { return "the " + e.what + " is protected by a password" }
func (e *needsPasswordError) Is(target error) bool { return target == ErrNeedsPassword }

// Options are what the app works with.
type Options struct {
	Vault Vault
	// Unlock opens the vault again with password, which it wipes;
	// ErrWrongPassword when it's wrong.
	Unlock func(password []byte) (Vault, error)
	// TouchID opens the vault again with a fingerprint; nil when it's
	// never offered. TouchIDOn says whether it's on now.
	TouchID func() (Vault, error)
	// Copy puts text on the clipboard, cleared after ClearAfter.
	Copy func(text string) error
	// OpenURL opens an entry's URL in the browser.
	OpenURL func(url string) error
	// LockAgent locks sesh's agent, for "lock now"; nil when there's none
	// to lock.
	LockAgent func() error
	// EditNotes opens notes in the user's editor and returns them as
	// saved; nil when there's none.
	EditNotes func([]byte) ([]byte, error)
	// IsWeak says whether a secret typed is easy to guess.
	IsWeak func([]byte) bool
	// Generate makes a new password of length characters: with symbols,
	// or letters and digits only. It refuses a length sesh doesn't make.
	Generate func(length int, symbols bool) ([]byte, error)
	// Passphrase makes a new passphrase of words from the EFF's long
	// list, joined by separator, each capitalized or not; nil where the
	// app makes only random characters. It refuses what sesh doesn't make.
	Passphrase func(words int, separator string, capitalize bool) ([]byte, error)
	// ScanQR reads a TOTP entry's link from a QR code on screen, where
	// the area with it is selected; nil when it can't be done here. The
	// caller wipes the link.
	ScanQR func() (ScannedQR, error)
	// ReadQRImage reads a TOTP entry's link from the QR code in the image
	// file at path (a full path, or from ~/); nil when it can't be done
	// here. The caller wipes the link.
	ReadQRImage func(path string) (ScannedQR, error)
	// ReadFile reads the file at the path typed (a full path, or from ~/)
	// for a file entry: its content, which the caller wipes, and its name;
	// nil where files can't be read here.
	ReadFile func(typed string) (content []byte, name string, err error)
	// SaveFile writes a file entry's content to the path typed, readable
	// only by its owner, refusing a file already there; it says where.
	SaveFile func(typed string, content []byte) (string, error)
	Now      func() time.Time
	// Settings are the config settings, for the settings panel; nil when
	// there's none to show. SetSetting writes one to the config file (""
	// takes it out) and says what the app now uses.
	Settings   func() ([]Setting, error)
	SetSetting func(key, value string) (Live, error)
	// ChangePassword changes the master password from current to next,
	// which it wipes, and opens the vault again with next; an error means
	// nothing changed. nil: it isn't offered.
	ChangePassword func(current, next []byte) (Changed, error)
	// PasswordChangeNote, when set, is said under the form changing the
	// master password: what the change does to syncing, or "".
	PasswordChangeNote func() string
	// Sync syncs the vault v with its sync folder, asking nothing, for
	// how's reason, and says what it did, line by line (a warning or a
	// problem starting ⚠️ or ❌); nothing when nothing moved. Syncing says
	// whether the vault syncs now. nil: the app doesn't sync.
	Sync    func(v Vault, how SyncHow) []string
	Syncing func() bool
	// RenewBackups deletes the vault's backups and makes a fresh one, and
	// says so.
	RenewBackups func() (string, error)
	// Recovery says the vault's recovery key's state; nil: the recovery
	// key isn't offered. NewRecovery makes one, and RemoveRecovery
	// removes it.
	Recovery       func() (Recovery, error)
	NewRecovery    func() (*NewRecovery, error)
	RemoveRecovery func() (Done, error)
	// TouchIDState says Touch ID unlock's state; nil: it isn't offered.
	// SetTouchID turns it on or off, and says so; takeOther takes it from
	// another vault's file, which it otherwise refuses with ErrRefused.
	TouchIDState func() (TouchID, error)
	SetTouchID   func(on, takeOther bool) (string, error)
	// Backups lists the vault's backups; nil: they aren't offered. BackUp
	// makes one: in the backups folder, or at to, replacing a file there
	// only when replace (ErrExists otherwise). DeleteBackup deletes one.
	// PlanRestore says what restoring the vault from one does, and Restore
	// does it, saying what it did.
	Backups      func() (Backups, error)
	BackUp       func(to string, replace bool) (string, error)
	DeleteBackup func(path string) (string, error)
	PlanRestore  func(path string) (string, error)
	Restore      func(path string) (string, error)
	// TouchIDOn says whether Touch ID unlock is on now, for the locked
	// screen; nil: TouchID being there says so.
	TouchIDOn  func() bool
	ClearAfter time.Duration
	// OldAfter is how long a secret can go unchanged before the health
	// report calls it old; 0 doesn't check.
	OldAfter time.Duration
	// IdleTimeout locks after this long without a key pressed, and
	// MaxLifetime this long after the app unlocked, as the agent does; 0
	// never.
	IdleTimeout, MaxLifetime time.Duration
}

// Model is the app. Its methods take a pointer: the one Model is the
// program's, and Close is called on it after the program ends.
type Model struct {
	lastKey, unlockedAt time.Time
	// lastPull and lastPush are when the app last synced to take changes
	// and looked for its own to send; lastSynced, when a sync last
	// finished (syncing says one is under way).
	lastPull, lastPush, lastSynced time.Time
	statusUntil                    time.Time
	lastKeepAlive                  time.Time
	clipUntil                      time.Time // when the clipboard clears what was copied

	quitErr error
	// afterword is said once the app has ended.
	afterword string
	// importing is the import being previewed; importAsk shows its form's
	// password input, when the export asks for one, and importName says
	// where it's from.
	importing  *importing
	importAsk  func()
	importName string

	v *gate // nil while locked

	ov   *overlay // the panel over the app, nil when none
	form *form    // the form over the app, nil when none

	// shut are gates locking closed, which Close waits for.
	shut []*gate

	// keys are TOTP keys held for drawing codes, wiped on lock and exit;
	// pending are being read, and failed couldn't be. codes are the codes
	// shown, each made once a period.
	failed  map[vault.Key]bool
	keys    map[vault.Key][]byte
	pending map[vault.Key]bool
	codes   map[vault.Key]shownCode

	// notes are entries' notes, or secure notes' text, held while
	// unlocked to show them, wiped on lock and exit; notesPending are
	// being read, and notesFailed couldn't be, saying why.
	notes        map[vault.Key][]byte
	notesPending map[vault.Key]bool
	notesFailed  map[vault.Key]string
	shown        *revealed // secrets revealed with Tab
	selKey       vault.Key // the selected entry, as last seen
	editing      vault.Key // an entry the health report is to open the form of, once listed
	// wraps are notes and revealed values wrapped to the pane, by what
	// they are, so they're wrapped once rather than each time it's drawn.
	wraps map[string]wrapped

	// every is the clock, a tick each whole second; tests replace it.
	every func() tea.Cmd

	lockedWhy string // why it's locked, while it is
	status    string
	password  []byte // typed on the locked screen

	// found are the entries the search found, and rows those of them the
	// sidebar's filter lets through, as listed.
	found, rows []vault.Entry

	// The sidebar's rows, from the folders and tags the vault has; marked
	// are entries marked with Space, for acting on together.
	folders []Folder
	tags    []Tag
	side    []sideRow
	marked  map[vault.Key]bool

	input textinput.Model // the search
	spin  spinner.Model   // while unlocking
	th    theme

	opts   Options
	filter sideRow // the sidebar's row filtering the list

	// epoch counts unlocks: a message from before the last lock or unlock
	// is dropped. searches counts searches: only the latest's results are
	// shown.
	epoch, searches int
	filings         int // reads of the folders and tags: only the latest's is kept

	width, height int
	previewTop    int // the preview's first line shown, when it scrolls
	total         int // entries in the vault
	wrong         int
	top, sel      int
	sideSel       int // the sidebar's row its cursor is on
	sideTop       int // the sidebar's first row shown
	focus         focus
	unlocking     bool
	revealing     bool // a reveal asked for hasn't come back yet
	// inEditor is the notes editor having the terminal: its time is use, so
	// the idle lock waits for it. Ticks due meanwhile arrive before it ends.
	inEditor bool
	checking bool // sesh doctor's checks are running
	// changing is the master password being changed: the vault open stops
	// opening once it commits, so it isn't read meanwhile.
	changing  bool
	quitAfter bool // Ctrl-C was pressed while changing: it quits once that's done
	// scanning says a QR code is being captured from the screen: quitting
	// waits for it to end, so the capture, and its picture of the code,
	// don't outlast the app.
	scanning bool
	// touchOn is Touch ID unlock on, as last read: at the lock, after a
	// fingerprint fails, on Enter with nothing typed while it was off, and
	// when turning it on or off ends while locked.
	touchOn   bool
	statusBad bool // the status is something that went wrong
	showHelp  bool
	dark      bool
	syncing   bool
}

// shownCode is a TOTP code, and the period it's for.
type shownCode struct {
	text   string
	period int64
}

// New is the app, unlocked with opts.Vault.
func New(opts *Options) *Model {
	now := opts.Now()
	m := &Model{
		opts: *opts, v: newGate(opts.Vault),
		keys: map[vault.Key][]byte{}, pending: map[vault.Key]bool{}, failed: map[vault.Key]bool{},
		codes: map[vault.Key]shownCode{},
		notes: map[vault.Key][]byte{}, notesPending: map[vault.Key]bool{}, notesFailed: map[vault.Key]string{},
		wraps:   map[string]wrapped{},
		marked:  map[vault.Key]bool{},
		filter:  sideRow{kind: sideAll, label: "All"},
		lastKey: now, unlockedAt: now, lastKeepAlive: now,
		width: 80, height: 24,
		every: tick,
		input: searchInput(),
		spin:  spinner.New(spinner.WithSpinner(spinner.MiniDot)),
		dark:  true,
	}
	m.restyle()
	return m
}

// searchInput is the search box. It doesn't paste from the clipboard
// itself (a secret just copied would show in it; the terminal's own
// paste still works), and the arrows move the list, not suggestions.
func searchInput() textinput.Model {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = "Search names, usernames, sites…"
	in.KeyMap.Paste.SetEnabled(false)
	in.KeyMap.AcceptSuggestion.SetEnabled(false)
	in.KeyMap.NextSuggestion.SetEnabled(false)
	in.KeyMap.PrevSuggestion.SetEnabled(false)
	in.Focus()
	return in
}

// restyle styles the app for a dark terminal or a light one.
func (m *Model) restyle() {
	m.th = newTheme(m.dark)
	s := textinput.DefaultStyles(m.dark)
	s.Focused.Text = m.th.style()
	s.Focused.Placeholder = m.th.dimmed()
	s.Cursor.Color = m.th.accent
	s.Cursor.Blink = false
	m.input.SetStyles(s)
	m.spin.Style = m.th.accented()
}

// Err is why the app ended, when it wasn't asked to: too many wrong
// passwords, or the vault couldn't be read.
func (m *Model) Err() error { return m.quitErr }

// Afterword is what the app has left to say once it has ended; "" when
// nothing.
func (m *Model) Afterword() string { return m.afterword }

// Close waits for reads still running, wipes what the app holds, and
// closes the vault.
func (m *Model) Close() {
	if m.v != nil {
		m.v.close()
		m.v = nil
	}
	for _, g := range m.shut {
		g.close()
	}
	m.shut = nil
	m.wipe()
	if m.importing != nil {
		// Its plan or apply is done: the vault's reads have been waited for.
		m.importing.im.Close()
		m.importing = nil
	}
	if m.form != nil {
		m.form.wipe()
		m.form = nil
	}
	secure.SecureZeroBytes(m.password)
	m.password = nil
}

// wipe drops the held TOTP keys and the codes made from them, the notes
// held, and secrets revealed.
func (m *Model) wipe() {
	for k, key := range m.keys {
		secure.SecureZeroBytes(key)
		delete(m.keys, k)
	}
	clear(m.pending)
	clear(m.failed)
	clear(m.codes)
	for k, n := range m.notes {
		secure.SecureZeroBytes(n)
		delete(m.notes, k)
	}
	clear(m.notesPending)
	clear(m.notesFailed)
	clear(m.wraps)
	m.hide()
	// A reveal still being read when this runs never comes back.
	m.revealing = false
}

// Messages, each from a command started at an epoch.
type (
	tickMsg    time.Time
	resultsMsg struct {
		err    error
		rows   []vault.Entry
		total  int
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
		bad   bool // what went wrong, not what was done
	}
	checkedMsg struct {
		err error
		// synced is what a sync before the check said, didSync that it
		// ran.
		synced  []string
		epoch   int
		changed bool
		didSync bool
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

// Init starts the search for every entry and the clock, and asks the
// terminal whether it's dark or light.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.reread(), m.every(), tea.RequestBackgroundColor)
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
	q, epoch, n := m.input.Value(), m.epoch, m.searches
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		rows, total, err := v.Search(q)
		return resultsMsg{rows: rows, total: total, err: err, epoch: epoch, search: n}
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
	case gateClosedMsg:
		m.shut = slices.DeleteFunc(m.shut, func(g *gate) bool { return g == msg.g })
		return nil
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.restyle()
		return nil
	case spinner.TickMsg:
		if !m.unlocking {
			return nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return cmd
	case tea.MouseClickMsg:
		m.editing = vault.Key{}
		if m.v == nil || msg.Button != tea.MouseLeft || !m.listShown() || m.ov != nil || m.form != nil {
			return nil
		}
		m.lastKey = m.opts.Now()
		if n, ok := m.sideAt(msg.X, msg.Y); ok {
			m.focusOn(focusSide)
			return tea.Batch(m.pick(n), m.keepAlive())
		}
		if n, ok := m.rowAt(msg.X, msg.Y); ok {
			m.focusOn(focusList)
			m.sel = n
			m.scroll()
			return tea.Batch(m.moved(), m.keepAlive())
		}
		return m.keepAlive()
	case tea.MouseWheelMsg:
		m.editing = vault.Key{}
		if m.v == nil || !m.listShown() || m.ov != nil || m.form != nil {
			return nil
		}
		m.lastKey = m.opts.Now()
		keep := m.keepAlive()
		step := 1
		if msg.Button == tea.MouseWheelUp {
			step = -1
		} else if msg.Button != tea.MouseWheelDown {
			return nil
		}
		if sw := m.sideWidth(); sw > 0 && msg.X <= sw {
			m.sideTop = max(min(m.sideTop+step, len(m.side)-m.listHeight()), 0)
			return keep
		}
		if lw := m.listWidth(); lw < m.mainWidth() && msg.X >= m.listX()+lw {
			m.scrollPreview(3 * step)
			return keep
		}
		m.sel += step
		m.scroll()
		return tea.Batch(m.moved(), keep)
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.scroll()
		m.scrollSide()
		m.showPlan()
		return m.moved()
	case openedMsg:
		if msg.err != nil {
			m.sayBad(msg.err.Error())
		} else {
			m.say("Opened " + msg.url)
		}
		return nil
	case historyMsg, trashMsg, doneMsg, healthMsg:
		return m.actionResult(msg)
	case qrMsg:
		return m.shownQR(&msg)
	case savedFileMsg:
		return m.savedFile(&msg)
	case settingsMsg:
		return m.gotSettings(&msg)
	case checksMsg:
		return m.gotChecks(&msg)
	case auditMsg:
		return m.gotAudit(&msg)
	case scannedMsg:
		return m.scanned(&msg)
	case generatedMsg:
		return m.generated(&msg)
	case changedMsg:
		return m.changed(&msg)
	case newRecoveryMsg:
		return m.showRecovery(&msg)
	case recoveryMsg:
		return m.gotRecovery(&msg)
	case touchIDMsg:
		return m.gotTouchID(&msg)
	case backupsMsg:
		return m.gotBackups(&msg)
	case backedUpMsg:
		return m.backedUp(&msg)
	case restorePlanMsg:
		return m.askRestore(&msg)
	case restoredMsg:
		return m.restored(&msg)
	case exportedMsg:
		return m.exported(&msg)
	case importStartedMsg:
		return m.importStarted(&msg)
	case importPlannedMsg:
		return m.importPlanned(&msg)
	case importedMsg:
		return m.imported(&msg)
	case agentLockedMsg:
		if msg.err != nil && m.v == nil {
			m.lockedWhy = "sesh's agent couldn't be locked (" + msg.err.Error() + "). Lock it with: sesh agent lock"
		}
		return nil
	case savedMsg:
		return m.saved(&msg)
	case editorMsg:
		return m.editedNotes(&msg)
	case fieldValueMsg:
		return m.gotFieldValue(&msg)
	case filingMsg:
		return m.gotFiling(&msg)
	case notesMsg:
		return m.gotNotes(&msg)
	case revealMsg:
		return m.gotReveal(&msg)
	case tea.KeyPressMsg:
		// Enter again while a form waits to open (a double press) waits
		// with it, rather than copying the entry's secret.
		if m.editing != (vault.Key{}) && m.form == nil && m.ov == nil && msg.String() == "enter" {
			return nil
		}
		// A form the health report is waiting to open isn't, once the
		// user does something else.
		m.editing = vault.Key{}
		if m.v == nil {
			return m.lockedKey(msg)
		}
		if m.changing && m.form == nil {
			// The vault is being restored: only Ctrl-C does anything, once
			// that's done.
			if msg.String() == "ctrl+c" {
				m.quitAfter = true
				if p := m.backupsPanel(); p != nil {
					p.busy = "Quitting once the vault is restored…"
				}
			}
			return nil
		}
		if m.form != nil {
			return tea.Batch(m.formKey(msg), m.keepAlive())
		}
		if m.ov != nil {
			return tea.Batch(m.overlayKey(msg), m.keepAlive())
		}
		return tea.Batch(m.key(msg), m.keepAlive())
	case tea.PasteMsg:
		m.editing = vault.Key{}
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
		if m.form != nil {
			return m.formPaste(msg.Content)
		}
		if m.ov != nil {
			return nil // not into the search behind a panel
		}
		m.focusSearch()
		m.input.SetValue(m.input.Value() + text)
		m.input.CursorEnd()
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
		m.found, m.total = msg.rows, msg.total
		if len(msg.rows) == msg.total {
			// Every entry is here: a mark on one that's gone goes too.
			for k := range m.marked {
				if !slices.ContainsFunc(m.found, func(e vault.Entry) bool { return e.Key == k }) {
					delete(m.marked, k)
				}
			}
		}
		// The list may have changed order under the selection: it stays
		// on the entry, not the row, so Enter copies what was picked.
		m.showFound()
		return tea.Batch(m.moved(), m.editWhenReady(true))
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
			m.sayBad("Couldn't copy it: " + msg.err.Error())
		case msg.bad:
			m.sayBad(msg.what)
		default:
			m.say(msg.what)
			if m.opts.ClearAfter > 0 {
				m.clipUntil = m.opts.Now().Add(m.opts.ClearAfter)
			}
		}
		return nil
	case checkedMsg:
		if msg.didSync {
			m.syncing = false
		}
		if msg.epoch != m.epoch || m.v == nil {
			return nil
		}
		if msg.err != nil {
			return m.failure(msg.err)
		}
		if msg.didSync {
			m.lastSynced = m.opts.Now()
			m.saySynced(msg.synced)
		}
		if msg.changed {
			// Entries may have changed, keys with them: read again. A
			// panel open on what they were is closed, not left to act on
			// what they are now.
			m.wipe()
			if m.importing != nil && m.importing.applying {
				// The import being written changes the vault: its panel
				// stays, to say what it did.
				return m.reread()
			}
			if m.ov != nil {
				m.ov = nil
				if msg.didSync {
					m.sayBad("A sync took changes from another computer; open the actions again.")
				} else {
					m.sayBad("Another command changed the vault; open the actions again.")
				}
			}
			return tea.Batch(m.endImport(), m.reread())
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
			// A fingerprint that failed may have turned Touch ID unlock off
			// (fingerprints changed, or out of date).
			m.touchOn = m.touchIDOn()
			if errors.Is(msg.err, ErrWrongPassword) {
				m.wrong++
				if m.wrong >= maxAttempts {
					m.quitErr = errors.New("wrong master password (after 3 attempts)")
					return tea.Quit
				}
				m.lockedWhy = wrongPassword
				return nil
			}
			m.lockedWhy = msg.err.Error()
			return nil
		}
		m.v, m.wrong, m.lockedWhy = newGate(msg.v), 0, ""
		m.epoch++
		now := m.opts.Now()
		m.lastKey, m.unlockedAt, m.lastKeepAlive = now, now, now
		// Unlocked again: it takes what changed meanwhile at once.
		m.lastPull = time.Time{}
		return m.reread()
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
	if m.shown != nil && !now.Before(m.shown.until) {
		m.hide()
	}
	if ov := m.ov; ov != nil && ov.kind == panelQR && !ov.until.IsZero() && !now.Before(ov.until) {
		m.ov = ov.back
		m.say("The QR code closed after " + spoken(revealFor) + ": q shows it again")
	}
	if m.changing {
		return m.every()
	}
	switch {
	case m.opts.IdleTimeout > 0 && !m.inEditor && since(now, m.lastKey) >= m.opts.IdleTimeout:
		return tea.Batch(m.every(), m.lock("No use for "+spoken(m.opts.IdleTimeout)+"."))
	case m.opts.MaxLifetime > 0 && since(now, m.unlockedAt) >= m.opts.MaxLifetime:
		return tea.Batch(m.every(), m.lock("It's been "+spoken(m.opts.MaxLifetime)+" since it was unlocked."))
	}
	how, sync := m.syncDue(now)
	m.syncing = m.syncing || sync
	return tea.Batch(m.every(), m.checkAfter(how, sync))
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
	if m.v == nil || m.changing || since(now, m.lastKeepAlive) < every {
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

// lock wipes what the app holds and shows the locked screen, saying why;
// the vault is closed once the reads still running end.
func (m *Model) lock(why string) tea.Cmd {
	var closing tea.Cmd
	if m.v != nil {
		closing = m.v.shut()
		m.shut = append(m.shut, m.v)
		m.v = nil
	}
	m.wipe()
	m.epoch++
	m.found, m.rows, m.sel, m.top = nil, nil, 0, 0
	m.checking = false
	m.editing = vault.Key{}
	clear(m.marked)
	m.folders, m.tags, m.side, m.sideSel, m.sideTop = nil, nil, nil, 0, 0
	m.filter = sideRow{kind: sideAll, label: "All"}
	m.focusSearch()
	m.ov = nil
	if m.form != nil {
		if m.form.lost != nil {
			if lost := m.form.lost(); lost != "" {
				why += " " + lost
			}
		}
		m.form.wipe()
		m.form = nil
	}
	m.status = ""
	if m.importing != nil && m.importing.applying {
		why += " An import was being written: it carried on to the end, or stopped where it failed; look at the entries to see what it imported."
	}
	ended := m.endImport()
	m.importAsk = nil
	m.lockedWhy = why
	m.touchOn = m.touchIDOn()
	if m.quitAfter {
		// Ctrl-C waited for what the lock cut off: it quits now, saying
		// why, or, during a scan, once the capture ends (see scanned).
		m.afterword = why
		if m.scanning {
			return tea.Batch(closing, ended)
		}
		return tea.Batch(closing, ended, tea.Quit)
	}
	return tea.Batch(closing, ended)
}

// say shows what was done for a few seconds.
func (m *Model) say(what string) {
	m.status, m.statusBad = what, false
	m.statusUntil = m.opts.Now().Add(5 * time.Second)
}

// sayBad shows what went wrong for a few seconds.
func (m *Model) sayBad(what string) {
	m.say(what)
	m.statusBad = true
}
