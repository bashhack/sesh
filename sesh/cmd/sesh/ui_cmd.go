package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/health"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

const uiUsage = `Usage:
  sesh ui    Search every entry; Enter copies its secret, or its TOTP code

Type to search, as sesh search does; ↑ and ↓ move; Enter copies, and
the clipboard clears after clipboard_timeout; Esc clears the search, or
quits. TOTP entries show their code and the seconds it has left.

It locks after the agent's idle timeout (agent.idle_timeout) without a key
pressed, or when the agent locks, and asks for the master password again.
Quitting locks sesh too, unless ui.lock_on_quit is false.`

// runUI is sesh ui: the search screen.
func runUI(app *App, args []string) error {
	if len(args) > 0 {
		if isHelp(args[0]) {
			_, err := fmt.Fprintln(app.Stdout, uiUsage)
			return err
		}
		return fmt.Errorf("sesh ui takes no arguments, got %q", strings.Join(args, " "))
	}
	if app.StdinIsTerminal == nil || !app.StdinIsTerminal() || !uiStdoutIsTerminal(app.Stdout) {
		return errors.New("sesh ui needs a terminal; to search from a script, use: sesh search <words>")
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	if err := requireVault(cfg.DBPath.Value, "there's no vault yet: sesh add creates it with your first entry (sesh init first chooses where it lives)"); err != nil {
		return err
	}
	// The first unlock is the usual prompt, before the app draws.
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	opts := uiOptions(app, cfg, newUIVault(store))
	m := tui.New(&opts)
	// Last, once the app has let the vault go and what it held back is
	// written: ui.lock_on_quit, as the settings are when it ends, so a
	// change made in the app counts.
	defer func() {
		if said := lockOnQuit(); said != "" {
			fmt.Fprintln(app.Stderr, said) //nolint:errcheck // best effort, on the way out
		}
	}()
	// What's written to stderr while the app draws (a warning while it
	// unlocks again, say) would land on its screen: it's held, and
	// written once the app has ended.
	restore := holdStderr()
	defer func() {
		m.Close()
		restore()
	}()
	p := tea.NewProgram(m, append([]tea.ProgramOption{tea.WithInput(app.Stdin), tea.WithOutput(app.Stdout)}, uiProgramOptions...)...)
	// The terminal closed: the app ends as when it's quit, so what it's
	// writing (an export) is finished, or its file removed, first.
	hup, done := make(chan os.Signal, 1), make(chan struct{})
	signal.Notify(hup, syscall.SIGHUP)
	defer func() {
		signal.Stop(hup)
		close(done)
	}()
	go func() {
		select {
		case <-hup:
			p.Quit()
		case <-done:
		}
	}()
	_, err = p.Run()
	if err != nil {
		return fmt.Errorf("sesh ui: %w", err)
	}
	if said := m.Afterword(); said != "" {
		if _, err := fmt.Fprintln(app.Stderr, said); err != nil {
			return err
		}
	}
	return m.Err()
}

// lockOnQuit locks sesh's agent when ui.lock_on_quit is on, and says so,
// or why it couldn't; "" when it's off.
func lockOnQuit() string {
	cfg, err := settings()
	switch {
	case err != nil:
		return "sesh may still be unlocked: ui.lock_on_quit couldn't be read (" + err.Error() + "); run sesh agent lock"
	case !cfg.UILockOnQuit.Value:
		return ""
	}
	conn, err := agent.DialExisting()
	if agent.IsNotRunning(err) {
		// Nothing holds the vault unlocked.
		return ""
	}
	if err == nil {
		defer closeAgentConn(conn)
		err = agent.Lock(conn)
	}
	if err != nil {
		return "sesh is still unlocked: its agent couldn't be locked (" + err.Error() + "); run sesh agent lock"
	}
	return "Locked sesh (ui.lock_on_quit)."
}

// touchIDPlatform is a system with Touch ID: macOS. Tests set it.
var touchIDPlatform = runtime.GOOS == "darwin"

// uiStdoutIsTerminal says whether w is a terminal, which the app draws on;
// tests replace it.
var uiStdoutIsTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// uiProgramOptions are added to the app's; tests set a window size.
var uiProgramOptions []tea.ProgramOption

// holdStderr sends what's written to os.Stderr into a pipe, until the
// function it returns writes it out where it was going.
func holdStderr() (restore func()) {
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	was := os.Stderr
	os.Stderr = w
	var held bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&held, r) //nolint:errcheck,gosec // what's held is best effort
		close(done)
	}()
	return func() {
		os.Stderr = was
		w.Close() //nolint:errcheck,gosec // ends the copy
		<-done
		r.Close()               //nolint:errcheck,gosec // read to the end
		was.Write(held.Bytes()) //nolint:errcheck,gosec // best effort
	}
}

// uiOptions are the app's, with v open.
func uiOptions(app *App, cfg *config.Config, v tui.Vault) tui.Options {
	dbPath := cfg.DBPath.Value
	opts := tui.Options{
		Vault:     v,
		Copy:      app.ClipboardCopy,
		OpenURL:   openURL,
		LockAgent: lockAgent,
		EditNotes: provider.EditNotes,
		IsWeak:    func(pw []byte) bool { return password.IsWeak(pw) },
		Generate: func(length int, symbols bool) ([]byte, error) {
			opts := password.DefaultGenerateOptions()
			opts.Length, opts.Symbols = length, symbols
			return password.GeneratePassword(opts)
		},
		ScanQR:      uiScanQR(),
		ClearAfter:  cfg.ClipboardTimeout.Value,
		IdleTimeout: cfg.AgentIdleTimeout.Value,
		MaxLifetime: cfg.AgentMaxLifetime.Value,
		OldAfter:    time.Duration(cfg.HealthOldAfterDays.Value) * 24 * time.Hour,
		Settings: func() ([]tui.Setting, error) {
			now, err := settings()
			if err != nil {
				return nil, err
			}
			return uiSettings(now), nil
		},
		SetSetting: func(key, value string) (tui.Live, error) {
			if err := config.Set(cfg.Path, key, value); err != nil {
				return tui.Live{}, err
			}
			now, err := settings()
			if err != nil {
				return tui.Live{}, err
			}
			return tui.Live{OldAfter: time.Duration(now.HealthOldAfterDays.Value) * 24 * time.Hour}, nil
		},
		Now: time.Now,
		ChangePassword: func(current, next []byte) (tui.Changed, error) {
			return uiChangePassword(cfg, current, next)
		},
		RenewBackups:   func() (string, error) { return uiRenewBackups(dbPath) },
		Backups:        func() (tui.Backups, error) { return uiBackups(dbPath) },
		BackUp:         func(to string, replace bool) (string, error) { return uiBackUp(dbPath, to, replace) },
		DeleteBackup:   func(path string) (string, error) { return uiDeleteBackup(dbPath, path) },
		PlanRestore:    func(path string) (string, error) { return uiPlanRestore(dbPath, path) },
		Restore:        func(path string) (string, error) { return uiRestore(dbPath, path) },
		Recovery:       func() (tui.Recovery, error) { return uiRecovery(dbPath) },
		NewRecovery:    func() (*tui.NewRecovery, error) { return uiNewRecovery(dbPath) },
		RemoveRecovery: func() (tui.Done, error) { return uiRemoveRecovery(dbPath) },
		Unlock: func(pw []byte) (tui.Vault, error) {
			store, err := reopenWith(cfg, pw)
			if err != nil {
				return nil, err
			}
			return newUIVault(store), nil
		},
	}
	if touchIDPlatform {
		opts.TouchIDState = func() (tui.TouchID, error) {
			t := uiTouchID(dbPath)
			if os.Getenv("SESH_MASTER_PASSWORD") != "" && t.Here {
				t.Here, t.Why = false, "sesh doesn't use it while SESH_MASTER_PASSWORD gives the master password."
				t.Said += " (not used while SESH_MASTER_PASSWORD is set)"
			}
			return t, nil
		}
		opts.SetTouchID = func(on, takeOther bool) (string, error) { return uiSetTouchID(dbPath, on, takeOther) }
	}
	if touchIDPlatform && os.Getenv("SESH_MASTER_PASSWORD") == "" {
		// Offered on the locked screen while it's on, which it can be
		// turned on or off from the app.
		opts.TouchIDOn = func() bool { return touchIDSetUp(dbPath) && !overSSH() }
		opts.TouchID = func() (tui.Vault, error) {
			store, err := reopenWithTouchID(cfg)
			if err != nil {
				return nil, err
			}
			return newUIVault(store), nil
		}
	}
	return opts
}

// reopenWith opens the vault again with the password pw, which it wipes,
// as the first unlock did but without a prompt: one try, through the agent
// unless the master password comes from SESH_MASTER_PASSWORD. The password
// is checked even when the agent is unlocked.
func reopenWith(cfg *config.Config, pw []byte) (*database.Store, error) {
	defer secure.SecureZeroBytes(pw)
	// A vault removed meanwhile isn't made again from a password typed once.
	if err := requireVault(cfg.DBPath.Value, "the vault is gone from "+cfg.DBPath.Value); err != nil {
		return nil, err
	}
	pc := passwordPromptConfig{
		prompt:      func(string) ([]byte, error) { return bytes.Clone(pw), nil },
		fromEnv:     os.Getenv("SESH_MASTER_PASSWORD") != "",
		alwaysCheck: true,
	}.withKDF(cfg.KDF())
	oracle, err := buildKeySourceWith(cfg.DBPath.Value, pc)
	if errors.Is(err, database.ErrWrongPassword) {
		return nil, tui.ErrWrongPassword
	}
	if err != nil {
		return nil, err
	}
	store, err := openStoreWith(cfg.DBPath.Value, oracle)
	if err != nil {
		return nil, err
	}
	keepAsSet(store, cfg)
	return store, nil
}

// touchIDSetUp says whether Touch ID unlock is on for the vault at dbPath.
func touchIDSetUp(dbPath string) bool {
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return false
	}
	f, err := touchid.ReadFile(filepath.Dir(dbPath))
	return err == nil && f.UnlockID == agent.UnlockID(mat.Verify)
}

// reopenWithTouchID opens the vault again with a fingerprint, through the
// agent; why it didn't is the error.
func reopenWithTouchID(cfg *config.Config) (*database.Store, error) {
	dbPath := cfg.DBPath.Value
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return nil, err
	}
	conn, err := agent.EnsureAgent()
	if err != nil {
		return nil, fmt.Errorf("sesh agent unavailable: %w", err)
	}
	id := agent.UnlockID(mat.Verify)
	var said []string
	ok, err := tryTouchID(conn, filepath.Dir(dbPath), id, mat.Verify, true, func(format string, a ...any) {
		said = append(said, fmt.Sprintf(format, a...))
	})
	if !ok {
		closeAgentConn(conn)
		switch {
		case err != nil:
			return nil, err
		case len(said) > 0:
			return nil, errors.New(strings.Join(said, " "))
		}
		return nil, errors.New("Touch ID didn't unlock it; type your master password") //nolint:staticcheck // a sentence the locked screen shows, starting with a name
	}
	store, err := openStoreWith(dbPath, agent.NewOracle(conn, id))
	if err != nil {
		return nil, err
	}
	keepAsSet(store, cfg)
	return store, nil
}

// startBrowser opens a web address; tests replace it.
var startBrowser = func(address string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	cmd := exec.Command(name, address) //nolint:gosec // an http(s) address, checked by openURL
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open %s: %w", address, err)
	}
	go cmd.Wait() //nolint:errcheck // the browser's exit isn't ours to report
	return nil
}

// openURL opens an entry's URL in the browser: an http or https address
// only (a bare host gets https://), so a URL in the vault can't open a
// local file or start another program.
func openURL(address string) error {
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s isn't a web address sesh opens (http or https)", address)
	}
	return startBrowser(u.String())
}

// uiVault is the vault as the app reads it.
type uiVault struct {
	store *database.Store
	mgr   *password.Manager
	// version is the data version Check last saw, and fingerprint the
	// entries' then: a new version (any commit, the audit log's too) is a
	// change only when the fingerprint is new as well.
	mu          sync.Mutex
	version     int64
	fingerprint [sha256.Size]byte
}

func newUIVault(store *database.Store) *uiVault {
	u := &uiVault{store: store, mgr: password.NewManager(store)}
	if v, err := store.DataVersion(); err == nil {
		u.version = v
	}
	if f, err := store.Fingerprint(); err == nil {
		u.fingerprint = f
	}
	return u
}

// Search is every entry for "", the ones read most recently first, or
// the ones sesh's search finds, best first; and how many entries there
// are.
func (u *uiVault) Search(query string) ([]vault.Entry, int, error) {
	all, err := u.store.List(&vault.Filter{})
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(query) == "" {
		// The app's own reads for showing an entry aren't uses of it.
		last, err := u.store.LastReads("in sesh ui, to show", "in sesh ui, to reveal")
		if err != nil {
			return nil, 0, err
		}
		slices.SortStableFunc(all, func(a, b vault.Entry) int {
			return cmp.Compare(last[b.Key.String()], last[a.Key.String()])
		})
		return all, len(all), nil
	}
	found, err := u.mgr.SearchIn(query, &password.ListFilter{})
	if err != nil {
		return nil, 0, err
	}
	byID := make(map[string]int, len(all))
	for i := range all {
		byID[all[i].Key.String()] = i
	}
	out := make([]vault.Entry, 0, len(found))
	for i := range found {
		if j, ok := byID[found[i].ID]; ok {
			out = append(out, all[j])
		}
	}
	return out, len(all), nil
}

func (u *uiVault) Secret(k vault.Key, reading string) ([]byte, error) {
	secret, err := u.store.GetFor(k, reading)
	return secret, uiLocked(err)
}

// Notes is a secure note's text, which is its secret, or another entry's
// notes.
func (u *uiVault) Notes(k vault.Key) ([]byte, error) {
	if k.Kind == vault.KindNote {
		text, err := u.store.GetFor(k, "in sesh ui, to show it")
		return text, uiLocked(err)
	}
	d, err := u.store.Details(k, "in sesh ui, to show its notes")
	if err != nil {
		return nil, uiLocked(err)
	}
	notes := d.Notes
	d.Notes = nil
	d.Zero()
	return notes, nil
}

// SecretFields is k's secret fields, with their values.
func (u *uiVault) SecretFields(k vault.Key) ([]vault.Field, error) {
	d, err := u.store.Details(k, "in sesh ui, to reveal its fields")
	if err != nil {
		return nil, uiLocked(err)
	}
	secure.SecureZeroBytes(d.Notes)
	var out []vault.Field
	for _, f := range d.Fields {
		if f.Secret {
			out = append(out, f)
		} else {
			secure.SecureZeroBytes(f.Value)
		}
	}
	return out, nil
}

// Field is k's secret field name's value.
func (u *uiVault) Field(k vault.Key, name string) ([]byte, error) {
	d, err := u.store.Details(k, "in sesh ui, to copy or show its field "+name)
	if err != nil {
		return nil, uiLocked(err)
	}
	defer d.Zero()
	for i, f := range d.Fields {
		if f.Name == name {
			value := f.Value
			d.Fields[i].Value = nil
			return value, nil
		}
	}
	return nil, fmt.Errorf("%s has no field %s", k, name)
}

// History is when each of k's earlier secrets was replaced.
func (u *uiVault) History(k vault.Key) ([]tui.Version, error) {
	versions, err := u.store.History(k)
	if err != nil {
		return nil, uiLocked(err)
	}
	out := make([]tui.Version, len(versions))
	for i, v := range versions {
		out[i] = tui.Version{ID: v.ID, ReplacedAt: v.ReplacedAt}
	}
	return out, nil
}

func (u *uiVault) ReadVersion(k vault.Key, v tui.Version) ([]byte, error) {
	secret, err := u.store.ReadVersionOf(k, database.Version{ID: v.ID, ReplacedAt: v.ReplacedAt}, "in sesh ui, to copy it")
	if errors.Is(err, database.ErrVersionGone) {
		return nil, tui.ErrHistoryChanged
	}
	return secret, uiLocked(err)
}

func (u *uiVault) RestoreVersion(k vault.Key, v tui.Version) error {
	_, err := u.store.RestoreVersionOf(k, database.Version{ID: v.ID, ReplacedAt: v.ReplacedAt})
	if errors.Is(err, database.ErrVersionGone) {
		return tui.ErrHistoryChanged
	}
	return u.wrote(err)
}

func (u *uiVault) Delete(k vault.Key) error { return u.wrote(u.store.Delete(k)) }

func (u *uiVault) Health(now time.Time, oldAfter time.Duration) (health.Report, error) {
	c := &health.Checker{Now: now, IsWeak: password.IsWeak, OldAfter: oldAfter}
	if _, err := u.store.EachSecret("Health check, in sesh ui", health.Kinds, c.Add); err != nil {
		return health.Report{}, uiLocked(err)
	}
	return c.Report(), nil
}

func (u *uiVault) Checks() (tui.Checks, error) {
	// On a connection of their own: the checks read every entry, which on
	// the store's one connection would hold up everything else the app does.
	r, err := u.store.Reader()
	if err != nil {
		return tui.Checks{}, uiLocked(err)
	}
	defer r.Close() //nolint:errcheck // read only, but for the audit event
	c, err := doctorReport(nil, r)
	return c, uiLocked(err)
}

func (u *uiVault) Filing() ([]tui.Folder, []tui.Tag, error) {
	fs, err := u.store.Folders()
	if err != nil {
		return nil, nil, uiLocked(err)
	}
	ts, _, err := u.store.Tags()
	if err != nil {
		return nil, nil, uiLocked(err)
	}
	folders := make([]tui.Folder, len(fs))
	for i, f := range fs {
		folders[i] = tui.Folder{Name: f.Name, Entries: f.Entries, Total: f.Total}
	}
	tags := make([]tui.Tag, len(ts))
	for i, t := range ts {
		tags[i] = tui.Tag{Name: t.Name, Entries: t.Entries}
	}
	return folders, tags, nil
}

func (u *uiVault) MoveToFolder(keys []vault.Key, folder string) (int, error) {
	n, err := u.store.MoveToFolder(keys, folder)
	return n, u.wrote(err)
}

func (u *uiVault) AddTag(keys []vault.Key, tag string) (int, error) {
	n, err := u.store.AddTag(keys, tag)
	return n, u.wrote(err)
}

func (u *uiVault) RemoveTag(keys []vault.Key, tag string) (int, error) {
	n, err := u.store.RemoveTag(keys, tag)
	return n, u.wrote(err)
}

func (u *uiVault) DeleteMany(keys []vault.Key) error { return u.wrote(u.store.DeleteMany(keys)) }

func (u *uiVault) Purge(keys []vault.Key) error { return u.wrote(u.store.PurgeMany(keys)) }

func (u *uiVault) RenameFolder(from, to string) (int, bool, error) {
	n, merged, err := u.store.RenameFolder(from, to)
	return n, merged, u.wrote(err)
}

func (u *uiVault) RenameTag(from, to string) (int, bool, error) {
	n, merged, err := u.store.RenameTag(from, to)
	return n, merged, u.wrote(err)
}

func (u *uiVault) Trash() ([]tui.Trashed, error) {
	entries, err := u.store.Trash()
	if err != nil {
		return nil, uiLocked(err)
	}
	out := make([]tui.Trashed, len(entries))
	for i := range entries {
		e := &entries[i]
		out[i] = tui.Trashed{ID: e.ID, Key: e.Key, Folder: e.Folder, DeletedAt: e.DeletedAt}
	}
	return out, nil
}

func (u *uiVault) RestoreFromTrash(t *tui.Trashed, as vault.Key) (vault.Key, error) {
	if err := u.asListed(*t); err != nil {
		return vault.Key{}, err
	}
	r, err := u.store.RestoreFromTrash(t.ID, as)
	if errors.Is(err, database.ErrNotInTrash) {
		return vault.Key{}, tui.ErrTrashChanged
	}
	if errors.Is(err, database.ErrNameTaken) {
		return vault.Key{}, tui.ErrNameTaken
	}
	return r.Key, u.wrote(err)
}

func (u *uiVault) ForgetVersion(k vault.Key, v tui.Version) error {
	err := u.store.ForgetVersionOf(k, database.Version{ID: v.ID, ReplacedAt: v.ReplacedAt})
	if errors.Is(err, database.ErrVersionGone) {
		return tui.ErrHistoryChanged
	}
	return u.wrote(err)
}

func (u *uiVault) PruneAudit(days int) (string, error) {
	said, err := pruneAudit(u.store, days)
	return said, u.wrote(err)
}

// AuditLog is the audit log's newest limit events, said as sesh audit
// says them.
func (u *uiVault) AuditLog(limit int) (tui.AuditLog, error) {
	count, oldest, err := u.store.AuditSummary()
	if err != nil {
		return tui.AuditLog{}, uiLocked(err)
	}
	events, err := u.store.AuditEvents(limit)
	if err != nil {
		return tui.AuditLog{}, uiLocked(err)
	}
	log := tui.AuditLog{Count: count, Oldest: oldest}
	if cfg, err := settings(); err == nil {
		log.Keep = "Nothing is removed automatically (audit.retention_days is 0)."
		if days := cfg.AuditRetentionDays.Value; days > 0 {
			log.Keep = fmt.Sprintf("Events older than %s are removed automatically (audit.retention_days).", dayCount(int64(days)))
		}
	}
	for i := range events {
		kind, what := auditWhat(&events[i])
		if kind != "" {
			what = kind + " " + what
		}
		log.Events = append(log.Events, tui.AuditEvent{When: events[i].CreatedAt, Event: events[i].EventType, What: what})
	}
	return log, nil
}

func (u *uiVault) RemoveFromTrash(listed ...tui.Trashed) (int, error) {
	if err := u.asListed(listed...); err != nil {
		return 0, err
	}
	ids := make([]int64, len(listed))
	for i, t := range listed {
		ids[i] = t.ID
	}
	gone, err := u.store.RemoveFromTrash(ids...)
	if errors.Is(err, database.ErrNotInTrash) {
		return 0, tui.ErrTrashChanged
	}
	return len(gone), u.wrote(err)
}

// asListed is ErrTrashChanged unless each of listed is in the trash as
// the app listed it: by its id, name and when it was deleted, since a
// vault made before trash ids stopped being reused can give a deleted
// one's id to another.
func (u *uiVault) asListed(listed ...tui.Trashed) error {
	now, err := u.store.Trash()
	if err != nil {
		return uiLocked(err)
	}
	for _, t := range listed {
		if !slices.ContainsFunc(now, func(e database.TrashedEntry) bool {
			return e.ID == t.ID && e.Key == t.Key && e.DeletedAt.Equal(t.DeletedAt)
		}) {
			return tui.ErrTrashChanged
		}
	}
	return nil
}

// wrote is err, after the app's own write: the fingerprint is taken
// again, as the write isn't another command's change. Not when another
// command committed since the last Check, though (the store's own commits
// don't move its data version, so a version that moved is theirs): that
// change is left for Check to find.
func (u *uiVault) wrote(err error) error {
	if err != nil {
		return uiLocked(err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if v, verr := u.store.DataVersion(); verr != nil || v != u.version {
		return nil
	}
	if f, ferr := u.store.Fingerprint(); ferr == nil {
		u.fingerprint = f
	}
	return nil
}

// Save adds an entry, or changes one, as the app's form describes it.
func (u *uiVault) Save(c *tui.Change) (vault.Key, error) {
	to, secret := c.To, c.Secret
	var params *totp.Params
	if to.Kind == vault.KindTOTP && len(secret) > 0 {
		key, p, err := readTOTPKey(secret)
		if err != nil {
			return vault.Key{}, err
		}
		defer secure.SecureZeroBytes(key)
		secret, params = key, p
	}
	if c.Key == (vault.Key{}) {
		return to, u.add(c, secret, params)
	}
	if to.Kind == vault.KindTOTP && len(secret) > 0 && params == nil {
		// A key alone is a new enrolment's: its codes are the usual six
		// digits every 30 seconds, whatever the key before it made.
		cur, err := u.store.Lookup(c.Key)
		if err != nil {
			return vault.Key{}, uiLocked(err)
		}
		params = &totp.Params{Issuer: cur.Settings.TOTP.Issuer}
	}
	edit := database.EntryEdit{Secret: secret, Folder: c.Folder, TOTP: params}
	if to != c.Key {
		edit.To = &to
	}
	if c.TagsSet {
		tags := slices.Clone(c.Tags)
		if tags == nil {
			tags = []string{}
		}
		edit.Tags = &tags
	}
	if c.URL != nil || c.SetNotes || len(c.SetFields) > 0 || len(c.RemoveFields) > 0 {
		edit.Details = &vault.DetailsChange{
			URL: c.URL, Notes: c.Notes, SetNotes: c.SetNotes, NotesBase: c.NotesBase, HasNotesBase: c.SetNotes,
			Set: c.SetFields, Remove: c.RemoveFields, RemoveFirst: true,
		}
	}
	// One transaction: a part refused leaves the entry as it was.
	switch _, err := u.store.Edit(c.Key, edit); {
	case err == nil, errors.Is(err, database.ErrNothingToChange):
		return to, u.wrote(nil)
	case errors.Is(err, database.ErrNameTaken):
		return vault.Key{}, fmt.Errorf("%w: %s", tui.ErrNameTaken, to)
	default:
		return vault.Key{}, uiLocked(err)
	}
}

// add stores a new entry, refusing a name another entry has.
func (u *uiVault) add(c *tui.Change, secret []byte, params *totp.Params) error {
	switch err := u.store.Exists(c.To); {
	case err == nil:
		return fmt.Errorf("%w: %s", tui.ErrNameTaken, c.To)
	case !errors.Is(err, vault.ErrNotFound):
		return uiLocked(err)
	}
	ent := vault.Entry{Key: c.To, Tags: c.Tags}
	if c.Folder != nil {
		ent.Folder = *c.Folder
	}
	if params != nil {
		ent.Settings.TOTP = *params
	}
	d := vault.Details{Notes: c.Notes, Fields: c.SetFields}
	if c.URL != nil {
		d.URL = *c.URL
	}
	return u.wrote(u.store.SaveWithDetails(&ent, secret, &d))
}

// readTOTPKey is a TOTP key as typed: a base32 key, or an otpauth:// link
// with its settings.
func readTOTPKey(typed []byte) ([]byte, *totp.Params, error) {
	text := strings.TrimSpace(string(typed))
	if strings.HasPrefix(strings.ToLower(text), "otpauth://") {
		info, err := qrcode.ExtractTOTPFullInfo(text)
		if err != nil {
			return nil, nil, fmt.Errorf("that otpauth:// link can't be read: %w", err)
		}
		key, err := totp.ValidateAndNormalizeSecret(info.Secret)
		if err != nil {
			return nil, nil, fmt.Errorf("that otpauth:// link's key can't be used: %w", err)
		}
		return []byte(key), &totp.Params{Issuer: info.Issuer, Algorithm: info.Algorithm, Digits: info.Digits, Period: info.Period}, nil
	}
	key, err := totp.ValidateAndNormalizeSecret(text)
	if err != nil {
		return nil, nil, fmt.Errorf("that TOTP key can't be used: %w", err)
	}
	return []byte(key), nil, nil
}

// lockAgent locks sesh's agent; none running is nothing to lock.
func lockAgent() error {
	conn, err := agent.DialExisting()
	if agent.IsNotRunning(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer closeAgentConn(conn)
	return agent.Lock(conn)
}

func (u *uiVault) CodeKey(k vault.Key) ([]byte, error) {
	key, err := u.store.CodeKey(k)
	return key, uiLocked(err)
}

// Check says whether the vault can still be read, without counting as a
// use of the key, and whether another command changed its entries since
// it was opened or last checked. Writes that leave them as they were, such
// as another window's audit events, aren't changes.
func (u *uiVault) Check() (bool, error) {
	if err := u.store.CheckUnlocked(); err != nil {
		return false, uiLocked(err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	v, err := u.store.DataVersion()
	if err != nil || v == u.version {
		return false, err
	}
	u.version = v
	f, err := u.store.Fingerprint()
	if err != nil {
		return false, err
	}
	changed := f != u.fingerprint
	u.fingerprint = f
	return changed, nil
}

func (u *uiVault) KeepAlive() error { return uiLocked(u.store.KeepAlive()) }

func (u *uiVault) Close() error { return u.store.Close() }

// uiLocked is err as the app takes it: one meaning the vault must be
// unlocked again is tui.ErrLocked, saying why.
func uiLocked(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, database.ErrVaultKeyChanged):
		return tui.Locked("Another sesh command changed the master password or restored the vault.")
	case agent.Locked(err):
		return tui.Locked("sesh's agent locked the vault.")
	}
	return err
}

// uiSettings are cfg's settings as the app's settings panel lists them.
// uiScanQR reads a TOTP entry's link from a QR code on screen, for the
// add form; nil where the screen can't be captured (macOS's screencapture
// does it), or isn't this terminal's: over SSH it would ask on the Mac's
// own screen. The link is checked as sesh add totp --qr checks it.
func uiScanQR() func() (tui.ScannedQR, error) {
	if runtime.GOOS != "darwin" || overSSH() {
		return nil
	}
	return func() (tui.ScannedQR, error) {
		text, err := captureQRText()
		if err != nil {
			return tui.ScannedQR{}, err
		}
		info, err := qrcode.ExtractTOTPFullInfo(text)
		if err != nil {
			return tui.ScannedQR{}, err
		}
		return tui.ScannedQR{Link: []byte(text), Issuer: info.Issuer, Account: info.Account}, nil
	}
}

// captureQRText is the text of a QR code on screen; tests replace it.
var captureQRText = qrcode.CaptureText

func uiSettings(cfg *config.Config) []tui.Setting {
	var out []tui.Setting
	for _, it := range cfg.List() {
		s := tui.Setting{Key: it.Key, Value: it.Value, Raw: it.Raw, Default: it.Default, Said: it.Said(), Applies: it.Applies, Editable: it.Editable, Switch: it.Switch}
		if it.Source == config.FromEnv || it.Source == config.FromFlag {
			s.Env = it.Origin
		}
		out = append(out, s)
	}
	return out
}
