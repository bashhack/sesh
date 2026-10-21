package tui

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"hash/fnv"
	"image/color"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/health"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// fakeVault holds entries and secrets, finds entries whose name holds the
// query, and records what was read.
type fakeVault struct {
	err        error       // returned by every read when set
	checkErr   error       // returned by Check when set
	healthErr  error       // returned by Health when set
	checks     Checks      // what Checks gives
	unreadable []vault.Key // entries whose secret doesn't decrypt, for Health
	secrets    map[vault.Key]string
	notes      map[vault.Key]string
	fields     map[vault.Key][]vault.Field // secret fields, with values
	history    map[vault.Key][]string      // earlier secrets, the newest first
	replacedAt map[string]time.Time        // when each earlier secret was replaced; by its place when not here
	trash      []Trashed
	trashed    map[int64]vault.Entry
	exported   map[string]bool // files there already, which an export doesn't replace without asking
	importing  *fakeImport     // what StartImport gives
	// importPassword is the export's, which StartImport asks for when set.
	importPassword string
	saves          []Change // what Save was given
	entries        []vault.Entry
	reads          []string // "secret <key> <reading>" or "code <key>"
	exports        []string // "to password replace", each Export asked for
	starts         []string // "source files password", each StartImport asked for
	pruned         []int    // the days each PruneAudit was given
	pruneErr       error    // what PruneAudit says went wrong, after it pruned
	audit          AuditLog // what AuditLog gives
	kept           int      // keep-alives
	closed         bool
	changed        bool
	searched       int
	changes        int // folder and tag changes made
}

func (f *fakeVault) Search(q string) ([]vault.Entry, int, error) {
	f.searched++
	var out []vault.Entry
	for _, e := range f.entries {
		if strings.Contains(e.Key.String(), q) {
			out = append(out, e)
		}
	}
	return out, len(f.entries), nil
}

func (f *fakeVault) Secret(k vault.Key, reading string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reads = append(f.reads, "secret "+k.String()+" "+reading)
	return []byte(f.secrets[k]), nil
}

func (f *fakeVault) Notes(k vault.Key) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reads = append(f.reads, "notes "+k.String())
	if k.Kind == vault.KindNote {
		return []byte(f.secrets[k]), nil
	}
	return []byte(f.notes[k]), nil
}

func (f *fakeVault) SecretFields(k vault.Key) ([]vault.Field, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reads = append(f.reads, "fields "+k.String())
	var out []vault.Field
	for _, fl := range f.fields[k] {
		out = append(out, vault.Field{Name: fl.Name, Value: []byte(string(fl.Value)), Secret: true})
	}
	return out, nil
}

func (f *fakeVault) Field(k vault.Key, name string) ([]byte, error) {
	f.reads = append(f.reads, "field "+k.String()+" "+name)
	for _, fl := range f.fields[k] {
		if fl.Name == name {
			return []byte(string(fl.Value)), nil
		}
	}
	return nil, errors.New("no such field")
}

func (f *fakeVault) History(k vault.Key) ([]Version, error) {
	out := make([]Version, len(f.history[k]))
	for i, s := range f.history[k] {
		out[i] = Version{ID: versionID(s), ReplacedAt: time.Unix(1_700_000_000-int64(i)*86400, 0)}
		if at, ok := f.replacedAt[s]; ok {
			out[i].ReplacedAt = at
		}
	}
	return out, nil
}

// quits says whether cmd, or one it batches, quits the app.
func quits(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	switch msg := cmd().(type) {
	case tea.QuitMsg:
		return true
	case tea.BatchMsg:
		return slices.ContainsFunc(msg, quits)
	}
	return false
}

// versionID is the fake's row for an earlier secret: its own, whatever its place.
func versionID(secret string) int64 {
	h := fnv.New64a()
	h.Write([]byte(secret)) //nolint:errcheck // a hash never fails
	return int64(h.Sum64() >> 1)
}

// numbered is the place (version number) the earlier secret v has in k's history now; ErrHistoryChanged when none.
func (f *fakeVault) numbered(k vault.Key, v Version) (int, error) {
	i := slices.IndexFunc(f.history[k], func(s string) bool { return versionID(s) == v.ID })
	if i < 0 {
		return 0, ErrHistoryChanged
	}
	return i + 2, nil
}

func (f *fakeVault) ReadVersion(k vault.Key, v Version) ([]byte, error) {
	n, err := f.numbered(k, v)
	if err != nil {
		return nil, err
	}
	f.reads = append(f.reads, fmt.Sprintf("version %s %d", k, n))
	return []byte(f.history[k][n-2]), nil
}

func (f *fakeVault) RestoreVersion(k vault.Key, v Version) error {
	n, err := f.numbered(k, v)
	if err != nil {
		return err
	}
	h := f.history[k]
	now := f.secrets[k]
	f.secrets[k] = h[n-2]
	f.history[k] = append([]string{now}, append(append([]string{}, h[:n-2]...), h[n-1:]...)...)
	return nil
}

func (f *fakeVault) Delete(k vault.Key) error {
	for i, e := range f.entries {
		if e.Key == k {
			f.entries = append(f.entries[:i:i], f.entries[i+1:]...)
			id := int64(len(f.trash) + 1)
			f.trash = append(f.trash, Trashed{ID: id, Key: k, DeletedAt: time.Unix(1_700_000_000, 0)})
			if f.trashed == nil {
				f.trashed = map[int64]vault.Entry{}
			}
			f.trashed[id] = e
			return nil
		}
	}
	return errors.New("not found")
}

func (f *fakeVault) Health(now time.Time, oldAfter time.Duration) (health.Report, error) {
	f.reads = append(f.reads, "health")
	if f.healthErr != nil {
		return health.Report{}, f.healthErr
	}
	c := &health.Checker{Now: now, IsWeak: password.IsWeak, OldAfter: oldAfter}
	for i := range f.entries {
		e := &f.entries[i]
		var err error
		if slices.Contains(f.unreadable, e.Key) {
			err = errors.New("doesn't decrypt")
		}
		if err := c.Add(e, []byte(f.secrets[e.Key]), err); err != nil {
			return health.Report{}, err
		}
	}
	return c.Report(), f.err
}

func (f *fakeVault) Checks() (Checks, error) {
	f.reads = append(f.reads, "checks")
	return f.checks, f.err
}

func (f *fakeVault) Filing() ([]Folder, []Tag, error) {
	var folders []Folder
	var tags []Tag
	for _, e := range f.entries {
		// Each folder, and those above it, count the entry in their total.
		for p := e.Folder; ; {
			i := slices.IndexFunc(folders, func(x Folder) bool { return x.Name == p })
			if i < 0 {
				folders = append(folders, Folder{Name: p})
				i = len(folders) - 1
			}
			folders[i].Total++
			if p == e.Folder {
				folders[i].Entries++
			}
			if p == "" || !strings.Contains(p, "/") {
				break
			}
			p = p[:strings.LastIndex(p, "/")]
		}
		for _, t := range e.Tags {
			i := slices.IndexFunc(tags, func(x Tag) bool { return x.Name == t })
			if i < 0 {
				tags = append(tags, Tag{Name: t})
				i = len(tags) - 1
			}
			tags[i].Entries++
		}
	}
	slices.SortFunc(folders, func(a, b Folder) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(tags, func(a, b Tag) int { return strings.Compare(a.Name, b.Name) })
	return folders, tags, f.err
}

// each runs change on the entries keys name, and says how many it changed.
func (f *fakeVault) each(keys []vault.Key, change func(e *vault.Entry) bool) (int, error) {
	// As the store does, an entry not there fails the lot.
	for _, k := range keys {
		if !slices.ContainsFunc(f.entries, func(e vault.Entry) bool { return e.Key == k }) {
			return 0, fmt.Errorf("entry not found: %s", k)
		}
	}
	n := 0
	for i := range f.entries {
		if slices.Contains(keys, f.entries[i].Key) && change(&f.entries[i]) {
			n++
		}
	}
	f.changes++
	return n, f.err
}

func (f *fakeVault) MoveToFolder(keys []vault.Key, folder string) (int, error) {
	return f.each(keys, func(e *vault.Entry) bool { moved := e.Folder != folder; e.Folder = folder; return moved })
}

func (f *fakeVault) AddTag(keys []vault.Key, tag string) (int, error) {
	return f.each(keys, func(e *vault.Entry) bool {
		if slices.Contains(e.Tags, tag) {
			return false
		}
		e.Tags = append(slices.Clone(e.Tags), tag)
		return true
	})
}

func (f *fakeVault) RemoveTag(keys []vault.Key, tag string) (int, error) {
	return f.each(keys, func(e *vault.Entry) bool {
		had := slices.Contains(e.Tags, tag)
		e.Tags = slices.DeleteFunc(slices.Clone(e.Tags), func(t string) bool { return t == tag })
		return had
	})
}

func (f *fakeVault) Purge(keys []vault.Key) error {
	for _, k := range keys {
		if !slices.ContainsFunc(f.entries, func(e vault.Entry) bool { return e.Key == k }) {
			return fmt.Errorf("entry not found: %s", k)
		}
	}
	f.entries = slices.DeleteFunc(f.entries, func(e vault.Entry) bool { return slices.Contains(keys, e.Key) })
	return nil
}

func (f *fakeVault) DeleteMany(keys []vault.Key) error {
	for _, k := range keys {
		if err := f.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeVault) RenameFolder(from, to string) (int, bool, error) {
	f.changes++
	merged := slices.ContainsFunc(f.entries, func(e vault.Entry) bool { return vault.InFolder(e.Folder, to) })
	n := 0
	for i := range f.entries {
		if vault.InFolder(f.entries[i].Folder, from) {
			f.entries[i].Folder = to + strings.TrimPrefix(f.entries[i].Folder, from)
			n++
		}
	}
	return n, merged, f.err
}

func (f *fakeVault) RenameTag(from, to string) (int, bool, error) {
	merged := slices.ContainsFunc(f.entries, func(e vault.Entry) bool { return slices.Contains(e.Tags, to) })
	n := 0
	f.changes++
	for i := range f.entries {
		if j := slices.Index(f.entries[i].Tags, from); j >= 0 {
			f.entries[i].Tags = slices.Clone(f.entries[i].Tags)
			f.entries[i].Tags[j] = to
			n++
		}
	}
	return n, merged, f.err
}

func (f *fakeVault) Trash() ([]Trashed, error) { return slices.Clone(f.trash), nil }

// listed is ErrTrashChanged unless each of ts is in the trash as listed.
func (f *fakeVault) listed(ts ...Trashed) error {
	for _, t := range ts {
		if !slices.Contains(f.trash, t) {
			return ErrTrashChanged
		}
	}
	return nil
}

func (f *fakeVault) RestoreFromTrash(t *Trashed, as vault.Key) (vault.Key, error) {
	if err := f.listed(*t); err != nil {
		return vault.Key{}, err
	}
	id := t.ID
	e := f.trashed[id]
	if as != (vault.Key{}) {
		e.Key = as
	}
	if slices.ContainsFunc(f.entries, func(x vault.Entry) bool { return x.Key == e.Key }) {
		return vault.Key{}, ErrNameTaken
	}
	f.entries = append(f.entries, e)
	f.trash = slices.DeleteFunc(f.trash, func(t Trashed) bool { return t.ID == id })
	return e.Key, nil
}

func (f *fakeVault) ForgetVersion(k vault.Key, v Version) error {
	n, err := f.numbered(k, v)
	if err != nil {
		return err
	}
	h := f.history[k]
	f.history[k] = append(slices.Clone(h[:n-2]), h[n-1:]...)
	return nil
}

func (f *fakeVault) PruneAudit(days int) (string, error) {
	f.pruned = append(f.pruned, days)
	n := len(f.audit.Events)
	f.audit = AuditLog{}
	if f.pruneErr != nil {
		return "", f.pruneErr
	}
	return fmt.Sprintf("Removed all %d events.", n), nil
}

func (f *fakeVault) AuditLog(limit int) (AuditLog, error) {
	log := f.audit
	log.Events = log.Events[:min(limit, len(log.Events))]
	return log, f.err
}

func (f *fakeVault) RemoveFromTrash(listed ...Trashed) (int, error) {
	if err := f.listed(listed...); err != nil {
		return 0, err
	}
	n := len(f.trash)
	f.trash = slices.DeleteFunc(f.trash, func(t Trashed) bool { return slices.Contains(listed, t) })
	return n - len(f.trash), nil
}

func (f *fakeVault) Save(c *Change) (vault.Key, error) {
	if f.err != nil {
		return vault.Key{}, f.err
	}
	saved := *c
	saved.Secret, saved.Notes, saved.NotesBase = bytes.Clone(c.Secret), bytes.Clone(c.Notes), bytes.Clone(c.NotesBase)
	saved.SetFields = nil
	for _, fl := range c.SetFields {
		saved.SetFields = append(saved.SetFields, vault.Field{Name: fl.Name, Value: bytes.Clone(fl.Value), Secret: fl.Secret})
	}
	f.saves = append(f.saves, saved)
	for i, e := range f.entries {
		if e.Key == c.To && c.Key != c.To {
			return vault.Key{}, ErrNameTaken
		}
		if e.Key == c.Key && c.Key != (vault.Key{}) {
			f.entries[i].Key = c.To
			if c.URL != nil {
				f.entries[i].URL = *c.URL
			}
			if c.MFADevice != nil {
				f.entries[i].Settings.AWSMFADevice = *c.MFADevice
			}
			if c.Secret != nil {
				delete(f.secrets, c.Key)
				f.secrets[c.To] = string(c.Secret)
			}
			return c.To, nil
		}
	}
	f.entries = append(f.entries, vault.Entry{Key: c.To})
	f.secrets[c.To] = string(c.Secret)
	return c.To, nil
}

func (f *fakeVault) CodeKey(k vault.Key) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reads = append(f.reads, "code "+k.String())
	return []byte(f.secrets[k]), nil
}

func (f *fakeVault) Check() (bool, error) {
	c := f.changed
	f.changed = false
	return c, f.checkErr
}

func (f *fakeVault) KeepAlive() error { f.kept++; return f.err }

func (f *fakeVault) Export(to string, password []byte, replace bool, only ExportOnly) (string, error) {
	said := fmt.Sprintf("%s %s %v", to, password, replace)
	if only.Kind != "" || only.Folder != "" || len(only.Tags) > 0 {
		said += fmt.Sprintf(" only %q %q %q", only.Kind, only.Folder, only.Tags)
	}
	f.exports = append(f.exports, said)
	if f.err != nil {
		return "", f.err
	}
	if f.exported[to] && !replace {
		return "", Exists(to + " already exists.")
	}
	if f.exported == nil {
		f.exported = map[string]bool{}
	}
	f.exported[to] = true
	return "Exported 3 entries to " + to + ".", nil
}

func (f *fakeVault) Close() error { f.closed = true; return nil }

var (
	github = vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	code   = vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice"}
	gitlab = vault.Key{Kind: vault.KindAPIKey, Service: "gitlab"}
)

const seed = "JBSWY3DPEHPK3PXP"

func newFake() *fakeVault {
	return &fakeVault{
		entries: []vault.Entry{{Key: github, Folder: "work"}, {Key: code, Folder: "work"}, {Key: gitlab}},
		secrets: map[vault.Key]string{github: "gh-pass", code: seed, gitlab: "gl-token"},
	}
}

// app is the app on f at a fixed time, with copies recorded in copied,
// started as the program would start it.
type app struct {
	*Model
	t      *testing.T
	now    time.Time
	copied []string
	quit   bool
}

func newApp(t *testing.T, f *fakeVault, opts Options) *app {
	t.Helper()
	a := &app{t: t, now: time.Unix(1_700_000_005, 0)}
	opts.Vault = f
	opts.Now = func() time.Time { return a.now }
	if opts.Copy == nil {
		opts.Copy = func(s string) error { a.copied = append(a.copied, s); return nil }
	}
	a.Model = New(&opts)
	a.every = func() tea.Cmd { return nil }
	a.run(a.Init())
	return a
}

// run runs cmd and every command the messages it leads to start, in turn.
func (a *app) run(cmd tea.Cmd) {
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := c().(type) {
		case nil:
		case tea.BatchMsg:
			queue = append(queue, msg...)
		case tea.QuitMsg:
			a.quit = true
		default:
			_, next := a.Update(msg)
			queue = append(queue, next)
		}
	}
}

// press sends keys: a name Bubble Tea gives ("enter", "ctrl+c"), or text.
func (a *app) press(keys ...string) {
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "up":
			msg = tea.KeyPressMsg{Code: tea.KeyUp}
		case "backspace":
			msg = tea.KeyPressMsg{Code: tea.KeyBackspace}
		case "ctrl+c":
			msg = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "shift+down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown, Mod: tea.ModShift}
		case "ctrl+k":
			msg = tea.KeyPressMsg{Code: 'k', Mod: tea.ModCtrl}
		case "ctrl+g":
			msg = tea.KeyPressMsg{Code: 'g', Mod: tea.ModCtrl}
		case "ctrl+e":
			msg = tea.KeyPressMsg{Code: 'e', Mod: tea.ModCtrl}
		case "ctrl+r":
			msg = tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl}
		case "ctrl+s":
			msg = tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl}
		case "→":
			msg = tea.KeyPressMsg{Code: tea.KeyRight}
		case "←":
			msg = tea.KeyPressMsg{Code: tea.KeyLeft}
		case "ctrl+u":
			msg = tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl}
		case "space":
			msg = tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
		case "shift+tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
		case "wait": // past the moment a confirmation's y starts to count
			a.now = a.now.Add(time.Second)
			continue
		default:
			for _, r := range k {
				_, cmd := a.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
				a.run(cmd)
			}
			continue
		}
		_, cmd := a.Update(msg)
		a.run(cmd)
	}
}

// tick moves the clock on by d and lets a tick arrive.
func (a *app) tick(d time.Duration) {
	a.now = a.now.Add(d)
	_, cmd := a.Update(tickMsg(a.now))
	a.run(cmd)
}

// screen is what's drawn, without escape codes.
func (a *app) screen() string {
	v := a.View()
	if !v.AltScreen {
		a.t.Error("not drawn on the alternate screen")
	}
	return ansi.Strip(v.Content)
}

// It opens on every entry, the selected one beside them, with the TOTP
// entry's code, read without an audit, and its countdown when selected;
// typing narrows the list.
func TestSearchAndCodes(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	want, err := totp.CodeAt([]byte(seed), totp.Params{}, a.now)
	if err != nil {
		t.Fatal(err)
	}
	s := a.screen()
	for _, w := range []string{"3 entries", "● github", "alice", "◆ gitlab", "◷ github", want[:3] + " " + want[3:], "PASSWORD", "▸ work", "↵  copy", "tab  reveal"} {
		if !strings.Contains(s, w) {
			t.Errorf("screen missing %q:\n%s", w, s)
		}
	}
	if !slices.Equal(f.reads, []string{"code totp/github/alice"}) {
		t.Errorf("reads = %q", f.reads)
	}
	// Selected, the TOTP entry's code is drawn large, counting down; it
	// changes with the clock, and the key isn't read again.
	a.press("down")
	if s := a.screen(); !strings.Contains(s, "TOTP") || !strings.Contains(s, spaced(groupCode(want))) || !strings.Contains(s, " 5s") {
		t.Errorf("the TOTP entry selected:\n%s", s)
	}
	a.tick(10 * time.Second)
	if s := a.screen(); !strings.Contains(s, "25s") || len(f.reads) != 1 {
		t.Errorf("after 10s, reads %q:\n%s", f.reads, s)
	}
	a.press("gitl")
	if s := a.screen(); !strings.Contains(s, "⌕ gitl") || !strings.Contains(s, "1 of 3") || strings.Contains(s, "github") {
		t.Errorf("searching gitl:\n%s", s)
	}
	a.press("x")
	if s := a.screen(); !strings.Contains(s, "Nothing matches.") {
		t.Errorf("no match:\n%s", s)
	}
	a.press("esc")
	if s := a.screen(); !strings.Contains(s, "3 entries") || a.quit {
		t.Errorf("Esc with a search clears it (quit %v):\n%s", a.quit, s)
	}
	a.press("esc")
	if !a.quit {
		t.Error("Esc with no search doesn't quit")
	}
}

// Enter copies the selected entry's secret, or its TOTP code, each a read
// the audit log records.
func TestCopy(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second})
	a.press("enter")
	if !slices.Equal(a.copied, []string{"gh-pass"}) || !strings.Contains(a.screen(), "✓ Copied the password for github (alice) · clears in 30 seconds") {
		t.Errorf("copied %q:\n%s", a.copied, a.screen())
	}
	a.press("down", "enter")
	want, err := totp.CodeAt([]byte(seed), totp.Params{}, a.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.copied) != 2 || a.copied[1] != want || !strings.Contains(a.screen(), "Copied the code for github (alice)") {
		t.Errorf("copied %q, want the code %s:\n%s", a.copied, want, a.screen())
	}
	if !slices.Contains(f.reads, "secret password/github/alice in sesh ui, to copy it") || !slices.Contains(f.reads, "secret totp/github/alice in sesh ui, to copy its code") {
		t.Errorf("reads = %q", f.reads)
	}
	// The message goes after a few seconds.
	a.tick(6 * time.Second)
	if s := a.screen(); strings.Contains(s, "Copied") || !strings.Contains(s, "↵  copy") {
		t.Errorf("after 6s:\n%s", s)
	}
	failing := newApp(t, newFake(), Options{Copy: func(string) error { return errors.New("no clipboard") }})
	failing.press("enter")
	if s := failing.screen(); !strings.Contains(s, "✗ Couldn't copy: no clipboard") || failing.quit {
		t.Errorf("a failed copy:\n%s", s)
	}
}

// Idle past the timeout, it locks: the held key is wiped, the vault
// closed, and no entry shown; the password typed unlocks it again.
func TestIdleLockAndUnlock(t *testing.T) {
	f := newFake()
	var typed string
	again := newFake()
	a := newApp(t, f, Options{
		IdleTimeout: time.Minute,
		Unlock: func(pw []byte) (Vault, error) {
			typed = string(pw)
			if typed != "right" {
				return nil, ErrWrongPassword
			}
			return again, nil
		},
	})
	held := a.keys[code]
	a.tick(30 * time.Second)
	a.press("down") // a key keeps it open
	a.tick(59 * time.Second)
	if a.v == nil {
		t.Fatal("locked before the idle timeout")
	}
	a.tick(time.Second)
	s := a.screen()
	if a.v != nil || !f.closed || !strings.Contains(s, "sesh is locked") || !strings.Contains(s, "No use for 1 minute.") || strings.Contains(s, "github") {
		t.Fatalf("after the idle timeout (closed %v):\n%s", f.closed, s)
	}
	if string(held) != strings.Repeat("\x00", len(seed)) || len(a.keys) != 0 {
		t.Errorf("held key not wiped: %q", held)
	}
	a.press("wrong", "enter")
	if s := a.screen(); typed != "wrong" || !strings.Contains(s, "Wrong password, try again.") || strings.Contains(s, "wrong") {
		t.Errorf("a wrong password (typed %q):\n%s", typed, s)
	}
	a.press("right", "enter")
	if s := a.screen(); (a.v == nil || a.v.v != again) || !strings.Contains(s, "3 entries") || typed != "right" {
		t.Errorf("unlocked again:\n%s", s)
	}
}

// Three wrong passwords end the app.
func TestUnlockAttempts(t *testing.T) {
	a := newApp(t, newFake(), Options{
		MaxLifetime: time.Hour,
		Unlock:      func([]byte) (Vault, error) { return nil, ErrWrongPassword },
	})
	a.tick(time.Hour)
	if s := a.screen(); !strings.Contains(s, "It's been 1 hour since it was unlocked.") {
		t.Fatalf("past the longest unlock:\n%s", s)
	}
	for range 3 {
		a.press("x", "enter")
	}
	if !a.quit || a.Err() == nil || !strings.Contains(a.Err().Error(), "after 3 attempts") {
		t.Errorf("quit %v, err %v", a.quit, a.Err())
	}
}

// A vault that locked under the app, read for a copy or a code, locks it,
// saying why; Enter with nothing typed uses Touch ID when it's set up.
func TestLockedUnderneath(t *testing.T) {
	f := newFake()
	again := newFake()
	a := newApp(t, f, Options{TouchID: func() (Vault, error) { return again, nil }})
	f.err = Locked("The master password changed.")
	a.press("enter")
	s := a.screen()
	if a.v != nil || !strings.Contains(s, "sesh is locked") || !strings.Contains(s, "The master password changed.") || !strings.Contains(s, "Touch ID") || strings.Contains(s, "github") {
		t.Fatalf("locked underneath:\n%s", s)
	}
	a.press("enter")
	if a.v == nil || a.v.v != again {
		t.Errorf("Touch ID didn't unlock:\n%s", a.screen())
	}
}

// A change by another command searches again; a message from before a
// lock, arriving after the next unlock, is dropped.
func TestChangedAndStale(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{Unlock: func([]byte) (Vault, error) { return newFake(), nil }})
	f.entries = append(f.entries, vault.Entry{Kind: vault.KindNote, Service: "wifi"})
	f.changed = true
	a.tick(time.Second)
	if s := a.screen(); !strings.Contains(s, "4 entries") || !strings.Contains(s, "≡ wifi") {
		t.Errorf("after a change:\n%s", s)
	}
	stale := keyMsg{k: code, key: []byte("held"), epoch: a.epoch}
	a.lock("test")
	a.press("pw", "enter")
	if a.v == nil {
		t.Fatal("not unlocked again")
	}
	a.Update(stale)
	if string(a.keys[code]) == "held" || string(stale.key) != "\x00\x00\x00\x00" {
		t.Errorf("a stale key was kept: %q", stale.key)
	}
}

// Ctrl-C quits, and Close wipes and closes.
func TestQuitAndClose(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	held := a.keys[code]
	a.press("ctrl+c")
	if !a.quit {
		t.Fatal("Ctrl-C didn't quit")
	}
	a.Close()
	if !f.closed || string(held) != strings.Repeat("\x00", len(seed)) {
		t.Errorf("Close: closed %v, key %q", f.closed, held)
	}
}

// The agent locking is seen on the next tick, with nothing else read.
func TestLockedSeenOnTick(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	f.checkErr = Locked("sesh's agent locked.")
	a.tick(time.Second)
	if s := a.screen(); a.v != nil || !strings.Contains(s, "sesh's agent locked.") || strings.Contains(s, "github") {
		t.Errorf("after the agent locked:\n%s", s)
	}
}

// Keys pressed keep the agent from idling out: a keep-alive at most once
// in half its timeout.
func TestKeepAlive(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{IdleTimeout: 10 * time.Second})
	a.press("down")
	if f.kept != 0 {
		t.Errorf("a keep-alive right after unlocking: %d", f.kept)
	}
	a.now = a.now.Add(5 * time.Second)
	a.press("down", "up")
	if f.kept != 1 {
		t.Errorf("keep-alives after 5s = %d, want 1", f.kept)
	}
	a.now = a.now.Add(4 * time.Second)
	a.press("down")
	if f.kept != 1 {
		t.Errorf("keep-alives 4s later = %d, want still 1", f.kept)
	}
}

// A key read twice, as when the vault changed while it was read, is kept
// once and the other copy wiped.
func TestKeyReadTwice(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	held := a.keys[code]
	again := []byte(seed)
	a.Update(keyMsg{k: code, key: again, epoch: a.epoch})
	if string(again) != strings.Repeat("\x00", len(seed)) || &a.keys[code][0] != &held[0] {
		t.Errorf("the second read: kept %q, wiped %q", a.keys[code], again)
	}
}

// Closing waits for a copy that's running, so it isn't cut off; a key
// read that finishes after the close is wiped.
func TestCloseWaitsForReads(t *testing.T) {
	release := make(chan struct{})
	copying := make(chan struct{})
	f := newFake()
	a := newApp(t, f, Options{Copy: func(string) error { close(copying); <-release; return nil }})
	cmd := a.copySecret(a.selected())
	go cmd()
	<-copying
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close didn't wait for the copy")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-closed
	if !f.closed {
		t.Error("the vault wasn't closed")
	}

	g := newGate(newFake())
	var key []byte
	msg := g.run(func(v Vault, closed func() bool) tea.Msg {
		var err error
		if key, err = v.CodeKey(code); err != nil {
			t.Error(err)
		}
		g.mu.Lock()
		g.closed = true // as if closed meanwhile
		g.mu.Unlock()
		if closed() {
			secure.SecureZeroBytes(key)
			return nil
		}
		return keyMsg{key: key}
	})
	if msg != nil || string(key) != strings.Repeat("\x00", len(seed)) {
		t.Errorf("a read finishing after the close: %v, key %q", msg, key)
	}
}

// A pasted line's end isn't part of the search or the password.
func TestPasteNewline(t *testing.T) {
	var typed string
	a := newApp(t, newFake(), Options{
		IdleTimeout: time.Minute,
		Unlock:      func(pw []byte) (Vault, error) { typed = string(pw); return newFake(), nil },
	})
	a.Update(tea.PasteMsg{Content: "gitl\n"})
	a.run(a.requery())
	if s := a.screen(); !strings.Contains(s, "⌕ gitl ") || strings.Count(s, "\n") >= a.height {
		t.Errorf("pasted search:\n%s", s)
	}
	a.tick(time.Minute)
	a.Update(tea.PasteMsg{Content: "right\r\n"})
	a.press("enter")
	if typed != "right" {
		t.Errorf("pasted password = %q", typed)
	}
}

// A password outgrowing its array leaves no copy behind.
func TestAppendSecret(t *testing.T) {
	small := make([]byte, 0, 4)
	small = appendSecret(small, "abcd")
	old := small[:cap(small)]
	grown := appendSecret(small, "e")
	if string(grown) != "abcde" || string(old) != "\x00\x00\x00\x00" {
		t.Errorf("grown %q, old %q", grown, old)
	}
}

// slowVault is a fakeVault whose Search waits to be released.
type slowVault struct {
	*fakeVault
	release chan struct{}
}

func (s *slowVault) Search(q string) ([]vault.Entry, int, error) {
	<-s.release
	return s.fakeVault.Search(q)
}

// Locking doesn't wait on a slow read; Close does.
func TestLockDoesNotWait(t *testing.T) {
	f := newFake()
	slow := &slowVault{fakeVault: f, release: make(chan struct{})}
	m := New(&Options{Vault: slow, Now: time.Now, IdleTimeout: time.Minute})
	m.every = func() tea.Cmd { return nil }
	go m.search()()
	time.Sleep(50 * time.Millisecond) // the search is running
	m.lastKey = time.Now().Add(-time.Hour)
	start := time.Now()
	_, cmd := m.Update(tickMsg(time.Now()))
	if d := time.Since(start); d > 500*time.Millisecond || m.v != nil {
		t.Fatalf("locking took %s (locked %v)", d, m.v == nil)
	}
	closed := make(chan struct{})
	go func() { cmd(); m.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("the vault closed before the search ended")
	case <-time.After(100 * time.Millisecond):
	}
	close(slow.release)
	<-closed
	if !f.closed {
		t.Error("the vault wasn't closed")
	}
}

// ? shows the keys with nothing searched, and is searched for otherwise.
func TestHelp(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("?")
	if s := a.screen(); !strings.Contains(s, "clear the search and folder, or quit") || strings.Contains(s, "◆ gitlab") {
		t.Errorf("help:\n%s", s)
	}
	a.press("esc")
	if s := a.screen(); a.quit || !strings.Contains(s, "◆ gitlab") {
		t.Errorf("Esc closes the help (quit %v):\n%s", a.quit, s)
	}
	a.press("git?")
	if s := a.screen(); !strings.Contains(s, "⌕ git?") || strings.Contains(s, "clear the search, or quit") {
		t.Errorf("? in a search:\n%s", s)
	}
}

// A narrow window shows the list alone; a very small one asks for room;
// a light terminal gets the light colours.
func TestLayouts(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	if s := a.screen(); !strings.Contains(s, "● github") || strings.Contains(s, "PASSWORD") || strings.Count(s, "\n") != 19 {
		t.Errorf("60 columns:\n%s", s)
	}
	a.Update(tea.WindowSizeMsg{Width: 30, Height: 8})
	if s := a.screen(); !strings.Contains(s, "needs a bigger window") {
		t.Errorf("30×8:\n%s", s)
	}
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	dark := a.View().Content
	a.Update(tea.BackgroundColorMsg{Color: color.White})
	if light := a.View().Content; a.dark || light == dark || ansi.Strip(light) != ansi.Strip(dark) {
		t.Error("a light terminal kept the dark colours")
	}
}

// The letters matching a search are picked out, ignoring case.
func TestHighlight(t *testing.T) {
	hi := lipgloss.NewStyle().Bold(true)
	plain := lipgloss.NewStyle()
	got := highlight("GitHub", []string{"hub"}, &plain, &hi)
	if ansi.Strip(got) != "GitHub" || !strings.Contains(got, hi.Render("Hub")) {
		t.Errorf("highlight = %q", got)
	}
	if got := highlight("İstanbul", []string{"stan"}, &plain, &hi); ansi.Strip(got) != "İstanbul" || !strings.Contains(got, hi.Render("stan")) {
		t.Errorf("highlight İstanbul = %q", got)
	}
}

// A selected entry's notes and plain fields are shown, the notes read
// once; its password and secret fields only once revealed with Tab, until
// it moves or the time's up.
func TestPreviewNotesAndReveal(t *testing.T) {
	f := newFake()
	f.entries[0].HasNotes = true
	f.entries[0].Fields = []vault.Field{{Name: "pin", Secret: true}, {Name: "email", Value: []byte("a@example.com")}}
	f.notes = map[vault.Key]string{github: "recovery codes\nin the safe"}
	f.fields = map[vault.Key][]vault.Field{github: {{Name: "pin", Value: []byte("4321")}}}
	a := newApp(t, f, Options{})
	s := a.screen()
	for _, w := range []string{"recovery codes", "in the safe", "email     a@example.com", "pin       ••••••••", "password  ••••••••", "tab  reveal"} {
		if !strings.Contains(s, w) {
			t.Errorf("preview missing %q:\n%s", w, s)
		}
	}
	if strings.Contains(s, "gh-pass") || strings.Contains(s, "4321") {
		t.Errorf("a secret shown before Tab:\n%s", s)
	}
	a.press("down", "up")
	if n := strings.Count(strings.Join(f.reads, ","), "notes password/github/alice"); n != 1 {
		t.Errorf("notes read %d times, want once: %q", n, f.reads)
	}
	a.press("tab")
	if s := a.screen(); !strings.Contains(s, "password  gh-pass") || !strings.Contains(s, "pin       4321") || !strings.Contains(s, "tab  hide (30s)") {
		t.Errorf("revealed:\n%s", s)
	}
	if !slices.Contains(f.reads, "secret password/github/alice in sesh ui, to reveal it") || !slices.Contains(f.reads, "fields password/github/alice") {
		t.Errorf("reads = %q", f.reads)
	}
	shown := a.shown.secret
	a.tick(30 * time.Second)
	if s := a.screen(); strings.Contains(s, "gh-pass") || string(shown) != strings.Repeat("\x00", len("gh-pass")) {
		t.Errorf("after 30s, still shown (wiped %q):\n%s", shown, s)
	}
	a.press("tab")
	a.press("down")
	if a.shown != nil {
		t.Error("moving didn't hide what was revealed")
	}
	a.press("up", "tab", "tab")
	if a.shown != nil {
		t.Error("Tab again didn't hide it")
	}
}

// A secure note's text is shown, its control characters as symbols; a
// long note scrolls.
func TestPreviewSecureNote(t *testing.T) {
	f := newFake()
	wifi := vault.Key{Kind: vault.KindNote, Service: "wifi"}
	long := "ssid home\x1b[2Jpassword hunter2"
	for i := range 40 {
		long += fmt.Sprintf("\nline %d", i)
	}
	f.entries = []vault.Entry{{Key: wifi}}
	f.secrets = map[vault.Key]string{wifi: long}
	a := newApp(t, f, Options{})
	s := a.screen()
	if !strings.Contains(s, "ssid home␛[2Jpassword hunter2") || !strings.Contains(s, "shift ↑↓  scroll") || strings.Contains(s, "line 39") {
		t.Errorf("a long note:\n%s", s)
	}
	if strings.Contains(a.View().Content, "\x1b[2J") {
		t.Error("the note's escape code reached the terminal")
	}
	for range 50 {
		a.press("shift+down")
	}
	if s := a.screen(); !strings.Contains(s, "line 39") {
		t.Errorf("scrolled to the end:\n%s", s)
	}
}

// Ctrl-Y copies the username, Ctrl-O opens the URL; the footer counts
// down until the clipboard clears.
func TestUsernameURLAndCountdown(t *testing.T) {
	f := newFake()
	f.entries[0].URL = "github.com"
	var opened string
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second, OpenURL: func(u string) error { opened = u; return nil }})
	a.Update(tea.KeyPressMsg{Code: 'y', Mod: tea.ModCtrl})
	a.run(a.copyUsername(a.selected()))
	if len(a.copied) != 1 || a.copied[0] != "alice" || !strings.Contains(a.screen(), "Copied the username for github (alice)") {
		t.Errorf("copied %q:\n%s", a.copied, a.screen())
	}
	if len(f.reads) != 1 { // only the TOTP key, for its code
		t.Errorf("copying a username read the vault: %q", f.reads)
	}
	a.tick(10 * time.Second)
	if s := a.screen(); !strings.Contains(s, "clipboard clears in 20s") {
		t.Errorf("countdown:\n%s", s)
	}
	a.tick(20 * time.Second)
	if s := a.screen(); strings.Contains(s, "clipboard clears") {
		t.Errorf("countdown after it cleared:\n%s", s)
	}
	a.run(a.openURL(a.selected()))
	if opened != "github.com" || !strings.Contains(a.screen(), "Opened github.com") {
		t.Errorf("opened %q:\n%s", opened, a.screen())
	}
	a.press("down", "down")
	a.run(a.copyUsername(a.selected()))
	if s := a.screen(); !strings.Contains(s, "gitlab has no username") || len(a.copied) != 1 {
		t.Errorf("no username:\n%s", s)
	}
}

// A click selects the row under it; the wheel moves the selection, or
// scrolls the details over the pane.
func TestMouse(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	if a.View().MouseMode != tea.MouseModeCellMotion {
		t.Error("the mouse isn't on")
	}
	_, cmd := a.Update(tea.MouseClickMsg{X: 5, Y: 5, Button: tea.MouseLeft}) // the third row
	a.run(cmd)
	if a.sel != 2 {
		t.Errorf("clicked the third row, selected %d", a.sel)
	}
	_, cmd = a.Update(tea.MouseWheelMsg{X: 5, Y: 5, Button: tea.MouseWheelUp})
	a.run(cmd)
	if a.sel != 1 {
		t.Errorf("wheel up selected %d", a.sel)
	}
	a.Update(tea.MouseClickMsg{X: 5, Y: 20, Button: tea.MouseLeft}) // below the rows
	a.Update(tea.MouseClickMsg{X: 60, Y: 4, Button: tea.MouseLeft}) // the details
	if a.sel != 1 {
		t.Errorf("a click off the rows moved the selection to %d", a.sel)
	}
	a.lock("test")
	if a.View().MouseMode != tea.MouseModeNone {
		t.Error("the mouse is on while locked")
	}
}

// When the list reorders under it, the selection stays on its entry; a
// new search starts from the best match.
func TestSelectionFollowsEntry(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("down")                                                     // totp/github/alice
	f.entries = []vault.Entry{f.entries[1], f.entries[2], f.entries[0]} // it moves to the top
	f.changed = true
	a.tick(time.Second)
	if e := a.selected(); e == nil || e.Key != code {
		t.Errorf("after a reorder, selected %v", e)
	}
	a.press("git")
	if a.sel != 0 {
		t.Errorf("a new search selected row %d", a.sel)
	}
}

// Nothing is done to an entry that isn't on screen: behind the help, or
// in a window too small to draw the list.
func TestNoActionsUnseen(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("?")
	a.press("enter")
	a.Update(tea.MouseClickMsg{X: 5, Y: 5, Button: tea.MouseLeft})
	if len(a.copied) != 0 || a.sel != 0 {
		t.Errorf("behind the help: copied %q, selected %d", a.copied, a.sel)
	}
	a.press("?")
	a.Update(tea.WindowSizeMsg{Width: 30, Height: 8})
	a.press("enter")
	if len(a.copied) != 0 || a.View().MouseMode != tea.MouseModeNone {
		t.Errorf("too small: copied %q, mouse %v", a.copied, a.View().MouseMode)
	}
}

// A second Tab before the first reveal comes back reads nothing more;
// the mouse keeps the agent unlocked as keys do.
func TestRevealOnceAndMouseKeepAlive(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{IdleTimeout: 10 * time.Second})
	first := a.toggleReveal()
	if second := a.toggleReveal(); second != nil {
		t.Error("a second Tab started another reveal")
	}
	a.run(first)
	if n := strings.Count(strings.Join(f.reads, ","), "to reveal it"); n != 1 || a.shown == nil {
		t.Errorf("reveals read %d times (shown %v)", n, a.shown != nil)
	}
	a.now = a.now.Add(6 * time.Second)
	_, cmd := a.Update(tea.MouseWheelMsg{X: 5, Y: 5, Button: tea.MouseWheelDown})
	a.run(cmd)
	if f.kept != 1 {
		t.Errorf("keep-alives after the wheel = %d, want 1", f.kept)
	}
}

// A lock while a reveal is read doesn't leave Tab dead after unlocking.
func TestRevealAfterLockMidRead(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{Unlock: func([]byte) (Vault, error) { return f, nil }})
	pending := a.toggleReveal()
	a.lock("test")
	a.run(pending)
	a.press("pw", "enter")
	a.run(a.toggleReveal())
	if a.shown == nil {
		t.Error("Tab after the re-unlock revealed nothing")
	}
}

// Ctrl-K opens the actions on the selected entry; a key runs one; Esc
// closes it.
func TestActionMenu(t *testing.T) {
	f := newFake()
	f.entries[0].URL = "github.com"
	f.entries[0].Fields = []vault.Field{{Name: "pin", Secret: true}, {Name: "email", Value: []byte("a@example.com")}}
	f.fields = map[vault.Key][]vault.Field{github: {{Name: "pin", Value: []byte("4321")}}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k")
	s := a.screen()
	for _, w := range []string{"github (alice)", "copy a value…", "copy the username", "open the URL", "earlier secrets…", "move to the trash"} {
		if !strings.Contains(s, w) {
			t.Errorf("menu missing %q:\n%s", w, s)
		}
	}
	if strings.Contains(s, "the trash…") || strings.Contains(s, "lock sesh") {
		t.Errorf("sesh's own actions on the entry's menu:\n%s", s)
	}
	a.press("esc")
	if a.ov != nil {
		t.Fatal("Esc didn't close the menu")
	}
	// Copy a value: the secret field is read for it, the plain one isn't.
	a.press("ctrl+k", "f")
	if s := a.screen(); !strings.Contains(s, "pin (secret)") || !strings.Contains(s, "email") {
		t.Errorf("values:\n%s", s)
	}
	a.press("4") // password, username, URL, then pin
	if len(a.copied) != 1 || a.copied[0] != "4321" || !slices.Contains(f.reads, "field password/github/alice pin") {
		t.Errorf("copied %q, reads %q", a.copied, f.reads)
	}
	a.press("ctrl+k", "f", "5")
	if len(a.copied) != 2 || a.copied[1] != "a@example.com" {
		t.Errorf("copied %q", a.copied)
	}
	a.press("ctrl+k", "u")
	if len(a.copied) != 3 || a.copied[2] != "alice" {
		t.Errorf("copied %q", a.copied)
	}
}

// cellBackgrounds is line's characters, the true-colour background code
// ("48;2;r;g;b", or "" for none) each is drawn on, and whether each is bold.
func cellBackgrounds(line string) ([]rune, []string, []bool) {
	var text []rune
	var bgs []string
	var bolds []bool
	bg, bold := "", false
	for rest := line; rest != ""; {
		if strings.HasPrefix(rest, "\x1b[") {
			end := strings.IndexByte(rest, 'm')
			params := strings.Split(rest[2:end], ";")
			for k := 0; k < len(params); k++ {
				switch p := params[k]; {
				case p == "" || p == "0":
					bg, bold = "", false
				case p == "49":
					bg = ""
				case p == "1":
					bold = true
				case p == "22":
					bold = false
				case p == "48" && k+4 < len(params) && params[k+1] == "2":
					bg = strings.Join(params[k:k+5], ";")
					k += 4
				case (p == "38" || p == "58") && k+1 < len(params) && params[k+1] == "2":
					k += 4
				}
			}
			rest = rest[end+1:]
			continue
		}
		c, size := utf8.DecodeRuneInString(rest)
		text = append(text, c)
		bgs = append(bgs, bg)
		bolds = append(bolds, bold)
		rest = rest[size:]
	}
	return text, bgs, bolds
}

// bandCode is the background code the selection's colour is drawn with.
func bandCode(th *theme) string {
	r, g, b, _ := th.selBg.RGBA()
	return fmt.Sprintf("48;2;%d;%d;%d", r>>8, g>>8, b>>8)
}

// A menu's selected row is one band of colour, across the gap between its label and its key.
func TestMenuSelectedRowBand(t *testing.T) {
	a := wideApp(t, newFake())
	a.press("ctrl+g")
	want := bandCode(&a.th)
	for line := range strings.SplitSeq(a.View().Content, "\n") {
		if !strings.Contains(ansi.Strip(line), "add an entry…") {
			continue
		}
		runes, bgs, _ := cellBackgrounds(line)
		from := strings.Index(string(runes), "add an entry…")
		from = utf8.RuneCountInString(string(runes)[:from]) + utf8.RuneCountInString("add an entry…")
		// Up to the key's label, which starts with its own padding space.
		end := from
		for end < len(runes) && runes[end] == ' ' {
			end++
		}
		if end-1-from < 10 {
			t.Fatalf("no gap after the label: %q", line)
		}
		for k := from; k < end-1; k++ {
			if bgs[k] != want {
				t.Fatalf("the gap after the selected row's label isn't in the band, at %d: %q", k, line)
			}
		}
		return
	}
	t.Fatalf("no selected row:\n%s", a.screen())
}

// A selected row whose label has colours of its own (the trash's, a to-do's) stays on the band, and bold, throughout.
func TestSelectedRowStyledLabel(t *testing.T) {
	for _, dark := range []bool{true, false} {
		th := newTheme(dark)
		label := th.accented().Render("→") + " run sesh doctor " + th.dimmed().Render("deleted 3 days ago")
		row := th.selectedRow(label, 40)
		runes, bgs, bolds := cellBackgrounds(row)
		if string(runes) != "▌ → run sesh doctor deleted 3 days ago     " {
			t.Fatalf("dark %v: row %q", dark, string(runes))
		}
		for k, bg := range bgs {
			if bg != bandCode(&th) {
				t.Fatalf("dark %v: %q at %d isn't on the band: %q", dark, runes[k], k, row)
			}
		}
		// The words after the arrow's colour are bold, as the row's are.
		from := slices.Index(runes, 'r')
		for k := from; k < from+len("run sesh doctor"); k++ {
			if !bolds[k] {
				t.Fatalf("dark %v: %q at %d isn't bold: %q", dark, runes[k], k, row)
			}
		}
	}
}

// Ctrl-G opens sesh's own actions from the search, the list or the sidebar; Ctrl-K with no entry to act on does too.
func TestSeshMenu(t *testing.T) {
	a := wideApp(t, newFake())
	want := []string{"add an entry…", "the trash…", "backups…", "import and export…", "health report…", "settings and safety…", "lock sesh"}
	menu := func(how string) {
		t.Helper()
		s := a.screen()
		if a.ov == nil || a.ov.title != "sesh" {
			t.Fatalf("%s: panel %+v", how, a.ov)
		}
		for _, w := range want {
			if !strings.Contains(s, w) {
				t.Errorf("%s: missing %q:\n%s", how, w, s)
			}
		}
		a.press("esc")
	}
	if !strings.Contains(a.screen(), "ctrl+g  sesh") {
		t.Errorf("the footer doesn't say ctrl+g:\n%s", a.screen())
	}
	a.press("ctrl+g")
	menu("from the search")
	a.press("down", "ctrl+g")
	menu("from the list")
	a.press("←")
	if a.focus != focusSide || !strings.Contains(a.screen(), "ctrl+g  sesh") {
		t.Fatalf("not in the sidebar, or its footer doesn't say ctrl+g:\n%s", a.screen())
	}
	a.press("ctrl+g")
	menu("from the sidebar")
	a.press("esc", "zzz", "ctrl+k")
	menu("with nothing matching")
	// Where a terminal keeps Ctrl-G, Ctrl-K's g opens it from an entry, or those marked.
	// Esc from it goes back to the menu it was opened from.
	a.press("ctrl+u", "ctrl+k", "g")
	menu("from the entry's menu")
	if a.ov == nil || a.ov.title != "github (alice)" {
		t.Fatalf("back to %+v", a.ov)
	}
	a.press("esc", "down", "space", "ctrl+k", "g")
	menu("from the marked entries' menu")
	if a.ov == nil || !strings.Contains(a.ov.title, "marked") {
		t.Fatalf("back to %+v", a.ov)
	}
	a.press("esc")
	if !strings.Contains(a.screen(), "ctrl+g  sesh") {
		t.Errorf("the marked entries' footer doesn't say ctrl+g:\n%s", a.screen())
	}
	// Not opened unseen, in a window too small to show it.
	a.Update(tea.WindowSizeMsg{Width: 30, Height: 8})
	a.press("ctrl+g")
	if a.ov != nil {
		t.Errorf("opened in a window too small: %+v", a.ov)
	}
}

// The footer keeps whole hints, leaving out those that don't fit; an empty vault says how to add an entry.
func TestFooterFits(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.Update(tea.WindowSizeMsg{Width: 44, Height: 20})
	lines := strings.Split(a.screen(), "\n")
	foot := lines[len(lines)-2]
	if strings.Contains(foot, "…") || !strings.Contains(foot, "ctrl+g  sesh") {
		t.Errorf("the footer at 44: %q", foot)
	}
	f := newFake()
	f.entries = nil
	b := newApp(t, f, Options{})
	if s := b.screen(); !strings.Contains(s, "The vault is empty.") || !strings.Contains(s, "ctrl+g, then a.") || strings.Contains(s, "entr…") {
		t.Errorf("an empty vault:\n%s", b.screen())
	}
}

// The entry's earlier secrets are listed, copied, and restored after a yes.
func TestActionHistory(t *testing.T) {
	f := newFake()
	f.history = map[vault.Key][]string{github: {"old-1", "old-2"}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "h")
	if s := a.screen(); !strings.Contains(s, "version 2") || !strings.Contains(s, "version 3") {
		t.Fatalf("history:\n%s", s)
	}
	a.press("down", "enter")
	if len(a.copied) != 1 || a.copied[0] != "old-2" || !slices.Contains(f.reads, "version password/github/alice 3") {
		t.Errorf("copied %q, reads %q", a.copied, f.reads)
	}
	a.press("r")
	if s := a.screen(); !strings.Contains(s, "Make version 3 the secret for github (alice) again?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("n")
	if f.secrets[github] != "gh-pass" || a.ov == nil || a.ov.kind != panelHistory {
		t.Fatalf("no restored it, or closed the history (secret %q)", f.secrets[github])
	}
	a.press("r", "wait", "y")
	if f.secrets[github] != "old-2" || !strings.Contains(a.screen(), "Restored an earlier secret for github (alice)") {
		t.Errorf("restore: secret %q:\n%s", f.secrets[github], a.screen())
	}
}

// Delete asks first, then moves the entry to the trash; the trash puts it
// back, or deletes it for good after a yes.
func TestActionDeleteAndTrash(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "d")
	if s := a.screen(); !strings.Contains(s, "Move github (alice) to the trash?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("n")
	if len(f.entries) != 3 {
		t.Fatal("no deleted it")
	}
	a.press("ctrl+k", "d", "wait", "y")
	if s := a.screen(); len(f.entries) != 2 || !strings.Contains(s, "2 entries") || !strings.Contains(s, "Moved password github (alice) to the trash") {
		t.Fatalf("after delete:\n%s", s)
	}
	a.press("ctrl+g", "t")
	if s := a.screen(); !strings.Contains(s, "github (alice)  password · deleted") {
		t.Fatalf("trash:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); len(f.entries) != 3 || !strings.Contains(s, "3 entries") {
		t.Fatalf("put back:\n%s", s)
	}
	// The selection moved on to the TOTP entry when github left the list.
	a.press("ctrl+k", "d", "wait", "y", "ctrl+g", "t", "x")
	if s := a.screen(); !strings.Contains(s, "Delete TOTP github (alice) for good?") {
		t.Fatalf("confirm for good:\n%s", s)
	}
	a.press("wait", "y")
	if len(f.trash) != 0 || !strings.Contains(a.screen(), "Deleted TOTP github (alice) for good") {
		t.Errorf("for good: trash %v", f.trash)
	}
}

// An entry put back under a name that's taken says so; a puts it back under another; e empties the trash after a yes.
func TestTrashRestoreAsAndEmpty(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "d", "wait", "y")
	f.entries = append(f.entries, vault.Entry{Key: github}) // another entry takes its name
	a.press("ctrl+g", "t", "enter")
	if s := a.screen(); a.ov == nil || a.ov.kind != panelTrash || !strings.Contains(s, "a puts it back under another") {
		t.Fatalf("a name taken:\n%s", s)
	}
	a.press("a")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "password/github/alice") {
		t.Fatalf("the name to put it back as:\n%s", s)
	}
	a.press("enter")
	if a.form == nil || !strings.Contains(a.screen(), "That's its own name") {
		t.Fatalf("its own name again:\n%s", a.screen())
	}
	a.press("ctrl+u", "api_key/github-old", "enter")
	if a.form == nil || !strings.Contains(a.screen(), "It comes back as the kind it is: password/…") {
		t.Fatalf("another kind:\n%s", a.screen())
	}
	a.press("ctrl+u", "password/github-old/alice", "enter")
	old := vault.Key{Kind: vault.KindPassword, Service: "github-old", Username: "alice"}
	if !slices.ContainsFunc(f.entries, func(e vault.Entry) bool { return e.Key == old }) || len(f.trash) != 0 || !strings.Contains(a.screen(), "Restored password github-old (alice)") {
		t.Fatalf("put back as another: trash %v:\n%s", f.trash, a.screen())
	}
	a.press("down", "ctrl+k", "d", "wait", "y", "ctrl+k", "d", "wait", "y", "ctrl+g", "t", "e")
	if s := a.screen(); !strings.Contains(s, "Delete all 2 entries in the trash for good?") {
		t.Fatalf("confirm emptying:\n%s", s)
	}
	a.press("wait", "y")
	if s := a.screen(); len(f.trash) != 0 || a.ov == nil || a.ov.kind != panelTrash || !strings.Contains(s, "The trash is empty.") || !strings.Contains(s, "Deleted 2 entries in the trash for good") {
		t.Errorf("emptied: trash %v:\n%s", f.trash, s)
	}
}

// x deletes an earlier secret for good after a yes; the panel stays, listing those left.
func TestHistoryDeleteVersion(t *testing.T) {
	f := newFake()
	f.history = map[vault.Key][]string{github: {"old-1", "old-2"}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "h", "down", "x")
	if s := a.screen(); !strings.Contains(s, "Delete version 3 of github (alice) for good?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("n")
	if len(f.history[github]) != 2 {
		t.Fatal("no deleted it")
	}
	a.press("x", "wait", "y")
	if s := a.screen(); !slices.Equal(f.history[github], []string{"old-1"}) || a.ov == nil || a.ov.kind != panelHistory || strings.Contains(s, "version 3  replaced") || !strings.Contains(s, "Deleted version 3 of github (alice) for good") {
		t.Errorf("deleted: history %q:\n%s", f.history[github], s)
	}
}

// A version chosen from a list another command has changed since is the one acted on, whatever its number now;
// one that's gone isn't, and the panel says so, listing them as they are.
func TestHistoryChangedMeanwhile(t *testing.T) {
	f := newFake()
	f.history = map[vault.Key][]string{github: {"old-1", "old-2"}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "h", "down") // version 3: old-2
	f.history[github] = []string{"old-0", "old-1", "old-2"}
	a.press("x", "wait", "y")
	if !slices.Equal(f.history[github], []string{"old-0", "old-1"}) || a.ov == nil || a.ov.kind != panelHistory {
		t.Fatalf("deleted from a renumbered list: history %q", f.history[github])
	}
	// The one selected (old-1) is forgotten elsewhere: neither restored nor deleted.
	f.history[github] = []string{"old-0"}
	a.press("r", "wait", "y")
	if s := a.screen(); f.secrets[github] != "gh-pass" || a.ov == nil || a.ov.kind != panelHistory || !strings.Contains(s, "changed meanwhile") || strings.Contains(s, "version 3  replaced") {
		t.Errorf("restored a version gone: secret %q:\n%s", f.secrets[github], s)
	}
	// Copying one that's gone: nothing copied, and the list as it is now.
	f.history[github] = []string{"old-y"}
	a.press("enter")
	if s := a.screen(); len(a.copied) != 0 || a.ov == nil || a.ov.kind != panelHistory || len(a.ov.versions) != 1 || a.ov.versions[0].ID != versionID("old-y") {
		t.Errorf("copied a version gone: %q:\n%s", a.copied, s)
	}
}

// Emptying the trash deletes what it listed, not an entry trashed since.
func TestEmptyTrashOnlyWhatWasListed(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "d", "wait", "y", "ctrl+g", "t")
	f.trash = append(f.trash, Trashed{ID: 99, Key: vault.Key{Kind: vault.KindPassword, Service: "late"}})
	a.press("e")
	if s := a.screen(); !strings.Contains(s, "Delete the 1 entry in the trash for good?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("wait", "y")
	if len(f.trash) != 1 || f.trash[0].ID != 99 || !strings.Contains(a.screen(), "Deleted 1 entry in the trash for good") {
		t.Errorf("trash after = %+v:\n%s", f.trash, a.screen())
	}
}

// The settings' audit log row lists the newest events, saying when more are kept than shown; none says so.
func TestAuditPanel(t *testing.T) {
	f := newFake()
	when := time.Date(2026, 10, 14, 9, 30, 0, 0, time.Local)
	f.audit = AuditLog{Count: 600, Oldest: when.AddDate(0, -1, 0), Keep: "Nothing is removed automatically.",
		Events: []AuditEvent{{When: when, Event: "read", What: "password github (alice) (in sesh ui, to copy it)"}}}
	a := newApp(t, f, Options{Settings: func() ([]Setting, error) { return nil, nil }})
	a.press("ctrl+g", ",", "down", "enter")
	s := a.screen()
	for _, want := range []string{"Audit log: 600 events since", "2026-10-14 09:30  read    password github (alice)", "The newest 1 of 600 are shown"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	// p prunes, after a yes, and lists what's left.
	a.press("p", "x", "enter")
	if a.form == nil || !strings.Contains(a.screen(), "A whole number of days") {
		t.Fatalf("not a number:\n%s", a.screen())
	}
	a.press("ctrl+u", "0", "enter")
	if s := a.screen(); !strings.Contains(s, "Delete every event in the audit log?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("wait", "y")
	if s := a.screen(); !slices.Equal(f.pruned, []int{0}) || a.ov == nil || a.ov.kind != panelAudit || !strings.Contains(s, "No events yet") || !strings.Contains(s, "Removed all 1 events") {
		t.Errorf("pruned %v:\n%s", f.pruned, s)
	}
	// A prune that went through, then failed (compacting, say): the log as it is now, under why.
	f.audit = AuditLog{Count: 1, Oldest: when, Events: []AuditEvent{{When: when, Event: "read", What: "password github (alice)"}}}
	f.pruneErr = errors.New("removed all 1 event, but compacting the vault failed")
	a.press("esc", "enter", "p", "0", "enter", "wait", "y")
	if s := a.screen(); strings.Contains(s, "2026-10-14 09:30") || !strings.Contains(s, "compacting the vault failed") {
		t.Errorf("a failed prune:\n%s", s)
	}
}

// A TOTP entry's key can come from a QR code on screen, whose issuer and account name it when left empty; a code
// that can't be read is said, and nothing saved.
func TestAddScanQR(t *testing.T) {
	f := newFake()
	var scanErr error
	link := "otpauth://totp/Acme:jo@acme.io?secret=JBSWY3DPEHPK3PXP&issuer=Acme"
	a := newApp(t, f, Options{ScanQR: func() (ScannedQR, error) {
		return ScannedQR{Link: []byte(link), Issuer: "Acme", Account: "jo@acme.io"}, scanErr
	}})
	a.press("ctrl+g", "a", "→", "→", "→") // TOTP
	if s := a.screen(); !strings.Contains(s, "scan a QR code on screen") {
		t.Fatalf("the choice:\n%s", s)
	}
	a.tabs(3) // name, account, then the key's choice
	a.press("→")
	scanErr = errors.New("screenshot capture was canceled or failed")
	a.press("ctrl+s")
	if s := a.screen(); len(f.saves) != 0 || a.form == nil || !strings.Contains(s, "No QR code read: screenshot capture was canceled") {
		t.Fatalf("a failed scan:\n%s", s)
	}
	scanErr = nil
	a.press("ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saves = %d:\n%s", len(f.saves), a.screen())
	}
	if c := f.saves[0]; c.To != (vault.Key{Kind: vault.KindTOTP, Service: "Acme", Username: "jo@acme.io"}) || string(c.Secret) != link {
		t.Errorf("change = %+v", c)
	}
	// A name the code gives that's taken is shown in the form, which says so.
	acme := vault.Key{Kind: vault.KindTOTP, Service: "Acme", Username: "jo@acme.io"}
	f.entries = append(f.entries, vault.Entry{Key: acme})
	f.err = ErrNameTaken
	a.press("ctrl+g", "a", "→", "→", "→")
	a.tabs(3)
	a.press("→", "ctrl+s")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Another entry has that name") {
		t.Fatalf("a name taken:\n%s", s)
	}
	for _, in := range a.form.inputs {
		if want := map[string]string{"name": "Acme", "username": "jo@acme.io"}[in.label]; want != "" && in.value() != want {
			t.Errorf("the form's %s = %q, want %q", in.label, in.value(), want)
		}
	}
	f.err = nil
	// Ctrl-C while the screen is captured quits once it ends, saving nothing, even when the app locks meanwhile.
	saves := len(f.saves)
	a.quitAfter, a.scanning = true, true
	if quits(a.lock("You locked it.")) {
		t.Error("a lock during a scan quit before the capture ended")
	}
	// On the locked screen, Ctrl-C and Esc wait for it too, and say so.
	for _, key := range []tea.KeyPressMsg{{Code: 'c', Mod: tea.ModCtrl}, {Code: tea.KeyEscape}} {
		a.quitAfter = false
		if quits(a.lockedKey(key)) || !a.quitAfter || !strings.Contains(a.screen(), "Quitting once the screen capture ends") {
			t.Errorf("%s while locked during a scan:\n%s", key.String(), a.screen())
		}
	}
	cmd := a.scanned(&scannedMsg{qr: ScannedQR{Link: []byte(link)}, c: &Change{To: vault.Key{Kind: vault.KindTOTP, Service: "x"}}, epoch: a.epoch})
	if cmd == nil {
		t.Fatal("quitting mid-scan: nothing done")
	}
	if _, quits := cmd().(tea.QuitMsg); !quits || len(f.saves) != saves {
		t.Errorf("quitting mid-scan: quits %v, saves %d", quits, len(f.saves))
	}
}

// Delete for good skips the trash, after a yes, for the entry or those marked.
func TestPurge(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "x")
	if s := a.screen(); !strings.Contains(s, "Delete password github (alice) for good? It skips the") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("wait", "y")
	if len(f.entries) != 2 || len(f.trash) != 0 || !strings.Contains(a.screen(), "Deleted password github (alice) for good") {
		t.Fatalf("entries %d, trash %d:\n%s", len(f.entries), len(f.trash), a.screen())
	}
	a.press("down", "up", "space", "space")
	if len(a.keys[code]) == 0 {
		t.Fatal("the TOTP entry's key isn't held: the test can't see it wiped")
	}
	// Marked ones hidden by a search are said; one gone meanwhile is left out, the rest deleted and wiped.
	a.press("n", "o", "p", "e")
	a.press("ctrl+k", "x")
	if s := a.screen(); !strings.Contains(s, "2 of them not shown in the list") {
		t.Fatalf("confirm marked, hidden:\n%s", s)
	}
	f.entries = slices.DeleteFunc(f.entries, func(e vault.Entry) bool { return e.Key == gitlab })
	a.press("wait", "y")
	if s := a.screen(); len(f.entries) != 0 || len(f.trash) != 0 || len(a.marked) != 0 || len(a.keys[code]) != 0 || !strings.Contains(s, "1 marked was gone") {
		t.Errorf("entries %d, trash %d, marked %d, key held %v:\n%s", len(f.entries), len(f.trash), len(a.marked), len(a.keys[code]) != 0, s)
	}
}

// An entry deleted from its own menu, while marked, is unmarked, to the trash or for good.
func TestDeleteUnmarks(t *testing.T) {
	for _, key := range []string{"d", "x"} {
		f := newFake()
		a := newApp(t, f, Options{})
		// With a search typed, the list read again doesn't show every entry, so marks aren't tidied there.
		a.press("g", "i", "t", "h", "u", "b", "down", "up", "space", "up")
		marked := a.selected().Key
		if !a.marked[marked] {
			t.Fatalf("%s: the selected entry isn't the one marked: %v", key, a.marked)
		}
		a.press("ctrl+k", "s", key, "wait", "y")
		if len(a.marked) != 0 || slices.ContainsFunc(f.entries, func(e vault.Entry) bool { return e.Key == marked }) {
			t.Errorf("%s: marked %v, entries %v", key, a.marked, f.entries)
		}
	}
}

// Space marks entries in the trash; x then deletes those marked, after a yes.
func TestTrashMarks(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	for range 3 {
		a.press("ctrl+k", "d", "wait", "y")
	}
	a.press("ctrl+g", "t", "space", "down", "space")
	if s := a.screen(); len(a.ov.marked) != 2 || !strings.Contains(s, "delete the 2 marked") {
		t.Fatalf("marked:\n%s", s)
	}
	a.press("x")
	if s := a.screen(); !strings.Contains(s, "Delete the 2 entries marked for good?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("wait", "y")
	if s := a.screen(); len(f.trash) != 1 || a.ov == nil || a.ov.kind != panelTrash || len(a.ov.marked) != 0 || !strings.Contains(s, "Deleted 2 entries in the trash for good") {
		t.Errorf("trash %+v:\n%s", f.trash, s)
	}
	// Marked, then put back elsewhere: the delete is refused, the list read again, and the mark stays on what's left.
	for range 2 {
		f.trash = append(f.trash, Trashed{ID: int64(10 + len(f.trash)), Key: vault.Key{Kind: vault.KindPassword, Service: fmt.Sprint("x", len(f.trash))}})
	}
	a.press("esc", "ctrl+g", "t", "space", "space", "space")
	f.trash = f.trash[1:]
	a.press("x", "wait", "y")
	if s := a.screen(); len(f.trash) != 2 || len(a.ov.marked) != 2 || !strings.Contains(s, "the trash changed meanwhile") {
		t.Errorf("refused: trash %d, marked %v:\n%s", len(f.trash), a.ov.marked, s)
	}
}

// Lock now locks the app, and the agent.
func TestActionLockNow(t *testing.T) {
	f := newFake()
	agentLocked := false
	a := newApp(t, f, Options{LockAgent: func() error { agentLocked = true; return nil }})
	a.press("ctrl+g")
	if !strings.Contains(a.screen(), "lock sesh") {
		t.Fatalf("menu:\n%s", a.screen())
	}
	a.press("l")
	if s := a.screen(); a.v != nil || !agentLocked || !strings.Contains(s, "sesh is locked") || !f.closed {
		t.Errorf("lock now: app locked %v, agent locked %v:\n%s", a.v == nil, agentLocked, s)
	}
}

// A word typed after Ctrl-K by habit deletes nothing: a confirmation's y
// doesn't count in the same breath as the key that asked, and Enter is
// never a yes.
func TestConfirmNeedsADeliberateYes(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "d", "r", "y")
	if len(f.entries) != 3 || a.ov == nil || a.ov.kind != panelConfirm {
		t.Fatalf("typing a word after Ctrl-K deleted an entry, or asked nothing: %+v", a.ov)
	}
	a.press("esc", "esc", "ctrl+k", "d", "wait", "enter")
	if len(f.entries) != 3 || a.ov == nil {
		t.Fatalf("Enter confirmed a delete (entries %d)", len(f.entries))
	}
	// Unseen, in a window too small, it answers nothing.
	a.Update(tea.WindowSizeMsg{Width: 30, Height: 8})
	a.press("y")
	if len(f.entries) != 3 {
		t.Error("a confirmation that wasn't on screen was answered")
	}
}

// With text after the cursor, Ctrl-K deletes it, as in a shell, and opens
// nothing.
func TestCtrlKKillsToEndOfLine(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("github")
	for range 3 {
		a.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	}
	a.press("ctrl+k")
	if a.ov != nil || a.input.Value() != "git" {
		t.Errorf("Ctrl-K mid-line: menu open %v, search %q", a.ov != nil, a.input.Value())
	}
}

// An action is done to the entry its panel names, whatever is selected by
// then: a click on the card moves nothing, and another command's change
// closes the panel.
func TestActionsKeepTheirEntry(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "f")
	a.Update(tea.MouseClickMsg{X: 5, Y: 5, Button: tea.MouseLeft}) // gitlab's row, under the card
	if a.sel != 0 {
		t.Fatalf("a click through the panel selected row %d", a.sel)
	}
	a.sel = 2 // however the selection came to move
	a.press("1")
	if len(a.copied) != 1 || a.copied[0] != "gh-pass" {
		t.Errorf("copied %q, want github's password, which the panel named", a.copied)
	}
	a.sel = 0
	a.press("ctrl+k", "h")
	f.changed = true
	a.tick(time.Second)
	if s := a.screen(); a.ov != nil || !strings.Contains(s, "Another command changed the vault") {
		t.Errorf("a change under an open panel:\n%s", s)
	}
}

// Esc goes back from a panel to the menu it came from; a TOTP entry's
// value to copy is its code.
func TestPanelsGoBack(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("down", "ctrl+k", "f")
	if s := a.screen(); !strings.Contains(s, "code") || strings.Contains(s, "password ") {
		t.Errorf("a TOTP entry's values:\n%s", s)
	}
	a.press("esc")
	if a.ov == nil || a.ov.kind != panelMenu {
		t.Fatal("Esc from the values didn't go back to the menu")
	}
	a.press("h", "esc")
	if a.ov == nil || a.ov.kind != panelMenu {
		t.Error("Esc from the history didn't go back to the menu")
	}
	a.press("esc")
	if a.ov != nil {
		t.Error("Esc from the menu didn't close it")
	}
}

// What the app held of an entry is wiped when its secret is restored or
// it's deleted.
func TestActionsForgetWhatsHeld(t *testing.T) {
	f := newFake()
	f.history = map[vault.Key][]string{code: {"OLDKEYOLDKEYOLDK"}}
	a := newApp(t, f, Options{})
	held := a.keys[code]
	a.press("down", "ctrl+k", "h", "r", "wait", "y")
	if string(held) != strings.Repeat("\x00", len(seed)) {
		t.Errorf("the TOTP key held before the restore wasn't wiped: %q", held)
	}
	if string(a.keys[code]) != "OLDKEYOLDKEYOLDK" {
		t.Errorf("the key held after = %q, want the restored one", a.keys[code])
	}
}

// Lock now says so when the agent couldn't be locked; a restore from the
// trash that fails is said in the panel, which stays open; a long list
// keeps its selection on screen.
func TestActionFailuresAndLongPanels(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{LockAgent: func() error { return errors.New("broken pipe") }})
	for i := range 40 {
		f.trash = append(f.trash, Trashed{ID: int64(i + 1), Key: vault.Key{Kind: vault.KindPassword, Service: fmt.Sprintf("old-%02d", i)}})
	}
	a.press("ctrl+g", "t")
	for range 30 {
		a.press("down")
	}
	s := a.screen()
	if !strings.Contains(s, "old-30") || !strings.Contains(s, "deleted") || !strings.Contains(s, "put back") || strings.Count(s, "\n") != a.height-1 {
		t.Errorf("a long trash:\n%s", s)
	}
	a.press("esc", "esc", "ctrl+g", "l")
	// The card wraps the sentence, so it's checked as the app holds it.
	if s := a.screen(); a.v != nil || !strings.Contains(a.lockedWhy, "sesh's agent couldn't be locked (broken pipe)") || !strings.Contains(s, "sesh agent lock") {
		t.Errorf("lock now with the agent unreachable (%q):\n%s", a.lockedWhy, s)
	}
}

// A restore that fails is said above the trash's rows, which stay; a
// second Enter while one is put back does nothing; a paste doesn't reach
// the search behind a panel; a long name's question still fits the
// smallest window.
func TestPanelEdges(t *testing.T) {
	f := newFake()
	long := vault.Key{Kind: vault.KindPassword, Service: strings.Repeat("a-very-long-name-", 6)}
	f.entries = append(f.entries, vault.Entry{Key: long})
	a := newApp(t, f, Options{})
	a.Update(tea.WindowSizeMsg{Width: minWidth, Height: minHeight})
	a.press("down", "down", "down", "ctrl+k", "d")
	if s := a.screen(); strings.Count(s, "\n") != minHeight-1 || !strings.Contains(s, "yes") || !strings.Contains(s, "╰") {
		t.Errorf("a long name's question at the smallest size:\n%s", s)
	}
	a.press("esc", "esc")
	a.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	f.trash = []Trashed{{ID: 7, Key: github}}
	a.press("ctrl+g", "t")
	a.Update(tea.PasteMsg{Content: "zzz"})
	if a.input.Value() != "" {
		t.Errorf("a paste reached the search behind the panel: %q", a.input.Value())
	}
	first := a.restoreFromTrash(&f.trash[0], vault.Key{})
	if !a.ov.loading {
		t.Fatal("the panel takes keys while an entry is put back")
	}
	a.press("enter")
	a.Update(doneMsg{err: ErrNameTaken, epoch: a.epoch, closes: panelTrash})
	_ = first
	if s := a.screen(); a.ov == nil || !strings.Contains(s, "another entry has that name") || !strings.Contains(s, "github (alice)") {
		t.Errorf("a restore that failed:\n%s", s)
	}
}

// A secure note's text can be copied from its values, though it has no
// fields; an entry's notes can be too.
func TestCopyANotesText(t *testing.T) {
	f := newFake()
	wifi := vault.Key{Kind: vault.KindNote, Service: "wifi"}
	f.entries = append(f.entries, vault.Entry{Key: wifi})
	f.secrets[wifi] = "ssid home"
	f.entries[0].HasNotes = true
	f.notes = map[vault.Key]string{github: "recovery codes"}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "f")
	if s := a.screen(); !strings.Contains(s, "notes") {
		t.Fatalf("github's values:\n%s", s)
	}
	a.press("2")
	if len(a.copied) != 1 || a.copied[0] != "recovery codes" {
		t.Errorf("copied %q, want github's notes", a.copied)
	}
	a.press("down", "down", "down", "ctrl+k", "f")
	if s := a.screen(); !strings.Contains(s, "Copy from wifi") || !strings.Contains(s, "note") {
		t.Fatalf("wifi's values:\n%s", s)
	}
	a.press("1")
	if len(a.copied) != 2 || a.copied[1] != "ssid home" {
		t.Errorf("copied %q, want the note's text", a.copied)
	}
}

// tabs presses Tab n times.
func (a *app) tabs(n int) {
	for range n {
		a.press("tab")
	}
}

// The edit form changes what was changed, and nothing else: a username,
// then a new secret typed, which is wiped once saved.
func TestEditForm(t *testing.T) {
	f := newFake()
	f.entries[0].URL = "github.com"
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	if s := a.screen(); !strings.Contains(s, "Edit github (alice)") || !strings.Contains(s, "ctrl+s") {
		t.Fatalf("the form:\n%s", s)
	}
	a.press("tab", "2", "ctrl+s") // the username, then save
	if len(f.saves) != 1 {
		t.Fatalf("saves = %d:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	if c.Key != github || c.To.Username != "alice2" || c.URL != nil || c.Secret != nil || c.SetNotes || c.TagsSet || c.Folder != nil {
		t.Errorf("change = %+v", c)
	}
	if s := a.screen(); a.form != nil || !strings.Contains(s, "Saved password github (alice2)") || !strings.Contains(s, "alice2") {
		t.Errorf("after saving:\n%s", s)
	}
	// A new secret: the choice, then the secret typed unseen.
	a.press("ctrl+k", "e")
	a.tabs(3)
	a.press("→", "tab", "hunter2")
	typed := a.form.inputs[a.form.focus].secret
	if s := a.screen(); strings.Contains(s, "hunter2") || !strings.Contains(s, "•••••••") {
		t.Errorf("the secret typed is shown, or not marked:\n%s", s)
	}
	a.press("ctrl+s")
	if len(f.saves) != 2 || string(f.saves[1].Secret) != "hunter2" || string(typed[:7]) != strings.Repeat("\x00", 7) {
		t.Errorf("saved %+v; typed buffer %q", f.saves, typed)
	}
}

// A generated password is saved, and copied, since nobody has seen it; a
// name another entry has is said in the form, which stays.
func TestEditGenerateAndNameTaken(t *testing.T) {
	f := newFake()
	var asked []generating
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second, Generate: func(length int, symbols bool) ([]byte, error) {
		asked = append(asked, generating{length: length, symbols: symbols})
		return []byte("generated-pw"), nil
	}})
	a.press("ctrl+k", "e")
	a.tabs(3)
	a.press("→", "→", "ctrl+s")
	if len(f.saves) != 1 || string(f.saves[0].Secret) != "generated-pw" || len(a.copied) != 1 || a.copied[0] != "generated-pw" || !slices.Equal(asked, []generating{{length: 24, symbols: true}}) {
		t.Fatalf("saves %+v, copied %q, asked %v", f.saves, a.copied, asked)
	}
	// Its length, and letters and digits only.
	a.press("ctrl+k", "e")
	a.tabs(3)
	a.press("→", "→", "tab", "ctrl+u", "x", "ctrl+s")
	if a.form == nil || !strings.Contains(a.screen(), "The length is a whole number") {
		t.Fatalf("a length that isn't one:\n%s", a.screen())
	}
	a.press("backspace", "16", "tab", "→", "ctrl+s")
	if !slices.Equal(asked, []generating{{length: 24, symbols: true}, {length: 16}}) {
		t.Fatalf("asked %v:\n%s", asked, a.screen())
	}
	if s := a.screen(); !strings.Contains(s, "new password") || !strings.Contains(s, "clears in 30 seconds") {
		t.Errorf("after generating:\n%s", s)
	}
	// A rename to a name that's free is saved.
	a.press("down", "ctrl+k", "e")
	for range len("github") {
		a.press("backspace")
	}
	a.press("gitlab", "ctrl+s")
	if a.form != nil {
		t.Fatalf("saved onto a free name? saves %+v", f.saves[len(f.saves)-1])
	}
	f.entries = append(f.entries, vault.Entry{Kind: vault.KindPassword, Service: "taken"})
	a.press("esc", "ctrl+g", "a")
	a.press("tab", "taken")
	a.tabs(2)
	a.press("→") // type → generate
	a.press("ctrl+s")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Another entry has that name") {
		t.Errorf("a name taken:\n%s", s)
	}
}

// Ctrl-G's generator makes a password and copies it, storing it nowhere; a refused length is said in the form.
func TestGenerator(t *testing.T) {
	f := newFake()
	var asked []generating
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second, IsWeak: func(pw []byte) bool { return len(asked) > 0 && asked[len(asked)-1].length < 12 }, Generate: func(length int, symbols bool) ([]byte, error) {
		asked = append(asked, generating{length: length, symbols: symbols})
		if length > 1024 {
			return nil, errors.New("password length 2000 is more than the 1024 sesh makes")
		}
		return []byte("made-pw"), nil
	}})
	a.press("ctrl+g", "p")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Generate a password") || !strings.Contains(s, "24") {
		t.Fatalf("the generator:\n%s", s)
	}
	a.press("ctrl+u", "2000", "enter", "enter")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Not generated: password length 2000") {
		t.Fatalf("too long:\n%s", s)
	}
	a.press("shift+tab", "ctrl+u", "12", "tab", "→", "enter")
	if a.form != nil || !slices.Equal(a.copied, []string{"made-pw"}) || asked[len(asked)-1] != (generating{length: 12}) || len(f.saves) != 0 {
		t.Errorf("generated: copied %q, asked %v, saves %d:\n%s", a.copied, asked, len(f.saves), a.screen())
	}
	if s := a.screen(); !strings.Contains(s, "Copied a new password of 12 characters") || a.clipUntil.IsZero() {
		t.Errorf("what's said:\n%s", s)
	}
	a.press("ctrl+g", "p", "ctrl+u", "6", "enter", "enter")
	if s := a.screen(); !strings.Contains(s, "easy to guess") {
		t.Errorf("a short one:\n%s", s)
	}
}

// The generator makes a passphrase where the app can: words, what goes between them, and capitals; characters otherwise.
func TestGeneratorPassphrase(t *testing.T) {
	f := newFake()
	var asked []generating
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second,
		Generate: func(length int, symbols bool) ([]byte, error) {
			asked = append(asked, generating{length: length, symbols: symbols})
			return []byte("made-pw"), nil
		},
		Passphrase: func(words int, separator string, capitalize bool) ([]byte, error) {
			asked = append(asked, generating{words: words, separator: separator, capitalize: capitalize})
			if words > 20 {
				return nil, errors.New("a passphrase has 3 to 20 words, not 30")
			}
			return []byte("made-words"), nil
		},
	})
	a.press("ctrl+g", "p")
	if s := a.screen(); !strings.Contains(s, "random characters") || strings.Contains(s, "between words") {
		t.Fatalf("the generator, as characters:\n%s", s)
	}
	a.press("→")
	if s := a.screen(); !strings.Contains(s, "between words") || strings.Contains(s, "letters, digits and symbols") {
		t.Fatalf("the generator, as words:\n%s", s)
	}
	a.press("ctrl+s")
	if want := (generating{words: 6, separator: "-"}); len(asked) != 1 || asked[0] != want || !slices.Equal(a.copied, []string{"made-words"}) {
		t.Fatalf("asked %+v, copied %q", asked, a.copied)
	}
	if s := a.screen(); !strings.Contains(s, "Copied a new passphrase of 6 words") {
		t.Errorf("what's said:\n%s", s)
	}
	// A space between them is kept; capitals; a number refused is said.
	a.press("ctrl+g", "p", "→", "tab", "ctrl+u", "30", "tab", "ctrl+u", "space", "tab", "→", "enter")
	if want := (generating{words: 30, separator: " ", capitalize: true}); asked[len(asked)-1] != want || !strings.Contains(a.screen(), "Not generated: a passphrase has 3 to 20 words") {
		t.Fatalf("asked %+v:\n%s", asked, a.screen())
	}
	a.press("shift+tab", "shift+tab", "ctrl+u", "x", "ctrl+s")
	if s := a.screen(); !strings.Contains(s, "The words are a whole number") {
		t.Errorf("words that aren't a number:\n%s", s)
	}
}

// Generating in the add form can make a passphrase too.
func TestAddGeneratesPassphrase(t *testing.T) {
	f := newFake()
	var asked []generating
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second, Passphrase: func(words int, separator string, capitalize bool) ([]byte, error) {
		asked = append(asked, generating{words: words, separator: separator, capitalize: capitalize})
		return []byte("made-words"), nil
	}})
	a.press("ctrl+g", "a")
	a.press("tab", "bank")
	a.tabs(2)
	a.press("→", "tab", "→", "ctrl+s")
	if len(f.saves) != 1 || string(f.saves[0].Secret) != "made-words" || len(asked) != 1 || asked[0].words != 6 {
		t.Fatalf("saves %+v, asked %+v:\n%s", f.saves, asked, a.screen())
	}
}

// Adding: a secure note's text is its secret; a TOTP entry needs its key;
// Esc on a form with something typed asks once before discarding it.
func TestAddForm(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "a")
	if s := a.screen(); !strings.Contains(s, "Add an entry") || !strings.Contains(s, "● password") {
		t.Fatalf("the form:\n%s", s)
	}
	a.press("→", "→") // secure note
	a.press("tab", "wifi")
	a.tabs(4) // folder, tags, then the note
	a.press("ssid home")
	a.press("ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saves = %d:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	if c.Key != (vault.Key{}) || c.To != (vault.Key{Kind: vault.KindNote, Service: "wifi"}) || string(c.Secret) != "ssid home" || c.SetNotes {
		t.Errorf("change = %+v", c)
	}
	if !strings.Contains(a.screen(), "Added secure note wifi") {
		t.Errorf("after adding:\n%s", a.screen())
	}
	a.press("ctrl+g", "a", "→", "→", "→") // TOTP
	a.press("tab", "site", "ctrl+s")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Paste the TOTP key") {
		t.Errorf("a TOTP entry with no key:\n%s", s)
	}
	a.press("esc")
	if a.form == nil || !strings.Contains(a.screen(), "Press Esc again to discard") {
		t.Fatalf("one Esc closed a form with something typed:\n%s", a.screen())
	}
	a.press("esc")
	if a.form != nil {
		t.Error("the second Esc didn't close the form")
	}
}

// Fields are added (a secret one typed unseen), and removed; changed
// notes are saved with the notes they replace; what the editor saved goes
// into the notes; a lock wipes what was typed.
func TestFormFieldsNotesAndLock(t *testing.T) {
	f := newFake()
	f.entries[0].HasNotes = true
	f.entries[0].Fields = []vault.Field{{Name: "email", Value: []byte("a@example.com")}}
	f.notes = map[vault.Key]string{github: "old notes"}
	a := newApp(t, f, Options{IdleTimeout: time.Hour, Unlock: func([]byte) (Vault, error) { return f, nil }})
	a.press("ctrl+k", "e")
	a.tabs(8) // username, kind, secret, current, URL, folder, tags → notes
	a.press("!")
	a.Update(editorMsg{notes: []byte("from the editor")})
	a.press("tab")             // the fields
	a.press("x")               // remove email
	a.press("a", "pin", "tab") // a new field: its name, then "secret"
	a.press("→", "tab")        // yes; its value, unseen
	a.press("4321", "ctrl+s")  // the field's form
	if s := a.screen(); !strings.Contains(s, "pin") || strings.Contains(s, "4321") || strings.Contains(s, "email") {
		t.Fatalf("the fields:\n%s", s)
	}
	a.press("ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saves = %d:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	if !c.SetNotes || string(c.Notes) != "from the editor" || string(c.NotesBase) != "old notes" ||
		len(c.SetFields) != 1 || c.SetFields[0].Name != "pin" || !c.SetFields[0].Secret || string(c.SetFields[0].Value) != "4321" ||
		!slices.Equal(c.RemoveFields, []string{"email"}) {
		t.Errorf("change = %+v", c)
	}
	a.press("ctrl+k", "e")
	a.tabs(3)
	a.press("→", "tab", "secret")
	typed := a.form.inputs[a.form.focus].secret
	a.lock("test")
	if a.form != nil || string(typed[:6]) != strings.Repeat("\x00", 6) {
		t.Errorf("a lock left the form, or what was typed: %q", typed)
	}
}

// A TOTP entry's form asks for an account, and doesn't rate its key as a
// password; a password typed that's easy to guess is said to be.
func TestFormLabelsAndStrength(t *testing.T) {
	a := newApp(t, newFake(), Options{IsWeak: func([]byte) bool { return true }})
	a.press("ctrl+g", "a", "→", "→", "→", "tab", "x", "tab", "me", "tab", "JBSWY3DP")
	if s := a.screen(); !strings.Contains(s, " account ") || strings.Contains(s, " username ") || strings.Contains(s, "easy to guess") {
		t.Errorf("a TOTP entry's form:\n%s", s)
	}
	a.press("esc", "esc", "ctrl+g", "a")
	a.tabs(3) // kind, name, username → the secret's choice (type a new one)
	a.press("tab", "abc")
	if s := a.screen(); !strings.Contains(s, "easy to guess") {
		t.Errorf("a weak password typed:\n%s", s)
	}
}

// The folder and tags inputs offer the ones there are, matched anywhere.
func TestFormOffersFoldersAndTags(t *testing.T) {
	f := newFake()
	f.entries[0].Tags = []string{"prod", "personal"}
	f.entries[2].Folder = "home/network"
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "a", "tab", "x")
	a.tabs(3) // username, the secret's choice → the secret
	a.press("pw")
	a.tabs(2) // URL → folder
	if s := a.screen(); !strings.Contains(s, "work") || !strings.Contains(s, "home/network") {
		t.Fatalf("the folders there are aren't offered:\n%s", s)
	}
	a.press("NET")
	if s := a.screen(); !strings.Contains(s, "home/network") || strings.Contains(s, "   work") {
		t.Errorf("typed NET, want only home/network offered:\n%s", s)
	}
	a.press("down", "enter", "tab", "x, pr", "down", "enter", "ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saved %d entries:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	if c.Folder == nil || *c.Folder != "home/network" || !slices.Equal(c.Tags, []string{"x", "prod"}) {
		t.Errorf("saved in folder %v with tags %q", c.Folder, c.Tags)
	}
}

// Ctrl-R shows a secret being typed into a form, until the focus moves on.
func TestFormShowsATypedSecret(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("ctrl+g", "a")
	a.tabs(4) // name, username, the secret's choice → the secret
	a.press("hunter2")
	if s := a.screen(); strings.Contains(s, "hunter2") || !strings.Contains(s, "show what you typed") {
		t.Fatalf("a secret typed should be hidden, with the key that shows it:\n%s", s)
	}
	a.press("ctrl+r", "!")
	if s := a.screen(); !strings.Contains(s, "hunter2!") {
		t.Errorf("after ctrl+r, the secret isn't shown:\n%s", s)
	}
	a.press("tab", "shift+tab")
	if s := a.screen(); strings.Contains(s, "hunter2") {
		t.Errorf("the secret is still shown after the focus left it:\n%s", s)
	}
}

// Ctrl-R on a secret field's empty input reads the value it has and shows it.
func TestFormShowsAFieldsValue(t *testing.T) {
	f := newFake()
	f.entries[0].Fields = []vault.Field{{Name: "pin", Secret: true}}
	f.fields = map[vault.Key][]vault.Field{github: {{Name: "pin", Secret: true, Value: []byte("4711")}}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(9) // username, kind, secret, current, URL, folder, tags, notes → the fields
	a.press("enter", "tab", "tab")
	if s := a.screen(); strings.Contains(s, "4711") || !strings.Contains(s, "••••••••▌") || !strings.Contains(s, "ctrl+r  show it") {
		t.Fatalf("the field's value should be unread, with the key that shows it:\n%s", s)
	}
	a.press("ctrl+r")
	if s := a.screen(); !strings.Contains(s, "4711") {
		t.Fatalf("after ctrl+r, the field's value isn't shown:\n%s", s)
	}
	if !slices.Contains(f.reads, "field "+github.String()+" pin") {
		t.Errorf("the read wasn't recorded: %q", f.reads)
	}
	a.press("ctrl+s", "tab", "shift+tab", "ctrl+s")
	if len(f.saves) != 1 || len(f.saves[0].SetFields) != 0 || len(f.saves[0].RemoveFields) != 0 {
		t.Errorf("a value only shown was saved as a change: %+v", f.saves)
	}
}

// Ctrl-R hides a value shown, even once it's been emptied, rather than reading it again.
func TestFormHidesAnEmptiedValue(t *testing.T) {
	f := newFake()
	f.entries[0].Fields = []vault.Field{{Name: "pin", Secret: true}}
	f.fields = map[vault.Key][]vault.Field{github: {{Name: "pin", Secret: true, Value: []byte("4711")}}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(9)
	a.press("enter", "tab", "tab", "ctrl+r", "backspace", "backspace", "backspace", "backspace")
	if s := a.screen(); !strings.Contains(s, "ctrl+r  hide it") {
		t.Fatalf("emptied, shown:\n%s", s)
	}
	a.press("ctrl+r", "1")
	field := 0
	for _, r := range f.reads {
		if strings.HasPrefix(r, "field ") {
			field++
		}
	}
	if s := a.screen(); strings.Contains(s, "4711") || strings.Contains(s, " 1▌") || field != 1 {
		t.Errorf("Ctrl-R read it again (%q), or didn't hide what's typed:\n%s", f.reads, s)
	}
}

// fieldsApp is the app with github's form open on its fields: email (plain)
// and pin (secret, not read).
func fieldsApp(t *testing.T) (*app, *fakeVault) {
	t.Helper()
	f := newFake()
	f.entries[0].Fields = []vault.Field{{Name: "email", Value: []byte("a@b")}, {Name: "pin", Secret: true}}
	f.fields = map[vault.Key][]vault.Field{github: {{Name: "pin", Secret: true, Value: []byte("4711")}}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(9) // username, kind, secret, current, URL, folder, tags, notes → the fields
	return a, f
}

// A field renamed, or made plain, is taken out and set again; names differ by more than case.
func TestFormFieldChanges(t *testing.T) {
	a, f := fieldsApp(t)
	a.press("enter", "backspace", "backspace", "backspace", "backspace", "backspace", "Email", "ctrl+s")
	a.press("a", "EMAIL", "ctrl+s")
	if s := a.screen(); !strings.Contains(s, "Another field already has that name") {
		t.Errorf("a second field named EMAIL:\n%s", s)
	}
	a.press("esc", "esc", "down", "enter", "tab", "h", "tab", "ctrl+s")
	if s := a.screen(); !strings.Contains(s, "Type a new value to make it plain") {
		t.Errorf("a secret field made plain without a value:\n%s", s)
	}
	a.press("1234", "ctrl+s", "ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saved %d:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	var set []string
	for _, fl := range c.SetFields {
		set = append(set, fmt.Sprintf("%s=%s/%v", fl.Name, fl.Value, fl.Secret))
	}
	if !slices.Equal(c.RemoveFields, []string{"email", "pin"}) || !slices.Equal(set, []string{"Email=a@b/false", "pin=1234/false"}) {
		t.Errorf("removed %q, set %q", c.RemoveFields, set)
	}
}

// A field's form cancelled wipes what was typed into it, and an edit made in one counts as a change.
func TestFormFieldFormWipesAndCounts(t *testing.T) {
	a, _ := fieldsApp(t)
	a.press("a", "pin2", "tab", "→", "tab", "4321")
	typed := a.form.inputs[3].secret
	a.press("esc", "esc")
	if string(typed) == "4321" {
		t.Error("a field's form cancelled left its secret in memory")
	}
	if a.form == nil || a.form.back != nil {
		t.Fatal("Esc should go back to the entry's form")
	}
	a.press("up", "down", "esc")
	if a.form != nil {
		t.Fatal("moving between fields counted as a change")
	}
	a, _ = fieldsApp(t)
	a.press("enter", "x", "ctrl+s", "esc")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Esc again") {
		t.Errorf("a field renamed and then one Esc discarded the form:\n%s", s)
	}
}

// Notes the input shows differently aren't saved unless changed; a secure note needs its text.
func TestFormNotesKeptAsTheyAre(t *testing.T) {
	f := newFake()
	f.entries[0].HasNotes = true
	f.notes = map[vault.Key]string{github: "a\tb\r\nc"}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e", "tab", "x", "ctrl+s")
	if len(f.saves) != 1 || f.saves[0].SetNotes {
		t.Errorf("notes nobody changed were saved: %+v", f.saves)
	}
	a.press("ctrl+g", "a", "→", "→", "tab", "a note", "ctrl+s")
	if s := a.screen(); len(f.saves) != 1 || !strings.Contains(s, "Write the note") {
		t.Errorf("an empty secure note: %d saves\n%s", len(f.saves), s)
	}
}

// Time spent in the editor doesn't lock the app as idle when it returns.
func TestFormEditorTimeIsUse(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{IdleTimeout: 10 * time.Minute, EditNotes: func(b []byte) ([]byte, error) { return b, nil }})
	a.press("ctrl+k", "e")
	a.tabs(8) // → notes
	a.press("ctrl+e")
	// The program delivers the ticks due while the editor ran before the
	// editor's own message.
	a.tick(15 * time.Minute)
	if a.form == nil || a.v == nil {
		t.Fatal("the app locked as idle while the editor had the terminal")
	}
	_, cmd := a.Update(editorMsg{notes: []byte("from the editor")})
	a.run(cmd)
	a.tick(time.Second)
	if a.form == nil || a.v == nil {
		t.Fatal("the app locked as idle after the editor returned")
	}
	if got := a.form.inputs[a.form.focus].area.Value(); got != "from the editor" {
		t.Errorf("notes = %q", got)
	}
	a.tick(10 * time.Minute)
	if a.v != nil {
		t.Error("the idle lock didn't start again after the editor")
	}
}

// A paste is held to what a key is: not into a form that isn't drawn, and it counts against Esc.
func TestFormPasteGuards(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("ctrl+k", "e", "x", "esc")
	_, cmd := a.Update(tea.PasteMsg{Content: "y"})
	a.run(cmd)
	a.press("esc")
	if a.form == nil {
		t.Fatal("Esc, a paste, Esc discarded the form")
	}
	a.Update(tea.WindowSizeMsg{Width: 30, Height: 8})
	a.Update(tea.PasteMsg{Content: "unseen"})
	a.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if s := a.screen(); strings.Contains(s, "unseen") {
		t.Errorf("a paste went into a form that wasn't drawn:\n%s", s)
	}
}

// An entry whose notes can't be read says why it can't be edited.
func TestEditNotesUnreadable(t *testing.T) {
	f := newFake()
	f.entries[0].HasNotes = true
	a := newApp(t, f, Options{})
	delete(a.notes, github)
	a.notesFailed[github] = "boom"
	a.press("ctrl+k", "e")
	if s := a.screen(); a.form != nil || !strings.Contains(s, "Can't edit it here: its notes couldn't be read (boom).") {
		t.Errorf("editing with unreadable notes:\n%s", s)
	}
}

// The field chosen in a long list stays on screen, and an error stays in the window.
func TestFormLongFieldsAndErrors(t *testing.T) {
	f := newFake()
	for i := range 30 {
		f.entries[0].Fields = append(f.entries[0].Fields, vault.Field{Name: fmt.Sprintf("field%02d", i), Value: []byte("v")})
	}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(9)
	for range 25 {
		a.press("down")
	}
	if s := a.screen(); !strings.Contains(s, "field25") {
		t.Errorf("the chosen field is off screen:\n%s", s)
	}
	a.Update(tea.WindowSizeMsg{Width: minWidth, Height: minHeight})
	a.form.err = strings.Repeat("a long error that wraps ", 12)
	if lines := strings.Count(a.View().Content, "\n") + 1; lines > minHeight {
		t.Errorf("the form drew %d lines in a window of %d:\n%s", lines, minHeight, a.screen())
	}
}

// The vault is kept from idling out while the notes editor is open.
func TestEditorKeepsTheVaultInUse(t *testing.T) {
	var kept atomic.Int32
	e := &editor{
		edit:  func(b []byte) ([]byte, error) { time.Sleep(60 * time.Millisecond); return b, nil },
		keep:  func() { kept.Add(1) },
		every: 10 * time.Millisecond,
		notes: []byte("n"),
	}
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	after := kept.Load()
	if after == 0 {
		t.Error("nothing kept the vault in use while the editor was open")
	}
	time.Sleep(30 * time.Millisecond)
	if kept.Load() != after {
		t.Error("the vault was still kept in use after the editor closed")
	}
}

// A secret field renamed is set again under its new name with the value read for it.
func TestFormRenamesAnUnreadSecretField(t *testing.T) {
	a, f := fieldsApp(t)
	a.press("down", "enter", "backspace", "backspace", "backspace", "PIN", "ctrl+s")
	if a.form == nil || a.form.back != nil {
		t.Fatalf("the field's form didn't go back once its value was read:\n%s", a.screen())
	}
	a.press("ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saved %d:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	if !slices.Equal(c.RemoveFields, []string{"pin"}) || len(c.SetFields) != 1 || c.SetFields[0].Name != "PIN" || !c.SetFields[0].Secret {
		t.Errorf("removed %q, set %+v", c.RemoveFields, c.SetFields)
	}
	if !slices.Contains(f.reads, "field "+github.String()+" pin") {
		t.Errorf("the value wasn't read: %q", f.reads)
	}
}

// Ctrl-S while Ctrl-R's read is on its way saves the field once it lands; a field saved as it was is no change.
func TestFormFieldSaveWhileReading(t *testing.T) {
	a, f := fieldsApp(t)
	a.press("down", "enter", "backspace", "backspace", "backspace", "PIN", "tab", "tab")
	_, read := a.Update(tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl})
	a.press("ctrl+s")
	a.run(read)
	if a.form == nil || a.form.back != nil {
		t.Fatalf("the field wasn't saved once its value landed:\n%s", a.screen())
	}
	a.press("ctrl+s")
	if len(f.saves) != 1 || len(f.saves[0].SetFields) != 1 || f.saves[0].SetFields[0].Name != "PIN" {
		t.Errorf("saved %+v", f.saves)
	}

	a, _ = fieldsApp(t)
	a.press("enter", "ctrl+s", "esc")
	if a.form != nil {
		t.Errorf("a field saved as it was counted as a change:\n%s", a.screen())
	}
}

// The edit form changes a password, API key or note into another of them, keeping the secret; a TOTP entry has no
// kind to change; one with notes isn't made a note, whose text is its secret.
func TestEditKind(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(2) // username → kind
	if s := a.screen(); !strings.Contains(s, "● password") || strings.Contains(s, "TOTP") && strings.Contains(s, "○ TOTP") {
		t.Fatalf("the kind:\n%s", s)
	}
	a.press("→", "ctrl+s") // API key
	if len(f.saves) != 1 || f.saves[0].To != (vault.Key{Kind: vault.KindAPIKey, Service: "github", Username: "alice"}) || f.saves[0].Secret != nil || f.saves[0].SetNotes {
		t.Fatalf("saves = %+v", f.saves)
	}
	// Made a note, it keeps its username, as sesh edit --type does.
	a.press("ctrl+k", "e")
	a.tabs(2)
	a.press("→", "ctrl+s") // API key → secure note
	if last := f.saves[len(f.saves)-1]; last.To != (vault.Key{Kind: vault.KindNote, Service: "github", Username: "alice"}) {
		t.Errorf("made a note: %+v", last.To)
	}
	// Notes typed, then the kind crossing a note: refused, so they aren't lost.
	g := newFake()
	b := newApp(t, g, Options{})
	b.press("down", "down", "ctrl+k", "e") // gitlab, an API key
	b.tabs(8)                              // → its notes
	b.press("x", "shift+tab", "shift+tab", "shift+tab", "shift+tab", "shift+tab", "shift+tab", "→", "ctrl+s")
	if s := b.screen(); len(g.saves) != 0 || !strings.Contains(s, "Changing the kind keeps the text as it was") {
		t.Errorf("notes typed, then the kind: saves %+v:\n%s", g.saves, s)
	}
	// A TOTP entry's form has no kind.
	a.press("down", "ctrl+k", "e")
	if s := a.screen(); a.form == nil || strings.Contains(s, "○ secure note") || strings.Contains(s, "● secure note") {
		t.Errorf("a TOTP entry's form:\n%s", s)
	}
	a.press("esc")
	// Into a note, with notes: refused in the form.
	f = newFake()
	f.entries[2].HasNotes = true
	f.notes = map[vault.Key]string{gitlab: "some notes"}
	a = newApp(t, f, Options{})
	a.press("down", "down", "ctrl+k", "e")
	a.tabs(2)
	a.press("→", "ctrl+s") // API key → secure note
	if s := a.screen(); a.form == nil || len(f.saves) != 0 || !strings.Contains(s, "A secure note can't have notes") {
		t.Errorf("a note with notes:\n%s", s)
	}
}

// Keeping the secret shows it as dots, unread until Ctrl-R; nothing typed there changes it.
func TestFormShowsTheCurrentSecret(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(4) // username, kind, the secret's choice → the current password
	if s := a.screen(); !strings.Contains(s, "current password") || strings.Contains(s, "gh-pass") || slices.ContainsFunc(f.reads, func(r string) bool { return strings.HasPrefix(r, "secret ") }) {
		t.Fatalf("the current password should be unread dots:\n%s\nreads %q", s, f.reads)
	}
	a.press("x")
	_, cmd := a.Update(tea.PasteMsg{Content: "y"})
	a.run(cmd)
	a.press("ctrl+r")
	if s := a.screen(); !strings.Contains(s, "gh-pass") || strings.Contains(s, "gh-passx") {
		t.Fatalf("after ctrl+r:\n%s", s)
	}
	a.press("esc")
	if a.form != nil {
		t.Error("looking at the current password counted as a change")
	}
}

// In a window too narrow for the sidebar, Ctrl-G's folders and tags list its rows: Enter shows a row's entries,
// r renames a folder or tag.
func TestFilingPanel(t *testing.T) {
	f := newFake()
	f.entries[2].Tags = []string{"ops"}
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "f")
	s := a.screen()
	for _, want := range []string{"Folders and tags", "All", "work  2", "No folder  1", "#ops  1"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	a.press("down", "enter")
	if s := a.screen(); a.ov != nil || !strings.Contains(s, "in work") || strings.Contains(s, "gitlab") {
		t.Fatalf("work's entries:\n%s", s)
	}
	a.press("ctrl+g", "f")
	if a.ov.sel != 1 {
		t.Errorf("the panel opened on row %d, not the filter's", a.ov.sel)
	}
	a.press("r")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Rename the folder work") {
		t.Errorf("rename:\n%s", s)
	}
	a.press("esc", "ctrl+g", "f", "up", "r")
	if a.form != nil {
		t.Error("All was renamed")
	}
}

// A TOTP entry's key is hidden until Tab reveals it, and copy a value copies it; each read is audited.
func TestTOTPKey(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("down") // the TOTP entry
	if s := a.screen(); !strings.Contains(s, "TOTP key") || strings.Contains(s, seed) {
		t.Fatalf("hidden:\n%s", s)
	}
	a.press("tab")
	if s := a.screen(); !strings.Contains(s, seed[:8]) || !slices.Contains(f.reads, "secret "+code.String()+" in sesh ui, to reveal its key") {
		t.Errorf("revealed: reads %q:\n%s", f.reads, s)
	}
	a.press("ctrl+k", "f")
	if s := a.screen(); !strings.Contains(s, "TOTP key") {
		t.Fatalf("copy a value:\n%s", s)
	}
	a.press("2")
	if !slices.Equal(a.copied, []string{seed}) || !slices.Contains(f.reads, "secret "+code.String()+" in sesh ui, to copy its key") {
		t.Errorf("copied %q, reads %q", a.copied, f.reads)
	}
}

// wideApp is the app on f in a window wide enough for the sidebar.
func wideApp(t *testing.T, f *fakeVault) *app {
	t.Helper()
	a := newApp(t, f, Options{})
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	return a
}

// filedFake has github in work, its code in work, gitlab in work/aws, and github tagged prod.
func filedFake() *fakeVault {
	f := newFake()
	f.entries[0].Tags = []string{"prod"}
	f.entries[2].Folder = "work/aws"
	return f
}

// The sidebar lists folders (counting those inside) and tags, and picking one filters the list.
func TestSidebarFilters(t *testing.T) {
	a := wideApp(t, filedFake())
	s := a.screen()
	for _, w := range []string{"All     3", "work    3", "  aws   1", "#prod   1"} {
		if !strings.Contains(s, w) {
			t.Fatalf("sidebar missing %q:\n%s", w, s)
		}
	}
	a.press("down", "←", "down", "down")
	if s := a.screen(); len(a.rows) != 1 || a.rows[0].Key != gitlab || !strings.Contains(s, "1 of 3 in work/aws") {
		t.Fatalf("work/aws picked: %d rows\n%s", len(a.rows), s)
	}
	a.press("down")
	if len(a.rows) != 1 || a.rows[0].Key != github {
		t.Errorf("#prod picked: %v", a.rows)
	}
	a.press("enter", "esc")
	if a.filter.kind != sideAll || len(a.rows) != 3 || a.quit {
		t.Errorf("Esc in the list should clear the filter first (quit %v, %d rows)", a.quit, len(a.rows))
	}
	a.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
	a.press("down", "←")
	if a.focus == focusSide {
		t.Error("← went to a sidebar that isn't shown")
	}
}

// ↑↓ move into the list, where Space marks; typing goes back to the search, where Space is a space.
func TestFocusFollowsUse(t *testing.T) {
	a := wideApp(t, filedFake())
	a.press("space")
	if a.input.Value() != " " || len(a.marked) != 0 {
		t.Fatalf("Space in the search: query %q, marked %v", a.input.Value(), a.marked)
	}
	a.press("backspace", "down", "space")
	if !a.marked[code] || a.sel != 2 || !strings.Contains(a.screen(), "✓") {
		t.Fatalf("Space in the list should mark and move on: marked %v, sel %d", a.marked, a.sel)
	}
	a.press("g")
	if a.focus != focusSearch || a.input.Value() != "g" {
		t.Errorf("typing in the list: focus %v, query %q", a.focus, a.input.Value())
	}
	a.press("esc")
	if len(a.marked) != 0 || a.input.Value() != "g" {
		t.Errorf("Esc should unmark first: marked %v, query %q", a.marked, a.input.Value())
	}
}

// Ctrl-K with entries marked moves, tags, untags and trashes them together.
func TestMarkedActions(t *testing.T) {
	f := filedFake()
	a := wideApp(t, f)
	a.press("down", "space", "space") // the code and gitlab
	a.press("ctrl+k", "m", "home", "enter")
	if f.entries[1].Folder != "home" || f.entries[2].Folder != "home" || f.entries[0].Folder != "work" || len(a.marked) != 0 {
		t.Fatalf("moved: %+v, still marked %v", f.entries, a.marked)
	}
	if s := a.screen(); !strings.Contains(s, "Moved 2 entries to home") || !strings.Contains(s, "home    2") {
		t.Errorf("after moving:\n%s", s)
	}
	a.press("up", "space", "down", "space", "ctrl+k", "+", "pr", "down", "enter", "enter")
	if !slices.Contains(f.entries[1].Tags, "prod") || !slices.Contains(f.entries[0].Tags, "prod") {
		t.Fatalf("tagged: %+v", f.entries)
	}
	a.press("space", "ctrl+k", "-", "prod", "enter")
	if slices.Contains(f.entries[2].Tags, "prod") || !slices.Contains(f.entries[0].Tags, "prod") {
		t.Errorf("untagged: %+v", f.entries)
	}
	a.press("up", "space", "space", "ctrl+k", "d", "wait", "y")
	if len(f.entries) != 1 || len(f.trash) != 2 || !strings.Contains(a.screen(), "Moved 2 entries to the trash") {
		t.Errorf("trashed: %d left, %d in the trash\n%s", len(f.entries), len(f.trash), a.screen())
	}
}

// Ctrl-K in the sidebar renames a folder, the filter following it.
func TestSidebarRename(t *testing.T) {
	f := filedFake()
	a := wideApp(t, f)
	a.press("down", "←", "down", "ctrl+k", "r", "ctrl+u", "job", "enter")
	if f.entries[0].Folder != "job" || f.entries[2].Folder != "job/aws" {
		t.Fatalf("renamed: %+v", f.entries)
	}
	if s := a.screen(); a.filter.name != "job" || len(a.rows) != 3 || !strings.Contains(s, "Renamed the folder work to job (3 entries)") {
		t.Errorf("filter %q, %d rows:\n%s", a.filter.name, len(a.rows), s)
	}
	if r := a.side[a.sideSel]; r.name != "job" {
		t.Errorf("the sidebar's cursor left the folder renamed: on %+v", r)
	}
	a.press("ctrl+k", "r", "ctrl+u", "job/inner", "enter")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "can't move inside itself") {
		t.Errorf("a folder renamed into itself:\n%s", s)
	}
	a.press("esc", "esc", "down", "down", "ctrl+k", "r", "ctrl+u", "bad tag", "enter")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "the tag") {
		t.Errorf("a tag name with a space:\n%s", s)
	}
}

// A click in the sidebar picks its row.
func TestSidebarClick(t *testing.T) {
	a := wideApp(t, filedFake())
	a.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: 3, Y: 4}) // the second row: work
	if a.filter.name != "work" || a.focus != focusSide {
		t.Errorf("clicked: filter %+v, focus %v", a.filter, a.focus)
	}
}

// A marked entry another command deleted is left out of what's done to the marks, and unmarked.
func TestMarksGoneElsewhere(t *testing.T) {
	f := filedFake()
	a := wideApp(t, f)
	a.press("down", "space", "space", "gitlab") // the code and gitlab marked, then a search
	f.entries = slices.DeleteFunc(f.entries, func(e vault.Entry) bool { return e.Key == code })
	f.changed = true
	a.tick(time.Second)
	if len(a.marked) != 2 {
		t.Fatalf("marks after a search's results: %v", a.marked)
	}
	a.press("ctrl+k", "m", "home", "enter")
	if s := a.screen(); f.entries[1].Folder != "home" || len(a.marked) != 0 || !strings.Contains(s, "Moved 1 entry to home; 1 marked was gone") {
		t.Errorf("moving with one gone: %+v, marked %v\n%s", f.entries, a.marked, s)
	}
	a.press("esc", "down", "space")
	var gone vault.Key
	for k := range a.marked {
		gone = k
	}
	f.entries = slices.DeleteFunc(f.entries, func(e vault.Entry) bool { return e.Key == gone })
	a.press("ctrl+k", "d", "wait", "y")
	if s := a.screen(); len(a.marked) != 0 || len(f.trash) != 0 || !strings.Contains(s, "the entries marked are gone") {
		t.Errorf("acting on marks all gone: marked %v\n%s", a.marked, s)
	}
}

// Marks the list doesn't show are said to be, and a trash of one names it.
func TestHiddenMarksNamed(t *testing.T) {
	a := wideApp(t, filedFake())
	a.press("down", "down", "space", "←", "down", "down", "down") // gitlab marked, then #prod
	a.press("enter", "ctrl+k")
	if s := a.screen(); !strings.Contains(s, "1 entry marked (1 not shown)") || !strings.Contains(s, "the selected entry's actions") {
		t.Fatalf("menu with a mark not shown:\n%s", s)
	}
	a.press("d")
	if q := a.ov.question; !strings.Contains(q, "API key gitlab") || !strings.Contains(q, "not shown") {
		t.Errorf("the trash's question: %q", q)
	}
}

// A filter another command empties goes back to every entry, keeping the selection and its code.
func TestFilterGoneElsewhere(t *testing.T) {
	f := filedFake()
	a := wideApp(t, f)
	a.press("down", "←", "down", "enter", "down") // work, then its code selected
	if e := a.selected(); e == nil || e.Key != code {
		t.Fatalf("selected %v", e)
	}
	for i := range f.entries {
		f.entries[i].Folder = strings.Replace(f.entries[i].Folder, "work", "job", 1)
	}
	f.changed = true
	a.tick(time.Second)
	if e := a.selected(); a.filter.kind != sideAll || e == nil || e.Key != code || a.keys[code] == nil {
		t.Errorf("filter %+v, selected %v, its key held %v", a.filter, e, a.keys[code] != nil)
	}
}

// The sidebar keeps its rows in view as the window changes, and gives up the focus when it goes.
func TestSidebarResize(t *testing.T) {
	f := filedFake()
	for i := range 30 {
		f.entries[0].Tags = append(f.entries[0].Tags, fmt.Sprintf("t%02d", i))
	}
	a := wideApp(t, f)
	a.press("down", "←")
	for range 40 {
		a.press("down")
	}
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 60})
	if a.sideTop != 0 {
		t.Errorf("after growing, the sidebar starts at row %d", a.sideTop)
	}
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	filter := a.filter
	a.press("enter")
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	a.press("up")
	if a.filter != filter || a.focus != focusList {
		t.Errorf("↑ after the sidebar went and came back: filter %+v, focus %v", a.filter, a.focus)
	}
}

// A paste goes to the search, which takes the focus; a click lands on the list beside the sidebar.
func TestPasteAndClickBesideSidebar(t *testing.T) {
	a := wideApp(t, filedFake())
	a.press("down")
	_, cmd := a.Update(tea.PasteMsg{Content: "git"})
	a.run(cmd)
	if a.focus != focusSearch {
		t.Errorf("after a paste the focus is %v", a.focus)
	}
	a.press("esc")
	a.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: a.listX() + 3, Y: 5}) // the third entry
	if a.sel != 2 || a.focus != focusList {
		t.Errorf("clicked the third entry: sel %d, focus %v", a.sel, a.focus)
	}
}

// A deep folder keeps its count in the sidebar.
func TestSidebarDeepFolder(t *testing.T) {
	f := filedFake()
	f.entries[2].Folder = "a/b/c/d/e/f/g/h/i/j/k/l"
	a := wideApp(t, f)
	if s := a.screen(); !regexp.MustCompile(`│ +l +1 │`).MatchString(s) {
		t.Errorf("the deepest folder's count:\n%s", s)
	}
}

// A trash of one marked entry names it shortened, as the other questions do.
func TestMarkedTrashLongName(t *testing.T) {
	f := filedFake()
	for i := range f.entries {
		f.entries[i].Key.Service = strings.Repeat("git-long-name-", 18) + fmt.Sprint(i)
	}
	a := newApp(t, f, Options{})
	a.press("down", "down", "space", "ctrl+k", "d")
	if q := a.ov.question; !strings.Contains(q, "…") || strings.Count(q, "git-long-name") > 8 {
		t.Errorf("the question's name isn't shortened: %q", q)
	}
	a.press("esc", "esc", "zzz") // the mark kept, its entry no longer listed
	a.press("ctrl+k", "d")
	if q := a.ov.question; !strings.Contains(q, "…") || !strings.Contains(q, "not shown") {
		t.Errorf("a mark not shown, with a long name: %q", q)
	}
}

// A reveal that comes back once its entry is no longer listed isn't kept.
func TestRevealLandsOnNothingListed(t *testing.T) {
	f := filedFake()
	a := wideApp(t, f)
	_, read := a.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	entries := f.entries
	f.entries, f.changed = nil, true // another command empties the vault
	a.tick(time.Second)
	f.entries = entries
	a.run(read)
	if a.shown != nil {
		t.Error("a reveal was kept for an entry not listed")
	}
}

// healthFake has github and gitlab sharing a weak secret, and an old strong password.
func healthFake() *fakeVault {
	f := newFake()
	f.secrets[github], f.secrets[gitlab] = "password1", "password1"
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	f.entries = append(f.entries, vault.Entry{Key: bank, UpdatedAt: time.Unix(1_600_000_000, 0)})
	f.secrets[bank] = "Wq7#vPz!2kLm9$Xr-Tb4"
	return f
}

// The report lists each problem; Enter goes to its entry, set to generate a new password.
func TestHealthReport(t *testing.T) {
	f := healthFake()
	a := newApp(t, f, Options{OldAfter: 365 * 24 * time.Hour})
	a.press("git", "ctrl+g", "r")
	s := a.screen()
	for _, want := range []string{"4 problems in 3 passwords and API keys", "github (alice) · weak", "github (alice) · reused: same as gitlab", "gitlab · reused: same as github (alice)", "bank · old: changed"} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q:\n%s", want, s)
		}
	}
	if strings.Count(strings.Join(f.reads, " "), "health") != 1 {
		t.Errorf("reads = %q", f.reads)
	}
	a.press("enter")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Edit github (alice)") || !strings.Contains(s, "● generate one") {
		t.Fatalf("Enter on the weak password:\n%s", s)
	}
	if a.input.Value() != "" || len(a.rows) != 4 {
		t.Errorf("the search should be cleared to find it: %q, %d rows", a.input.Value(), len(a.rows))
	}
}

// An entry gone by the time it's chosen is said to be; an API key's form keeps its secret.
func TestHealthReportGoneAndKeys(t *testing.T) {
	f := healthFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "r")
	f.entries = slices.DeleteFunc(f.entries, func(e vault.Entry) bool { return e.Key == github })
	a.press("enter")
	if s := a.screen(); a.form != nil || !strings.Contains(s, "github (alice) isn't in the vault any more") {
		t.Errorf("choosing an entry that's gone:\n%s", s)
	}
	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+g", "r", "down", "enter") // gitlab, the first reused row
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Edit gitlab") || !strings.Contains(s, "● keep") {
		t.Errorf("an API key's form:\n%s", s)
	}
}

// A vault with nothing wrong says so.
func TestHealthReportClean(t *testing.T) {
	f := newFake()
	f.entries = f.entries[:1]
	f.secrets[github] = "Wq7#vPz!2kLm9$Xr-Tb4"
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "r")
	if s := a.screen(); !strings.Contains(s, "no problems in 1 password or API key") || !strings.Contains(s, "Nothing is weak, used twice, or old.") {
		t.Errorf("a clean report:\n%s", s)
	}
}

// An entry with notes opens once they've been read.
func TestHealthReportWaitsForNotes(t *testing.T) {
	f := healthFake()
	f.entries[2].HasNotes = true // gitlab: not selected, so its notes aren't read yet
	f.notes = map[vault.Key]string{gitlab: "the note"}
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "r", "down", "enter")
	if a.form == nil {
		t.Fatalf("no form once its notes were read:\n%s", a.screen())
	}
	if i := slices.IndexFunc(a.form.inputs, func(in *input) bool { return in.kind == inputNotes }); a.form.inputs[i].area.Value() != "the note" {
		t.Errorf("the form's notes = %q", a.form.inputs[i].area.Value())
	}
}

// enterHeld is Enter on the report's row, its search not run yet.
func enterHeld(a *app) tea.Cmd {
	_, cmd := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	return cmd
}

// A form waited for isn't opened once the user does something else, or the app locks.
func TestHealthReportPendingEdit(t *testing.T) {
	a := newApp(t, healthFake(), Options{})
	a.press("ctrl+g", "r")
	held := enterHeld(a)
	a.press("x")
	if a.editing != (vault.Key{}) {
		t.Error("a key pressed while it waited left the form to open")
	}
	a.run(held)
	if s := a.screen(); a.form != nil || strings.Contains(s, "isn't in the vault") {
		t.Errorf("typing while it waited:\n%s", s)
	}

	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+g", "r")
	held = enterHeld(a)
	a.press("ctrl+g", "a", "my new entry")
	a.editing = github // as if nothing the user did had dropped it
	a.run(held)
	if a.form == nil || a.form.title != "Add an entry" {
		t.Errorf("a form opened meanwhile was replaced: %v", a.form)
	}

	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+g", "r")
	enterHeld(a)
	a.lock("test")
	if a.editing != (vault.Key{}) {
		t.Error("a lock left a form to open after the next unlock")
	}
}

// An error stays said; an unreadable row says why and keeps the report; a second report replaces the first.
func TestHealthReportPanel(t *testing.T) {
	f := healthFake()
	f.healthErr = errors.New("database disk image is malformed")
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "r", "down")
	if s := a.screen(); !strings.Contains(s, "malformed") || strings.Contains(s, "Nothing is weak") {
		t.Errorf("an error, then a key:\n%s", s)
	}

	f = healthFake()
	f.unreadable = []vault.Key{gitlab}
	a = newApp(t, f, Options{})
	a.press("ctrl+g", "r")
	for range 3 {
		a.press("down")
	}
	a.press("enter")
	if s := a.screen(); a.ov == nil || !strings.Contains(s, "doesn't decrypt: sesh doctor says more") || !strings.Contains(s, "in 3 passwords and API keys") {
		t.Errorf("Enter on an unreadable row:\n%s", s)
	}

	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+g")
	_, first := a.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	a.press("esc")
	_, second := a.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	a.run(first)
	a.run(second)
	if len(a.ov.items) != 3 { // weak, and the two reused; nothing old with the age check off
		t.Errorf("two reports in one panel: %d rows", len(a.ov.items))
	}
}

// A long report, with lines between its groups, fits the window.
func TestHealthReportFits(t *testing.T) {
	f := healthFake()
	for i := range 20 {
		k := vault.Key{Kind: vault.KindPassword, Service: fmt.Sprintf("weak%02d", i)}
		f.entries = append(f.entries, vault.Entry{Key: k, UpdatedAt: time.Unix(1_600_000_000, 0)})
		f.secrets[k] = "abc"
		f.unreadable = append(f.unreadable, k)
	}
	a := newApp(t, f, Options{OldAfter: time.Hour})
	a.press("ctrl+g", "r") // the top of it, where the groups and the lines between them are
	if lines := strings.Count(a.View().Content, "\n") + 1; lines > a.height {
		t.Errorf("the report drew %d lines in %d:\n%s", lines, a.height, a.screen())
	}
}

// Enter pressed twice opens the form, and copies nothing.
func TestHealthReportDoubleEnter(t *testing.T) {
	f := healthFake()
	f.entries[2].HasNotes = true // gitlab: its notes read after it's listed
	f.notes = map[vault.Key]string{gitlab: "n"}
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "r", "down")
	held := enterHeld(a)
	a.press("enter")
	a.run(held)
	if len(a.copied) != 0 || a.form == nil {
		t.Errorf("Enter twice: copied %q, form %v", a.copied, a.form != nil)
	}
}

// settingsApp is the app with a fake config: its settings, and the changes asked of it.
func settingsApp(t *testing.T) (*app, *[]string) {
	t.Helper()
	a, asked, _ := settingsAppValues(t)
	return a, asked
}

// settingsAppValues is settingsApp, with the fake config's values, to change as another command would.
func settingsAppValues(t *testing.T) (*app, *[]string, map[string]string) {
	t.Helper()
	values := map[string]string{"history.keep": "10", "health.old_after_days": "365", "ui.lock_on_quit": "false"}
	inFile := map[string]bool{}
	said := func(key string) string {
		if inFile[key] {
			return "config file"
		}
		return "default"
	}
	var asked []string
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) {
			all := []Setting{
				{Key: "history.keep", Value: values["history.keep"], Raw: values["history.keep"], Default: "10", Said: said("history.keep"), Applies: "for other commands now, and in sesh ui from its next start", Editable: true},
				{Key: "health.old_after_days", Value: values["health.old_after_days"], Raw: values["health.old_after_days"], Default: "365", Said: said("health.old_after_days"), Applies: "at the next health check", Editable: true},
				{Key: "trash.keep_days", Value: "0", Raw: "0", Said: "environment: SESH_TRASH_KEEP_DAYS", Env: "SESH_TRASH_KEEP_DAYS", Editable: true},
				{Key: "db_path", Value: "/v.db", Said: "default"},
				{Key: "ui.lock_on_quit", Value: map[string]string{"true": "on", "false": "off"}[values["ui.lock_on_quit"]], Raw: values["ui.lock_on_quit"], Default: "true", Said: "default", Applies: "when sesh ui next quits", Editable: true, Switch: true},
				{Key: "agent.lock_on_sleep", Value: "off", Raw: "false", Default: "true", Said: "environment: SESH_AGENT_LOCK_ON_SLEEP", Env: "SESH_AGENT_LOCK_ON_SLEEP", Editable: true, Switch: true},
			}
			for i := range all {
				all[i].File, all[i].NoFile = "~/.config/sesh/config.toml", len(inFile) == 0
			}
			return all, nil
		},
		SetSetting: func(key, value string) (Live, error) {
			asked = append(asked, key+"="+value)
			if value == "-1" {
				return Live{}, errors.New(key + ` = "-1": want a whole number`)
			}
			values[key], inFile[key] = cmp.Or(value, map[string]string{"history.keep": "10", "health.old_after_days": "365"}[key]), value != ""
			days, _ := strconv.Atoi(values["health.old_after_days"]) //nolint:errcheck // test
			return Live{OldAfter: time.Duration(days) * 24 * time.Hour}, nil
		},
	})
	return a, &asked, values
}

// A setting is changed through a one-line form; the panel stays, shows it, and the app takes up what it uses.
func TestSettingsChange(t *testing.T) {
	a, asked := settingsApp(t)
	a.press("ctrl+g", ",", "down", "down", "down")
	if s := a.screen(); !strings.Contains(s, "saved in ~/.config/sesh/config.toml, which the first change makes") {
		t.Errorf("before the file is made:\n%s", s)
	}
	a.press("enter", "ctrl+u", "90", "enter")
	if !slices.Equal(*asked, []string{"health.old_after_days=90"}) || a.opts.OldAfter != 90*24*time.Hour {
		t.Fatalf("asked %q, old after %v", *asked, a.opts.OldAfter)
	}
	if s := a.screen(); a.ov == nil || a.ov.kind != panelSettings || !strings.Contains(s, "health.old_after_days     90") || !strings.Contains(s, "Saved health.old_after_days in ~/.config/sesh/config.toml") || !strings.Contains(s, "saved in ~/.config/sesh/config.toml") || strings.Contains(s, "the first change makes") {
		t.Errorf("after saving:\n%s", s)
	}
	a.press("up", "enter", "ctrl+u", "-1", "enter")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "want a whole number") {
		t.Errorf("a value refused:\n%s", s)
	}
	// Set by another command since the panel was read: emptying it takes it out.
	if _, err := a.opts.SetSetting("history.keep", "7"); err != nil {
		t.Fatal(err)
	}
	a.press("ctrl+u", "enter")
	if (*asked)[len(*asked)-1] != "history.keep=" {
		t.Fatalf("set elsewhere, then emptied: asked %q\n%s", *asked, a.screen())
	}
	// Emptied at its default: nothing to take out. Emptied once set: taken out.
	a.press("enter")
	a.press("ctrl+u", "enter")
	if len(*asked) != 4 || !strings.Contains(a.screen(), "history.keep is at its default already") {
		t.Errorf("emptied at its default: asked %q\n%s", *asked, a.screen())
	}
	a.press("down", "enter", "ctrl+u", "enter")
	if (*asked)[len(*asked)-1] != "health.old_after_days=" || !strings.Contains(a.screen(), "Took health.old_after_days out of ~/.config/sesh/config.toml") {
		t.Errorf("emptied: asked %q\n%s", *asked, a.screen())
	}
}

// Enter turns a switch over at once, with nothing to type.
func TestSettingsSwitch(t *testing.T) {
	a, asked := settingsApp(t)
	a.press("ctrl+g", ",", "down", "down", "down", "down", "down", "down", "enter")
	if s := a.screen(); a.form != nil || !slices.Equal(*asked, []string{"ui.lock_on_quit=true"}) || !strings.Contains(s, "Turned ui.lock_on_quit on in ~/.config/sesh/config.toml:") || !strings.Contains(s, "ui.lock_on_quit           on") || !strings.Contains(s, "turn it off") {
		t.Fatalf("asked %q, form %v\n%s", *asked, a.form != nil, s)
	}
	a.press("enter")
	if s := a.screen(); (*asked)[1] != "ui.lock_on_quit=false" || !strings.Contains(s, "Turned ui.lock_on_quit off") {
		t.Errorf("asked %q\n%s", *asked, s)
	}
}

// One set by the environment, or the vault's place, isn't changed from the app, and says why.
func TestSettingsNotChanged(t *testing.T) {
	a, asked := settingsApp(t)
	a.press("ctrl+g", ",", "down", "down", "down", "down", "enter")
	if s := a.screen(); a.form != nil || !strings.Contains(s, "set by SESH_TRASH_KEEP_DAYS") {
		t.Errorf("one set by the environment:\n%s", s)
	}
	a.press("down", "enter")
	if s := a.screen(); a.form != nil || !strings.Contains(s, "move the vault") || len(*asked) != 0 {
		t.Errorf("the vault's place: asked %q\n%s", *asked, s)
	}
	// A switch the environment sets doesn't offer to turn it over.
	a.press("down", "down")
	if s := a.screen(); strings.Contains(s, "turn it") || !strings.Contains(s, "set by SESH_AGENT_LOCK_ON_SLEEP") {
		t.Errorf("a switch set by the environment:\n%s", s)
	}
	a.press("enter")
	if len(*asked) != 0 {
		t.Errorf("a switch set by the environment was changed: %q", *asked)
	}
}

// An unchanged value writes nothing; lowering one that deletes asks first, and emptying one compares its default.
func TestSettingsLoss(t *testing.T) {
	a, asked := settingsApp(t)
	a.press("ctrl+g", ",", "down", "down", "enter", "enter")
	if len(*asked) != 0 || !strings.Contains(a.screen(), "Nothing changed: history.keep is 10 already") {
		t.Fatalf("unchanged: asked %q\n%s", *asked, a.screen())
	}
	a.press("enter", "ctrl+u", "4", "enter")
	if q := a.ov.question; len(*asked) != 0 || !strings.Contains(q, "beyond its newest 4 will be deleted for good") {
		t.Fatalf("lowering history.keep: asked %q, question %q", *asked, q)
	}
	a.press("n")
	if len(*asked) != 0 || a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("no: asked %q, panel %v", *asked, a.ov)
	}
	a.press("enter", "ctrl+u", "4", "enter", "wait", "y")
	if !slices.Equal(*asked, []string{"history.keep=4"}) || a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("yes: asked %q", *asked)
	}
	// From 4, an empty value goes back to the default 10: nothing lost, nothing asked.
	a.press("enter", "ctrl+u", "enter")
	if (*asked)[len(*asked)-1] != "history.keep=" || a.ov.kind != panelSettings {
		t.Errorf("back to the default: asked %q", *asked)
	}
	// From 50, it would lose: asked.
	a.press("enter", "ctrl+u", "50", "enter", "enter", "ctrl+u", "enter")
	if q := a.ov.question; !strings.Contains(q, "beyond its newest 10 will be deleted") {
		t.Errorf("back to the default from 50: question %q", q)
	}
}

// The panel fits the smallest window it's drawn in.
func TestSettingsSmallWindow(t *testing.T) {
	a := newApp(t, newFake(), Options{Settings: func() ([]Setting, error) {
		// The longest of the details the real settings have.
		return []Setting{{Key: "backup.dir", Value: "/Users/someone/Library/Application Support/sesh/backups", Raw: "", Said: "default: next to the vault", Editable: true,
			Applies: "for sesh's agent when it next starts, and in sesh ui from its next start"}}, nil
	}})
	a.Update(tea.WindowSizeMsg{Width: minWidth, Height: minHeight})
	a.press("ctrl+g", ",")
	if s := a.screen(); strings.Count(s, "\n")+1 > minHeight || !strings.Contains(s, "backup.dir") {
		t.Errorf("the panel at %dx%d:\n%s", minWidth, minHeight, s)
	}
}

// A loss is judged against the file as it is when saving, not as the panel last read it.
func TestSettingsLossAgainstNow(t *testing.T) {
	a, asked, values := settingsAppValues(t)
	a.press("ctrl+g", ",")
	values["history.keep"] = "20" // another command raises it
	a.press("down", "down", "enter", "ctrl+u", "15", "enter")
	if a.ov == nil || !strings.Contains(a.ov.question, "beyond its newest 15") || len(*asked) != 0 {
		t.Errorf("15 from 20 (the panel showing 10): asked %q, panel %+v", *asked, a.ov)
	}
}

// The settings' first row runs the checks on the open vault and lists them, with what to do; Esc goes back.
func TestChecksPanel(t *testing.T) {
	f := newFake()
	f.checks = Checks{Summary: "FAIL: 1 problem", Checks: []Check{
		{Section: "Setup", Mark: "ok", Label: "Agent", Value: "running, unlocked"},
		{Section: "Vault", Mark: "FAIL", Label: "Entries", Value: "1 of 3 entries can't be read", Details: []string{"password/c/u: times don't read"}},
	}, ToDo: [][]string{{"Restore it from a backup, or delete it:", "sesh trash --purge --force password/c/u"}}}
	a := newApp(t, f, Options{Settings: func() ([]Setting, error) { return nil, nil }})
	a.press("ctrl+g", ",", "enter")
	s := a.screen()
	for _, want := range []string{"Checks: FAIL: 1 problem", "Agent", "1 of 3 entries can't be read", "Restore it from a backup"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	if !slices.Contains(f.reads, "checks") {
		t.Errorf("reads = %q", f.reads)
	}
	a.press("down")
	if s := a.screen(); !strings.Contains(s, "password/c/u: times don't read") {
		t.Errorf("the selected check's details:\n%s", s)
	}
	a.press("down")
	if s := a.screen(); !strings.Contains(s, "Run: sesh trash --purge --force password/c/u") {
		t.Errorf("the step's command:\n%s", s)
	}
	a.press("esc")
	if a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("Esc went to %+v", a.ov)
	}
}

// A check's long details are cut to the window, saying how many lines are left out; the lines between sections stay.
func TestChecksPanelFits(t *testing.T) {
	f := newFake()
	var details []string
	for i := range 60 {
		details = append(details, fmt.Sprintf("password/e%02d: secret doesn't decrypt", i))
	}
	f.checks = Checks{Summary: "FAIL: 60 problems", Checks: []Check{
		{Section: "Setup", Mark: "ok", Label: "Agent", Value: "running"},
		{Section: "Vault", Mark: "FAIL", Label: "Entries", Value: "60 of 60 entries can't be read", Details: details},
	}}
	a := newApp(t, f, Options{Settings: func() ([]Setting, error) { return nil, nil }})
	a.press("ctrl+g", ",", "enter", "down")
	s := a.screen()
	if strings.Count(s, "\n")+1 > a.height || !strings.Contains(s, "more lines") || !strings.Contains(s, "password/e00") {
		t.Errorf("long details:\n%s", s)
	}
	if !strings.Contains(s, "│  ────") {
		t.Errorf("the line between the sections went:\n%s", s)
	}
}

// Opened again while it runs, the panel waits for that run rather than starting another.
func TestChecksOnce(t *testing.T) {
	f := newFake()
	f.checks = Checks{Summary: "OK: no problems"}
	a := newApp(t, f, Options{Settings: func() ([]Setting, error) { return nil, nil }})
	a.press("ctrl+g", ",")
	_, run := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.press("esc")
	_, again := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(run)
	a.run(again)
	if n := strings.Count(strings.Join(f.reads, " "), "checks"); n != 1 || !strings.Contains(a.screen(), "OK: no problems") {
		t.Errorf("checks run %d times:\n%s", n, a.screen())
	}
}

// fakeImport is an import of the fake vault's, planning what its plans say.
type fakeImport struct {
	plans   map[string]ImportPlan
	failing map[string]error // what each plan fails with, if it does
	applyTo func() (string, error)
	asked   []string // each plan's onConflict, then "apply"
	closed  bool
}

func (f *fakeImport) Plan(onConflict string) (ImportPlan, error) {
	f.asked = append(f.asked, "plan "+onConflict)
	return f.plans[onConflict], f.failing[onConflict]
}

func (f *fakeImport) Apply() (string, error) {
	f.asked = append(f.asked, "apply")
	if f.applyTo != nil {
		return f.applyTo()
	}
	return "Imported 2 entries from Bitwarden.", nil
}

func (f *fakeImport) Close() { f.closed = true }

func (f *fakeVault) StartImport(source string, files []string, password []byte) (Importer, error) {
	f.starts = append(f.starts, fmt.Sprintf("%s %q %s", source, files, password))
	if f.err != nil {
		return nil, f.err
	}
	if f.importPassword != "" && string(password) != f.importPassword {
		return nil, NeedsPassword("Bitwarden export")
	}
	return f.importing, nil
}

// A TOTP entry's menu shows its key as a QR code, read as the audit log records; c copies the link; a small window says what it needs.
func TestShowQR(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	for i := 0; a.selected() == nil || a.selected().Key != code; i++ {
		if i > 5 {
			t.Fatal("the TOTP entry isn't listed")
		}
		a.press("down")
	}
	a.press("ctrl+k", "q")
	if s := a.screen(); a.ov == nil || a.ov.kind != panelQR || !strings.Contains(s, "▀") || !strings.Contains(s, "it adds github") {
		t.Fatalf("the QR panel:\n%s", s)
	}
	if !slices.Contains(f.reads, "secret "+code.String()+" in sesh ui, to show its key as a QR code") {
		t.Errorf("reads %q", f.reads)
	}
	a.press("c")
	if len(a.copied) != 1 || !strings.HasPrefix(a.copied[0], "otpauth://totp/github:alice?secret=") {
		t.Errorf("copied %q", a.copied)
	}
	if s := a.screen(); !strings.Contains(s, "close (30s)") {
		t.Errorf("no countdown:\n%s", s)
	}
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	if s := a.screen(); strings.Contains(s, "▀") || !strings.Contains(s, "too small for the QR code") {
		t.Errorf("a small window:\n%s", s)
	}
	// It says how wide a window it needs, and draws there.
	width := lipgloss.Width(a.ov.qr[0]) + 12
	a.Update(tea.WindowSizeMsg{Width: width - 1, Height: 50})
	if s := a.screen(); strings.Contains(s, "▀") || !strings.Contains(s, "needs about "+strconv.Itoa(width)+" columns") {
		t.Errorf("a column short:\n%s", s)
	}
	a.Update(tea.WindowSizeMsg{Width: width, Height: 50})
	if s := a.screen(); !strings.Contains(s, "▀") {
		t.Errorf("wide enough:\n%s", s)
	}
	a.press("esc")
	if a.ov == nil || a.ov.kind != panelMenu {
		t.Fatal("esc didn't go back to the menu")
	}
	// A password's menu doesn't offer it.
	a.press("esc", "up")
	if a.ov != nil || a.selected().Kind != vault.KindPassword {
		t.Fatalf("not back on the password: %+v", a.selected())
	}
	a.press("ctrl+k")
	if strings.Contains(a.screen(), "QR code") {
		t.Errorf("offered for a password:\n%s", a.screen())
	}
}

// Adding a TOTP entry can read its QR code from an image file, the path as typed; one that can't be read is said in the form.
func TestAddQRImage(t *testing.T) {
	f := newFake()
	link := "otpauth://totp/Shop:dee?secret=JBSWY3DPEHPK3PXP&issuer=Shop"
	var paths []string
	a := newApp(t, f, Options{ReadQRImage: func(path string) (ScannedQR, error) {
		paths = append(paths, path)
		if path != "~/shot.png" {
			return ScannedQR{}, errors.New("no QR code found in " + path)
		}
		return ScannedQR{Link: []byte(link), Issuer: "Shop", Account: "dee"}, nil
	}})
	a.press("ctrl+g", "a", "→", "→", "→") // TOTP
	a.tabs(3)                             // name, account, then the key's choice
	a.press("→")
	if s := a.screen(); a.form.inputs[a.form.focus].choices[1] != totpImage || len(a.form.inputs[a.form.focus].choices) != 2 || !strings.Contains(s, "image file") || strings.Contains(s, "scanning") {
		t.Fatalf("the choice:\n%s", s)
	}
	a.press("ctrl+s")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Give the image file") || len(paths) != 0 {
		t.Fatalf("no file:\n%s", s)
	}
	a.press("tab", "~/other.png", "ctrl+s")
	if s := a.screen(); len(f.saves) != 0 || a.form == nil || !strings.Contains(s, "No QR code read: no QR code found in ~/other.png") {
		t.Fatalf("a file without a code:\n%s", s)
	}
	a.press("ctrl+u", "~/shot.png", "ctrl+s")
	if len(f.saves) != 1 || f.saves[0].To != (vault.Key{Kind: vault.KindTOTP, Service: "Shop", Username: "dee"}) || string(f.saves[0].Secret) != link {
		t.Fatalf("saves %+v:\n%s", f.saves, a.screen())
	}
}

// A long link's QR code, wider than a panel usually is, widens its panel to fit.
func TestShowQRWide(t *testing.T) {
	f := newFake()
	long := vault.Key{Kind: vault.KindTOTP, Service: "Example Company VPN", Username: "alice.longname@example-company.com"}
	f.entries = append(f.entries, vault.Entry{Key: long, Settings: vault.Settings{TOTP: totp.Params{Algorithm: "SHA512", Digits: 8, Period: 60}}})
	f.secrets[long] = strings.Repeat("JBSWY3DPEHPK3PXP", 4)
	a := newApp(t, f, Options{})
	a.Update(tea.WindowSizeMsg{Width: 160, Height: 60})
	a.press("example", "ctrl+k", "q")
	if a.ov == nil || a.ov.kind != panelQR || len(a.ov.qr) == 0 || lipgloss.Width(a.ov.qr[0]) <= 58 {
		t.Fatalf("not a wide code:\n%s", a.screen())
	}
	if s := a.screen(); !strings.Contains(s, "▀") {
		t.Errorf("not drawn:\n%s", s)
	}
}

// The QR code closes after as long as a secret revealed shows, back to the menu.
func TestShowQRCloses(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	for a.selected() == nil || a.selected().Key != code {
		a.press("down")
	}
	a.press("ctrl+k", "q")
	a.tick(revealFor - time.Second)
	if a.ov == nil || a.ov.kind != panelQR {
		t.Fatal("closed early")
	}
	a.tick(time.Second)
	if s := a.screen(); a.ov == nil || a.ov.kind != panelMenu || !strings.Contains(s, "The QR code closed after 30 seconds") {
		t.Errorf("still open, or not said:\n%s", s)
	}
}

// fileFake is the fake vault with a text file entry and a binary one.
func fileFake() (f *fakeVault, text, binary vault.Key) {
	f = newFake()
	text = vault.Key{Kind: vault.KindFile, Service: "kubeconfig"}
	binary = vault.Key{Kind: vault.KindFile, Service: "cert"}
	f.entries = append(f.entries,
		vault.Entry{Key: text, Settings: vault.Settings{FileName: "config"}, Size: 28},
		vault.Entry{Key: binary, Settings: vault.Settings{FileName: "cert.der"}, Size: 9})
	f.secrets[text], f.secrets[binary] = "apiVersion: v1\nclusters: []\n", "\x00\x01binary\xff"
	return f, text, binary
}

// A file entry shows its file's name and size; Enter copies a text one, not a binary one; Ctrl-K saves it to a file.
func TestFileEntryInApp(t *testing.T) {
	f, text, binary := fileFake()
	var saved []string
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second, SaveFile: func(typed string, content []byte) (string, error) {
		saved = append(saved, typed+"="+string(content))
		return typed, nil
	}})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	a.press("kubeconfig")
	if s := a.screen(); a.selected() == nil || a.selected().Key != text || !strings.Contains(s, "config · 28 bytes") {
		t.Fatalf("the preview:\n%s", s)
	}
	a.press("enter")
	if len(a.copied) != 1 || a.copied[0] != "apiVersion: v1\nclusters: []\n" {
		t.Errorf("copied %q", a.copied)
	}
	a.press("ctrl+k", "s")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "~/config") {
		t.Fatalf("the save form:\n%s", s)
	}
	a.press("enter")
	if !slices.Equal(saved, []string{"~/config=apiVersion: v1\nclusters: []\n"}) || !strings.Contains(a.screen(), "Saved kubeconfig to ~/config") {
		t.Errorf("saved %q:\n%s", saved, a.screen())
	}
	if !slices.Contains(f.reads, "secret "+text.String()+" in sesh ui, to save it to a file") {
		t.Errorf("reads %q", f.reads)
	}
	// A binary one isn't copied, nor its content shown.
	for range len("kubeconfig") {
		a.press("backspace")
	}
	a.press("cert")
	if a.selected() == nil || a.selected().Key != binary {
		t.Fatalf("selected %+v", a.selected())
	}
	a.press("enter")
	if len(a.copied) != 1 || !strings.Contains(a.screen(), "binary file, which the clipboard can't hold") {
		t.Errorf("copied %q:\n%s", a.copied, a.screen())
	}
	a.press("tab")
	if s := a.screen(); strings.Contains(s, "binary\xff") || !strings.Contains(s, "binary: Ctrl-K, save to a file") {
		t.Errorf("revealed:\n%s", s)
	}
	// A password's menu has nothing to save.
	for range len("cert") {
		a.press("backspace")
	}
	for a.selected().Kind != vault.KindPassword {
		a.press("down")
	}
	a.press("ctrl+k")
	if a.ov == nil || a.ov.kind != panelMenu || slices.ContainsFunc(a.ov.items, func(it item) bool { return it.key == "s" }) {
		t.Errorf("a password's menu:\n%s", a.screen())
	}
}

// Adding a file entry reads the file from the path typed, naming the entry after it given no name; editing can give it a new one.
func TestFileEntryForm(t *testing.T) {
	f, text, _ := fileFake()
	var read []string
	a := newApp(t, f, Options{ReadFile: func(typed string) ([]byte, string, error) {
		read = append(read, typed)
		if typed == "~/nope" {
			return nil, "", errors.New("no such file")
		}
		return []byte("content of " + typed), filepath.Base(typed), nil
	}})
	a.press("ctrl+g", "a", "→", "→", "→", "→") // file
	if !slices.ContainsFunc(a.form.inputs, func(in *input) bool { return in.label == "file" && in.visible() }) {
		t.Fatalf("no file input:\n%s", a.screen())
	}
	a.press("ctrl+s")
	if s := a.screen(); !strings.Contains(s, "Give the file to keep") || len(read) != 0 {
		t.Fatalf("no file:\n%s", s)
	}
	a.tabs(3) // name, username, then the file
	a.press("~/nope", "ctrl+s")
	if s := a.screen(); a.form == nil || len(f.saves) != 0 || !strings.Contains(s, "no such file") {
		t.Fatalf("a missing file:\n%s", s)
	}
	a.press("ctrl+u", "~/.kube/config.yml", "ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saves %d:\n%s", len(f.saves), a.screen())
	}
	c := f.saves[0]
	if c.To != (vault.Key{Kind: vault.KindFile, Service: "config.yml"}) || string(c.Secret) != "content of ~/.kube/config.yml" || c.FileName == nil || *c.FileName != "config.yml" {
		t.Errorf("added %+v (file name %v)", c, c.FileName)
	}
	// Editing: the file kept unless one is given; it stays a file entry.
	a.press("kubeconfig")
	if a.selected() == nil || a.selected().Key != text {
		t.Fatalf("selected %+v", a.selected())
	}
	a.press("ctrl+k", "e")
	if s := a.screen(); !strings.Contains(s, "new file") || strings.Contains(s, "secure note") {
		t.Fatalf("the edit form:\n%s", s)
	}
	a.press("ctrl+s")
	if c := f.saves[len(f.saves)-1]; len(f.saves) != 2 || c.Secret != nil || c.FileName != nil {
		t.Errorf("kept: %+v", c)
	}
	a.press("ctrl+k", "e")
	a.form.focusInput(slices.IndexFunc(a.form.inputs, func(in *input) bool { return in.label == "new file" }))
	a.press("~/new.yml", "ctrl+s")
	if c := f.saves[len(f.saves)-1]; len(f.saves) != 3 || c.To != text || string(c.Secret) != "content of ~/new.yml" || c.FileName == nil || *c.FileName != "new.yml" {
		t.Errorf("a new file: %+v", c)
	}
}

// A binary file's earlier version isn't copied from its history either.
func TestFileVersionNotCopied(t *testing.T) {
	f, _, binary := fileFake()
	f.history = map[vault.Key][]string{binary: {"\x00old\xff"}}
	a := newApp(t, f, Options{})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	a.press("cert", "ctrl+k", "h")
	if a.ov == nil || a.ov.kind != panelHistory {
		t.Fatalf("no history:\n%s", a.screen())
	}
	a.press("enter")
	if s := a.screen(); len(a.copied) != 0 || !strings.Contains(s, "Version 2 of cert is a binary file") {
		t.Errorf("copied %q:\n%s", a.copied, s)
	}
}

// An AWS profile's entry shows its MFA device, which its form changes or
// takes out; another TOTP entry's form has no such input.
func TestAWSMFADevice(t *testing.T) {
	const was, now = "arn:aws:iam::123456789012:mfa/me", "arn:aws:iam::123456789012:mfa/new"
	f := newFake()
	awsKey := vault.AWSKey("work")
	f.entries = append([]vault.Entry{{Key: awsKey, Settings: vault.Settings{AWSMFADevice: was}}}, f.entries...)
	f.secrets[awsKey] = seed
	a := newApp(t, f, Options{})
	// The ARN wraps in the pane: its end is on a line of its own.
	if s := a.screen(); !strings.Contains(s, "MFA device  arn:aws:iam::") || !strings.Contains(s, "fa/me") {
		t.Fatalf("the details:\n%s", s)
	}
	setDevice := func(to string) {
		t.Helper()
		a.press("ctrl+k", "e")
		i := slices.IndexFunc(a.form.inputs, func(in *input) bool { return in.label == "MFA device" })
		if i < 0 || !a.form.inputs[i].visible() || a.form.inputs[i].value() != f.entries[0].Settings.AWSMFADevice {
			t.Fatalf("the form's MFA device input (%d):\n%s", i, a.screen())
		}
		a.form.focusInput(i)
		a.press("ctrl+u", to, "ctrl+s")
	}
	setDevice(now)
	if c := f.saves[len(f.saves)-1]; c.MFADevice == nil || *c.MFADevice != now {
		t.Fatalf("change = %+v", c)
	}
	if s := a.screen(); !strings.Contains(s, "fa/new") {
		t.Errorf("after the change:\n%s", s)
	}
	setDevice("")
	if c := f.saves[len(f.saves)-1]; c.MFADevice == nil || *c.MFADevice != "" {
		t.Fatalf("taken out: change = %+v", c)
	}
	if s := a.screen(); strings.Contains(s, "MFA device") {
		t.Errorf("a device taken out is still shown:\n%s", s)
	}
	// Saved as it is, the device isn't given.
	a.press("ctrl+k", "e", "ctrl+s")
	if c := f.saves[len(f.saves)-1]; c.MFADevice != nil {
		t.Errorf("unchanged: change = %+v", c)
	}
	// Renamed away from aws, the entry still shows the device it has, and
	// its form can take it out.
	setDevice(was)
	focus := func(label string) {
		t.Helper()
		i := slices.IndexFunc(a.form.inputs, func(in *input) bool { return in.label == label })
		if i < 0 || !a.form.inputs[i].visible() {
			t.Fatalf("no %s input:\n%s", label, a.screen())
		}
		a.form.focusInput(i)
	}
	a.press("ctrl+k", "e")
	focus("name")
	a.press("ctrl+u", "aws-old", "ctrl+s")
	// As sesh edit asks, the first save says sesh aws won't find it.
	if s := a.screen(); f.entries[0].Key.Service != "aws" || !strings.Contains(s, "This is an AWS profile's MFA entry: as totp/aws-old/work") {
		t.Fatalf("renamed away from aws with no word:\n%s", s)
	}
	a.press("ctrl+s")
	if s := a.screen(); f.entries[0].Key.Service != "aws-old" || !strings.Contains(s, "MFA device  arn:aws:iam::") {
		t.Fatalf("renamed: %+v\n%s", f.entries[0], s)
	}
	a.press("ctrl+k", "e")
	focus("MFA device")
	a.press("ctrl+u", "ctrl+s")
	if c := f.saves[len(f.saves)-1]; c.MFADevice == nil || *c.MFADevice != "" {
		t.Errorf("renamed, taken out: change = %+v", c)
	}
	// Another TOTP entry: none.
	a.press("down", "down", "ctrl+k", "e")
	if a.form == nil || a.form.title != "Edit "+entryName(&vault.Entry{Key: code}) {
		t.Fatalf("not the TOTP entry's form:\n%s", a.screen())
	}
	if s := a.screen(); strings.Contains(s, "MFA device") {
		t.Errorf("another TOTP entry's form has the input:\n%s", s)
	}
	a.press("esc")
	// Added: the input shows once the entry is an AWS profile's, a TOTP
	// entry named aws with the profile as its username.
	a.press("ctrl+g", "a", "→", "→", "→") // TOTP
	focus("name")
	a.press("aws")
	if i := slices.IndexFunc(a.form.inputs, func(in *input) bool { return in.label == "MFA device" }); a.form.inputs[i].visible() {
		t.Errorf("the input shows for aws with no username, which sesh aws never reads:\n%s", a.screen())
	}
	focus("username")
	a.press("home")
	focus("TOTP key, or otpauth:// link")
	a.press(seed)
	focus("MFA device")
	a.press(now, "ctrl+s")
	if c := f.saves[len(f.saves)-1]; c.Key != (vault.Key{}) || c.To != vault.AWSKey("home") || c.MFADevice == nil || *c.MFADevice != now {
		t.Errorf("added: change = %+v", c)
	}
}

// Ctrl-K on an AWS profile's entry signs in, then the app ends, leaving
// the shell to open; AWS refusing is said, and the app stays; Esc while
// it signs in leaves it, and nothing opens. Other entries aren't offered
// it.
func TestAWSSignIn(t *testing.T) {
	f := newFake()
	awsKey := vault.AWSKey("work")
	f.entries = append([]vault.Entry{{Key: awsKey}}, f.entries...)
	f.secrets[awsKey] = seed
	var refuse error
	var asked []vault.Key
	opened := 0
	// AWS refusing comes from the sign-in, once the vault's let go.
	a := newApp(t, f, Options{AWSSignIn: awsSignInFake(func(k vault.Key) error { asked = append(asked, k); return nil }, nil,
		func() (AWSShell, error) {
			if refuse != nil {
				return nil, refuse
			}
			return func(func()) error { opened++; return nil }, nil
		})})
	// Refused: said over the panel, which Enter closes.
	refuse = errors.New("AWS refused the next code too")
	a.press("ctrl+k", "a")
	if s := a.screen(); a.quit || !strings.Contains(s, "Not signed in: AWS refused the next code too") {
		t.Fatalf("refused:\n%s", s)
	}
	a.press("enter")
	if a.ov != nil || a.quit {
		t.Fatalf("after the refusal, Enter: panel %v, quit %v", a.ov, a.quit)
	}
	// Left with Esc while it signs in: the sign-in that ends after opens
	// nothing.
	refuse = nil
	e := f.entries[0]
	cmd := a.awsSignIn(&e)
	if s := a.screen(); !strings.Contains(s, "Signing in to AWS") || !strings.Contains(s, "leave it") {
		t.Errorf("while signing in:\n%s", s)
	}
	a.press("enter") // only Esc leaves it while it waits
	if a.ov == nil {
		t.Fatal("Enter left the sign-in")
	}
	a.press("esc")
	a.run(cmd)
	if a.quit || a.Then() != nil {
		t.Fatalf("left with Esc: quit %v", a.quit)
	}
	// Signed in: the app ends, and the shell is what's left to do.
	a.press("ctrl+k", "a")
	if !a.quit || a.Then() == nil {
		t.Fatalf("signed in: quit %v\n%s", a.quit, a.screen())
	}
	if err := a.Then()(func() {}); err != nil || opened != 1 || len(asked) != 3 || asked[2] != awsKey {
		t.Errorf("the shell: %v, opened %d; asked for %v", err, opened, asked)
	}
	// Another entry has no such action.
	b := newApp(t, newFake(), Options{AWSSignIn: awsSignInFake(nil, nil, nil)})
	b.press("down", "ctrl+k")
	if s := b.screen(); strings.Contains(s, "sign in to AWS") {
		t.Errorf("a TOTP entry not an AWS profile's has it:\n%s", s)
	}
}

// The sign-in talks to AWS with the vault let go: a lock meanwhile doesn't
// wait for it, and opens nothing once it's done; the vault locked under
// the sign-in locks the app.
func TestAWSSignInLetsTheVaultGo(t *testing.T) {
	f := newFake()
	awsKey := vault.AWSKey("work")
	f.entries = append([]vault.Entry{{Key: awsKey}}, f.entries...)
	f.secrets[awsKey] = seed
	started, release := make(chan struct{}), make(chan struct{})
	a := newApp(t, f, Options{AWSSignIn: awsSignInFake(nil, nil, func() (AWSShell, error) {
		close(started)
		<-release
		return func(func()) error { return nil }, nil
	})})
	e := f.entries[0]
	cmd := a.awsSignIn(&e)
	got := make(chan tea.Msg, 1)
	go func() { got <- cmd() }()
	<-started
	g := a.v
	closed := make(chan struct{})
	go func() { g.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the vault waited for AWS")
	}
	a.lock("locked")
	close(release)
	_, next := a.Update(<-got)
	a.run(next)
	if a.quit || a.Then() != nil {
		t.Errorf("signed in after a lock: quit %v", a.quit)
	}

	// Signed in, then a lock before the app has ended: no shell.
	c := newApp(t, f, Options{AWSSignIn: awsSignInFake(nil, nil, func() (AWSShell, error) { return func(func()) error { return nil }, nil })})
	cmd = c.awsSignIn(&e)
	c.Update(cmd()) // its tea.Quit not yet run
	c.lock("locked")
	if c.Then() != nil {
		t.Error("a lock after signing in left the shell to open")
	}

	// The vault locked as the sign-in reads it: the app locks.
	b := newApp(t, f, Options{AWSSignIn: awsSignInFake(nil, Locked("sesh's agent locked the vault."), nil)})
	b.press("ctrl+k", "a")
	if s := b.screen(); b.v != nil || !strings.Contains(s, "sesh's agent locked the vault.") {
		t.Errorf("locked under the sign-in:\n%s", s)
	}

	// How the profile signs in is found with the vault let go too (it may
	// ask the AWS CLI): closing it doesn't wait.
	firstStarted, firstRelease := make(chan struct{}), make(chan struct{})
	d := newApp(t, f, Options{AWSSignIn: awsSignInFake(func(vault.Key) error {
		close(firstStarted)
		<-firstRelease
		return nil
	}, nil, func() (AWSShell, error) { return func(func()) error { return nil }, nil })})
	cmd = d.awsSignIn(&e)
	go func() { got <- cmd() }()
	<-firstStarted
	g, closed = d.v, make(chan struct{})
	go func() { g.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the vault waited for the profile's kind")
	}
	close(firstRelease)
	<-got
}

// awsSignInFake is an AWSSignIn whose steps are first (with the vault let
// go), then the vault step's err, then signIn.
func awsSignInFake(first func(k vault.Key) error, vaultErr error, signIn AWSSignInStep) func(k vault.Key) (AWSVaultStep, error) {
	return func(k vault.Key) (AWSVaultStep, error) {
		if first != nil {
			if err := first(k); err != nil {
				return nil, err
			}
		}
		return func(Vault) (AWSSignInStep, error) {
			if vaultErr != nil {
				return nil, vaultErr
			}
			return signIn, nil
		}, nil
	}
}

// fakeAWSSetup is sesh aws setup as the app's tests have it: profiles of
// kind, AWS's devices, and what was asked.
type fakeAWSSetup struct {
	checkErr, devicesErr error
	existing             *vault.Entry
	check                func() // run as Check asks AWS
	kind                 string
	keys                 []string // the keys ReadKey or FromEntry gave
	inHistory            []bool   // what each KeyOnly was told
	devices              []string
	codes                int  // codes made
	noHistory            bool // a key replaced isn't kept
}

func (s *fakeAWSSetup) Profiles() []string { return []string{"work", "home"} }
func (s *fakeAWSSetup) Check(profile string) (AWSProfile, error) {
	if s.check != nil {
		s.check()
	}
	if s.checkErr != nil {
		return AWSProfile{}, s.checkErr
	}
	p := AWSProfile{Profile: profile, Kind: s.kind, Done: "✅ set up " + profile}
	if s.kind == "" {
		p.Identity, p.Account = "arn:aws:iam::123456789012:user/alice", "123456789012"
	}
	return p, nil
}
func (s *fakeAWSSetup) Existing(Vault, string) (*vault.Entry, bool, error) {
	return s.existing, !s.noHistory, nil
}
func (s *fakeAWSSetup) ReadKey(typed []byte) ([]byte, error) {
	if string(typed) != seed {
		return nil, errors.New("that TOTP key can't be used")
	}
	s.keys = append(s.keys, string(typed))
	return bytes.Clone(typed), nil
}
func (s *fakeAWSSetup) FromEntry(_ Vault, src, _ vault.Key) ([]byte, error) {
	s.keys = append(s.keys, "from "+src.String())
	return []byte(seed), nil
}
func (s *fakeAWSSetup) Codes([]byte) (string, string, error) {
	s.codes++
	return fmt.Sprintf("11111%d", s.codes), fmt.Sprintf("22222%d", s.codes), nil
}
func (s *fakeAWSSetup) Devices(string) ([]string, error) { return s.devices, s.devicesErr }
func (s *fakeAWSSetup) CheckDevice(arn, _ string) error {
	if !strings.HasPrefix(arn, "arn:aws:iam::123456789012:mfa/") {
		return errors.New("that isn't an authenticator app's ARN")
	}
	return nil
}
func (s *fakeAWSSetup) KeyOnly(k vault.Key, inHistory bool, why error) string {
	s.inHistory = append(s.inHistory, inHistory)
	return why.Error() + "; the MFA key is saved, as " + k.String()
}

// focusOn moves the form's focus to the input labelled label.
func (a *app) focusOn(label string) {
	a.t.Helper()
	i := slices.IndexFunc(a.form.inputs, func(in *input) bool { return in.name() == label })
	if i < 0 || !a.form.inputs[i].visible() {
		a.t.Fatalf("no %s input:\n%s", label, a.screen())
	}
	a.form.focusInput(i)
}

// AWS setup in the app, a profile with access keys: the profile checked,
// the key pasted and saved before AWS is told, the codes (new ones on n),
// then the device chosen from AWS's, and the setup done.
func TestAWSSetup(t *testing.T) {
	f := newFake()
	s := &fakeAWSSetup{devices: []string{"arn:aws:iam::123456789012:mfa/phone", "arn:aws:iam::123456789012:mfa/sesh"}}
	a := newApp(t, f, Options{AWSSetup: s})
	work := vault.AWSKey("work")
	a.press("ctrl+g", "m")
	if a.form == nil || a.form.title != "Set up AWS MFA" || !slices.Equal(a.form.inputs[0].offers, []string{"work", "home"}) {
		t.Fatalf("the profile's form:\n%s", a.screen())
	}
	// A profile AWS can't say who signs in as stays in the form.
	s.checkErr = errors.New("AWS couldn't say who profile work signs in as")
	a.press("work", "enter")
	if a.form == nil || !strings.Contains(a.screen(), "AWS couldn't say who profile work signs in as") {
		t.Fatalf("refused:\n%s", a.screen())
	}
	s.checkErr = nil
	a.press("enter")
	if a.form == nil || a.form.title != "MFA key for profile work" || !strings.Contains(a.screen(), "Assign MFA device") {
		t.Fatalf("the key's form:\n%s", a.screen())
	}
	// A key that can't be used is said; one that can is saved first.
	a.focusOn("MFA key, or otpauth:// link")
	a.press("not-a-key", "ctrl+s")
	if !strings.Contains(a.screen(), "Not saved: that TOTP key can't be used") || len(f.saves) != 0 {
		t.Fatalf("a bad key:\n%s", a.screen())
	}
	a.press("ctrl+u", seed)
	a.focusOn("folder")
	a.press("work/aws", "ctrl+s")
	if len(f.saves) != 1 {
		t.Fatalf("saves %d:\n%s", len(f.saves), a.screen())
	}
	if c := f.saves[0]; c.Key != (vault.Key{}) || c.To != work || string(c.Secret) != seed || c.Folder == nil || *c.Folder != "work/aws" || c.MFADevice != nil {
		t.Errorf("the key saved: %+v", c)
	}
	if sc := a.screen(); !strings.Contains(sc, "MFA code 1:  111111") || !strings.Contains(sc, "MFA code 2:  222221") {
		t.Fatalf("the codes:\n%s", sc)
	}
	a.press("n")
	if sc := a.screen(); !strings.Contains(sc, "MFA code 1:  111112") {
		t.Fatalf("new codes:\n%s", sc)
	}
	a.press("enter")
	if sc := a.screen(); !strings.Contains(sc, "mfa/phone") || !strings.Contains(sc, "mfa/sesh") {
		t.Fatalf("the devices:\n%s", sc)
	}
	a.press("2")
	if c := f.saves[len(f.saves)-1]; c.Key != work || c.MFADevice == nil || *c.MFADevice != "arn:aws:iam::123456789012:mfa/sesh" || c.Secret != nil {
		t.Errorf("the device saved: %+v", c)
	}
	if sc := a.screen(); !strings.Contains(sc, "✅ set up work") || a.awsSet != nil {
		t.Errorf("done:\n%s", sc)
	}
}

// No device listed: looking again, or typing its ARN, checked; Esc over
// the codes says the key's kept; a lock wipes the key held.
func TestAWSSetupDevicesAndLeaving(t *testing.T) {
	f := newFake()
	s := &fakeAWSSetup{}
	a := newApp(t, f, Options{AWSSetup: s})
	start := func(profile string) {
		t.Helper()
		a.press("ctrl+g", "m", profile, "enter")
		a.focusOn("MFA key, or otpauth:// link")
		a.press(seed, "ctrl+s")
		if a.awsSet == nil || string(a.awsSet.key) != seed {
			t.Fatalf("not at the codes:\n%s", a.screen())
		}
	}
	start("work")
	a.press("enter")
	if sc := a.screen(); !strings.Contains(sc, "AWS lists no authenticator app") {
		t.Fatalf("no devices:\n%s", sc)
	}
	s.devices = []string{"arn:aws:iam::123456789012:mfa/sesh"}
	a.press("r")
	if sc := a.screen(); !strings.Contains(sc, "mfa/sesh") {
		t.Fatalf("looked again:\n%s", sc)
	}
	a.press("m", "arn:aws:iam::999999999999:mfa/x", "enter")
	if sc := a.screen(); a.form == nil || !strings.Contains(sc, "isn't an authenticator app's ARN") {
		t.Fatalf("a bad ARN:\n%s", sc)
	}
	a.press("ctrl+u", "arn:aws:iam::123456789012:mfa/typed", "enter")
	if c := f.saves[len(f.saves)-1]; c.MFADevice == nil || *c.MFADevice != "arn:aws:iam::123456789012:mfa/typed" {
		t.Errorf("the ARN typed: %+v", c)
	}
	// Leaving over the codes: the key is saved, and said so.
	a.press("enter") // the done notice
	start("home")
	key := a.awsSet.key
	a.press("esc")
	if sc := a.screen(); a.awsSet != nil || !strings.Contains(sc, "Left before AWS had the device") || string(key) != strings.Repeat("\x00", len(seed)) {
		t.Errorf("left over the codes, key %q:\n%s", key, sc)
	}
	// A lock over the codes wipes the key.
	a.press("enter")
	start("other")
	key = a.awsSet.key
	a.lock("locked")
	if a.awsSet != nil || string(key) != strings.Repeat("\x00", len(seed)) {
		t.Errorf("locked over the codes: key %q", key)
	}
}

// An entry sesh has already is replaced after a yes, its device taken out
// for the new key; a profile signing in with aws login, its key from a
// TOTP entry, needs no codes nor device.
func TestAWSSetupReplaceAndFromEntry(t *testing.T) {
	f := newFake()
	work := vault.AWSKey("work")
	s := &fakeAWSSetup{kind: "aws login", existing: &vault.Entry{Key: work, Folder: "aws"}}
	a := newApp(t, f, Options{AWSSetup: s})
	a.press("ctrl+g", "m", "work", "enter")
	if sc := a.screen(); !strings.Contains(sc, "sesh already has an MFA key for profile work") {
		t.Fatalf("not asked:\n%s", sc)
	}
	a.press("wait", "y")
	a.focusOn("the key")
	a.press("→") // a TOTP entry
	a.focusOn("TOTP entry")
	a.press("totp/github/alice", "ctrl+s")
	if len(s.keys) != 1 || s.keys[0] != "from totp/github/alice" {
		t.Fatalf("the key read: %q\n%s", s.keys, a.screen())
	}
	if c := f.saves[0]; c.Key != work || c.To != work || c.MFADevice == nil || *c.MFADevice != "" || c.Folder != nil {
		t.Errorf("replaced: %+v", c)
	}
	if sc := a.screen(); s.codes != 0 || !strings.Contains(sc, "✅ set up work") {
		t.Errorf("from an entry, for aws login: codes %d\n%s", s.codes, sc)
	}
}

// Another command changing the vault mid-setup leaves each step working;
// a lock once the key's saved says what's kept; AWS is asked with the
// vault let go; with history.keep 0, replacing a key says it's lost.
func TestAWSSetupAcrossChangesAndLocks(t *testing.T) {
	f := newFake()
	s := &fakeAWSSetup{devices: []string{"arn:aws:iam::123456789012:mfa/sesh"}}
	a := newApp(t, f, Options{AWSSetup: s})
	changed := func(what string) {
		t.Helper()
		f.changed = true
		a.tick(time.Second)
		if a.awsSet == nil {
			t.Fatalf("%s: the vault changing ended the setup:\n%s", what, a.screen())
		}
	}
	a.press("ctrl+g", "m", "work", "enter")
	changed("the key's form")
	a.focusOn("MFA key, or otpauth:// link")
	a.press(seed, "ctrl+s")
	if sc := a.screen(); len(f.saves) != 1 || !strings.Contains(sc, "MFA code 1:") {
		t.Fatalf("saving after a change:\n%s", sc)
	}
	changed("the codes")
	if sc := a.screen(); !strings.Contains(sc, "MFA code 1:") {
		t.Fatalf("the codes closed on a change:\n%s", sc)
	}
	a.press("enter")
	changed("the devices")
	if sc := a.screen(); !strings.Contains(sc, "mfa/sesh") {
		t.Fatalf("the devices closed on a change:\n%s", sc)
	}
	a.press("m")
	changed("the ARN's form")
	a.press("arn:aws:iam::123456789012:mfa/typed", "enter")
	if sc := a.screen(); !strings.Contains(sc, "✅ set up work") {
		t.Fatalf("the device saved after a change:\n%s", sc)
	}
	// Esc while the device saves: how it went is still said.
	a.press("enter")
	a.press("ctrl+g", "m", "esc-test", "enter")
	a.focusOn("MFA key, or otpauth:// link")
	a.press(seed, "ctrl+s", "enter")
	st := a.awsSet
	cmd := a.awsSaveDevice(st, "arn:aws:iam::123456789012:mfa/sesh")
	a.press("esc")
	a.run(cmd)
	if sc := a.screen(); !strings.Contains(sc, "✅ set up esc-test") {
		t.Fatalf("Esc while the device saved:\n%s", sc)
	}
	a.press("enter")
	// A lock between the key's save and its reply says it's kept.
	e := newApp(t, f, Options{AWSSetup: s})
	e.press("ctrl+g", "m", "mid-save", "enter")
	e.focusOn("MFA key, or otpauth:// link")
	e.press(seed)
	_, next := e.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	_, save := e.Update(next()) // the key read; its save runs, its reply held
	saved := save()
	e.lock("sesh locked: idle")
	e.Update(saved)
	if !strings.Contains(e.lockedWhy, "the MFA key is saved, as totp/aws/mid-save") {
		t.Errorf("locked mid-save: %q", e.lockedWhy)
	}

	// A lock over the codes says the key's saved.
	a.press("enter")
	a.press("ctrl+g", "m", "home", "enter")
	a.focusOn("MFA key, or otpauth:// link")
	a.press(seed, "ctrl+s")
	a.lock("sesh locked: idle")
	if !strings.Contains(a.lockedWhy, "the MFA key is saved, as totp/aws/home") || s.inHistory[len(s.inHistory)-1] {
		t.Errorf("locked once the key's saved: %q, in history %v", a.lockedWhy, s.inHistory)
	}

	// AWS is asked with the vault let go: closing it doesn't wait.
	b := newApp(t, f, Options{AWSSetup: s})
	started, release := make(chan struct{}), make(chan struct{})
	s.check = func() { close(started); <-release }
	b.press("ctrl+g", "m", "work")
	cmd = b.form.submit()
	got := make(chan tea.Msg, 1)
	go func() { got <- cmd() }()
	<-started
	g, closed := b.v, make(chan struct{})
	go func() { g.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the vault waited for AWS")
	}
	close(release)
	<-got
	s.check = nil

	// history.keep 0: replacing a key says the one there is lost; the key
	// saved, a lock says it isn't in the history.
	s.existing, s.noHistory = &vault.Entry{Key: vault.AWSKey("work")}, true
	c := newApp(t, f, Options{AWSSetup: s})
	c.press("ctrl+g", "m", "work", "enter")
	if sc := c.screen(); !strings.Contains(sc, "history.keep is 0") || c.ov == nil || !c.ov.danger {
		t.Fatalf("history.keep 0:\n%s", sc)
	}
	s.noHistory = false
	d := newApp(t, f, Options{AWSSetup: s})
	d.press("ctrl+g", "m", "work", "enter", "wait", "y")
	d.focusOn("MFA key, or otpauth:// link")
	d.press(seed, "ctrl+s")
	d.lock("sesh locked: idle")
	if !s.inHistory[len(s.inHistory)-1] {
		t.Errorf("a replaced key kept in the history: told %v", s.inHistory)
	}
}

// Ctrl-G's sign in to AWS… asks the profile (the AWS CLI's offered, the
// form starting with AWS_PROFILE's), and signs in with it; the default
// profile's entry is totp/aws/default.
func TestAWSSignInFromTheMenu(t *testing.T) {
	var asked []vault.Key
	a := newApp(t, newFake(), Options{AWSSetup: &fakeAWSSetup{}, AWSSignIn: awsSignInFake(func(k vault.Key) error { asked = append(asked, k); return nil }, nil,
		func() (AWSShell, error) { return func(func()) error { return nil }, nil })})
	a.press("ctrl+g", "w")
	if a.form == nil || a.form.title != "Sign in to AWS" || !slices.Equal(a.form.inputs[0].offers, []string{"work", "home"}) {
		t.Fatalf("the form:\n%s", a.screen())
	}
	a.press("work/x", "enter")
	if a.form == nil || !strings.Contains(a.form.err, `contains "/"`) || len(asked) != 0 {
		t.Fatalf("a bad name: %q, asked %v", a.form.err, asked)
	}
	a.press("ctrl+u", "personal", "enter")
	if !a.quit || a.Then() == nil || len(asked) != 1 || asked[0] != vault.AWSKey("personal") {
		t.Fatalf("signed in: quit %v, asked %v\n%s", a.quit, asked, a.screen())
	}
	b := newApp(t, newFake(), Options{AWSSignIn: a.opts.AWSSignIn})
	b.press("ctrl+g", "w", "enter")
	c := newApp(t, newFake(), Options{AWSSignIn: a.opts.AWSSignIn, AWSProfile: func() string { return "from-env" }})
	c.press("ctrl+g", "w")
	if c.form == nil || c.form.inputs[0].value() != "from-env" {
		t.Errorf("the form doesn't start with AWS_PROFILE's profile:\n%s", c.screen())
	}
	// Filled in for you, the profile hides none of the others.
	d := newApp(t, newFake(), Options{AWSSetup: &fakeAWSSetup{}, AWSSignIn: a.opts.AWSSignIn, AWSProfile: func() string { return "work" }})
	d.press("ctrl+g", "w")
	if got := d.form.inputs[0].matches(); !slices.Equal(got, []string{"home"}) {
		t.Errorf("offered %q with work filled in, want home", got)
	}
	d.press("backspace")
	if got := d.form.inputs[0].matches(); !slices.Equal(got, []string{"work"}) {
		t.Errorf("offered %q once typed over, want what matches", got)
	}
	if len(asked) != 2 || asked[1] != vault.AWSKey("") {
		t.Errorf("the default profile: asked %v", asked)
	}
}
