package tui

import (
	"bytes"
	"errors"
	"fmt"
	"image/color"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	unreadable []vault.Key // entries whose secret doesn't decrypt, for Health
	secrets    map[vault.Key]string
	notes      map[vault.Key]string
	fields     map[vault.Key][]vault.Field // secret fields, with values
	history    map[vault.Key][]string      // earlier secrets, the newest first
	trash      []Trashed
	trashed    map[int64]vault.Entry
	saves      []Change // what Save was given
	entries    []vault.Entry
	reads      []string // "secret <key> <reading>" or "code <key>"
	kept       int      // keep-alives
	closed     bool
	changed    bool
	searched   int
	changes    int // folder and tag changes made
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

func (f *fakeVault) History(k vault.Key) ([]time.Time, error) {
	out := make([]time.Time, len(f.history[k]))
	for i := range out {
		out[i] = time.Unix(1_700_000_000-int64(i)*86400, 0)
	}
	return out, nil
}

func (f *fakeVault) ReadVersion(k vault.Key, n int) ([]byte, error) {
	f.reads = append(f.reads, fmt.Sprintf("version %s %d", k, n))
	return []byte(f.history[k][n-2]), nil
}

func (f *fakeVault) RestoreVersion(k vault.Key, n int) error {
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

func (f *fakeVault) RestoreFromTrash(id int64) (vault.Key, error) {
	e := f.trashed[id]
	f.entries = append(f.entries, e)
	f.trash = slices.DeleteFunc(f.trash, func(t Trashed) bool { return t.ID == id })
	return e.Key, nil
}

func (f *fakeVault) RemoveFromTrash(id int64) error {
	f.trash = slices.DeleteFunc(f.trash, func(t Trashed) bool { return t.ID == id })
	return nil
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
	for _, w := range []string{"github (alice)", "copy a value…", "copy the username", "open the URL", "earlier secrets…", "move to the trash", "the trash…", "lock sesh"} {
		if !strings.Contains(s, w) {
			t.Errorf("menu missing %q:\n%s", w, s)
		}
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
	a.press("ctrl+k", "t")
	if s := a.screen(); !strings.Contains(s, "github (alice)  password · deleted") {
		t.Fatalf("trash:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); len(f.entries) != 3 || !strings.Contains(s, "3 entries") {
		t.Fatalf("put back:\n%s", s)
	}
	// The selection moved on to the TOTP entry when github left the list.
	a.press("ctrl+k", "d", "wait", "y", "ctrl+k", "t", "x")
	if s := a.screen(); !strings.Contains(s, "Delete TOTP github (alice) for good?") {
		t.Fatalf("confirm for good:\n%s", s)
	}
	a.press("wait", "y")
	if len(f.trash) != 0 || !strings.Contains(a.screen(), "Deleted TOTP github (alice) for good") {
		t.Errorf("for good: trash %v", f.trash)
	}
}

// Lock now locks the app, and the agent.
func TestActionLockNow(t *testing.T) {
	f := newFake()
	agentLocked := false
	a := newApp(t, f, Options{LockAgent: func() error { agentLocked = true; return nil }})
	a.press("ctrl+k")
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
	a.press("ctrl+k", "r", "e", "a", "d", "y")
	if len(f.entries) != 3 {
		t.Fatal("typing a word after Ctrl-K deleted an entry")
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
	a.press("ctrl+k", "t")
	for range 30 {
		a.press("down")
	}
	s := a.screen()
	if !strings.Contains(s, "old-30") || !strings.Contains(s, "deleted") || !strings.Contains(s, "put back") || strings.Count(s, "\n") != a.height-1 {
		t.Errorf("a long trash:\n%s", s)
	}
	a.press("esc", "esc", "ctrl+k", "l")
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
	a.press("ctrl+k", "t")
	a.Update(tea.PasteMsg{Content: "zzz"})
	if a.input.Value() != "" {
		t.Errorf("a paste reached the search behind the panel: %q", a.input.Value())
	}
	first := a.restoreFromTrash(7)
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
	a.tabs(2)
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
	a := newApp(t, f, Options{ClearAfter: 30 * time.Second, Generate: func() ([]byte, error) { return []byte("generated-pw"), nil }})
	a.press("ctrl+k", "e")
	a.tabs(2)
	a.press("→", "→", "ctrl+s")
	if len(f.saves) != 1 || string(f.saves[0].Secret) != "generated-pw" || len(a.copied) != 1 || a.copied[0] != "generated-pw" {
		t.Fatalf("saves %+v, copied %q", f.saves, a.copied)
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
	a.press("esc", "ctrl+k", "a")
	a.press("tab", "taken")
	a.tabs(2)
	a.press("→") // type → generate
	a.press("ctrl+s")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "Another entry has that name") {
		t.Errorf("a name taken:\n%s", s)
	}
}

// Adding: a secure note's text is its secret; a TOTP entry needs its key;
// Esc on a form with something typed asks once before discarding it.
func TestAddForm(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "a")
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
	a.press("ctrl+k", "a", "→", "→", "→") // TOTP
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
	a.tabs(7) // username, secret, current, URL, folder, tags → notes
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
	a.tabs(2)
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
	a.press("ctrl+k", "a", "→", "→", "→", "tab", "x", "tab", "me", "tab", "JBSWY3DP")
	if s := a.screen(); !strings.Contains(s, " account ") || strings.Contains(s, " username ") || strings.Contains(s, "easy to guess") {
		t.Errorf("a TOTP entry's form:\n%s", s)
	}
	a.press("esc", "esc", "ctrl+k", "a")
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
	a.press("ctrl+k", "a", "tab", "x")
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
	a.press("ctrl+k", "a")
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
	a.tabs(8) // username, secret, current, URL, folder, tags, notes → the fields
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

// fieldsApp is the app with github's form open on its fields: email (plain)
// and pin (secret, not read).
func fieldsApp(t *testing.T) (*app, *fakeVault) {
	t.Helper()
	f := newFake()
	f.entries[0].Fields = []vault.Field{{Name: "email", Value: []byte("a@b")}, {Name: "pin", Secret: true}}
	f.fields = map[vault.Key][]vault.Field{github: {{Name: "pin", Secret: true, Value: []byte("4711")}}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(8) // username, secret, current, URL, folder, tags, notes → the fields
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
	a.press("ctrl+k", "a", "→", "→", "tab", "a note", "ctrl+s")
	if s := a.screen(); len(f.saves) != 1 || !strings.Contains(s, "Write the note") {
		t.Errorf("an empty secure note: %d saves\n%s", len(f.saves), s)
	}
}

// Time spent in the editor doesn't lock the app as idle when it returns.
func TestFormEditorTimeIsUse(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{IdleTimeout: 10 * time.Minute, EditNotes: func(b []byte) ([]byte, error) { return b, nil }})
	a.press("ctrl+k", "e")
	a.tabs(7) // → notes
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
	a.tabs(8)
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

// Keeping the secret shows it as dots, unread until Ctrl-R; nothing typed there changes it.
func TestFormShowsTheCurrentSecret(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "e")
	a.tabs(3) // username, the secret's choice → the current password
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
	a.press("git", "ctrl+k", "r")
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
	a.press("ctrl+k", "r")
	f.entries = slices.DeleteFunc(f.entries, func(e vault.Entry) bool { return e.Key == github })
	a.press("enter")
	if s := a.screen(); a.form != nil || !strings.Contains(s, "github (alice) isn't in the vault any more") {
		t.Errorf("choosing an entry that's gone:\n%s", s)
	}
	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+k", "r", "down", "enter") // gitlab, the first reused row
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
	a.press("ctrl+k", "r")
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
	a.press("ctrl+k", "r", "down", "enter")
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
	a.press("ctrl+k", "r")
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
	a.press("ctrl+k", "r")
	held = enterHeld(a)
	a.press("ctrl+k", "a", "my new entry")
	a.editing = github // as if nothing the user did had dropped it
	a.run(held)
	if a.form == nil || a.form.title != "Add an entry" {
		t.Errorf("a form opened meanwhile was replaced: %v", a.form)
	}

	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+k", "r")
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
	a.press("ctrl+k", "r", "down")
	if s := a.screen(); !strings.Contains(s, "malformed") || strings.Contains(s, "Nothing is weak") {
		t.Errorf("an error, then a key:\n%s", s)
	}

	f = healthFake()
	f.unreadable = []vault.Key{gitlab}
	a = newApp(t, f, Options{})
	a.press("ctrl+k", "r")
	for range 3 {
		a.press("down")
	}
	a.press("enter")
	if s := a.screen(); a.ov == nil || !strings.Contains(s, "doesn't decrypt: sesh doctor says more") || !strings.Contains(s, "in 3 passwords and API keys") {
		t.Errorf("Enter on an unreadable row:\n%s", s)
	}

	a = newApp(t, healthFake(), Options{})
	a.press("ctrl+k")
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
	a.press("ctrl+k", "r") // the top of it, where the groups and the lines between them are
	if lines := strings.Count(a.View().Content, "\n") + 1; lines > a.height {
		t.Errorf("the report drew %d lines in %d:\n%s", lines, a.height, a.screen())
	}
}
