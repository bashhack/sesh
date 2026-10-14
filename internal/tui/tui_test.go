package tui

import (
	"errors"
	"fmt"
	"image/color"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// fakeVault holds entries and secrets, finds entries whose name holds the
// query, and records what was read.
type fakeVault struct {
	err      error // returned by every read when set
	checkErr error // returned by Check when set
	secrets  map[vault.Key]string
	notes    map[vault.Key]string
	fields   map[vault.Key][]vault.Field // secret fields, with values
	history  map[vault.Key][]string      // earlier secrets, the newest first
	trash    []Trashed
	trashed  map[int64]vault.Entry
	entries  []vault.Entry
	reads    []string // "secret <key> <reading>" or "code <key>"
	kept     int      // keep-alives
	closed   bool
	changed  bool
	searched int
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
	for _, w := range []string{"3 entries", "● github", "alice", "◆ gitlab", "◷ github", want[:3] + " " + want[3:], "PASSWORD", "▸ work", "↵ copy  ·  tab reveal"} {
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
	if !slices.Equal(a.copied, []string{"gh-pass"}) || !strings.Contains(a.screen(), "✓ Copied github (alice)'s password · clears in 30s") {
		t.Errorf("copied %q:\n%s", a.copied, a.screen())
	}
	a.press("down", "enter")
	want, err := totp.CodeAt([]byte(seed), totp.Params{}, a.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.copied) != 2 || a.copied[1] != want || !strings.Contains(a.screen(), "Copied github (alice)'s code") {
		t.Errorf("copied %q, want the code %s:\n%s", a.copied, want, a.screen())
	}
	if !slices.Contains(f.reads, "secret password/github/alice in sesh ui, to copy it") || !slices.Contains(f.reads, "secret totp/github/alice in sesh ui, to copy its code") {
		t.Errorf("reads = %q", f.reads)
	}
	// The message goes after a few seconds.
	a.tick(6 * time.Second)
	if s := a.screen(); strings.Contains(s, "Copied") || !strings.Contains(s, "↵ copy") {
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
	if a.v != nil || !f.closed || !strings.Contains(s, "sesh is locked") || !strings.Contains(s, "Locked after 1m0s without use.") || strings.Contains(s, "github") {
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
	if s := a.screen(); !strings.Contains(s, "Locked 1h0m0s after unlocking.") {
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
	if s := a.screen(); !strings.Contains(s, "clear the search, or quit") || strings.Contains(s, "◆ gitlab") {
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
	for _, w := range []string{"recovery codes", "in the safe", "email     a@example.com", "pin       ••••••••", "password  ••••••••", "tab reveal"} {
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
	if s := a.screen(); !strings.Contains(s, "password  gh-pass") || !strings.Contains(s, "pin       4321") || !strings.Contains(s, "tab hide (30s)") {
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
	if !strings.Contains(s, "ssid home␛[2Jpassword hunter2") || !strings.Contains(s, "shift ↑↓ scroll") || strings.Contains(s, "line 39") {
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
	if len(a.copied) != 1 || a.copied[0] != "alice" || !strings.Contains(a.screen(), "Copied github (alice)'s username") {
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
	for _, w := range []string{"github (alice)", "copy a value…", "copy the username", "open the URL", "earlier secrets…", "delete (to the trash)", "the trash…", "lock now"} {
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
	if s := a.screen(); !strings.Contains(s, "Make version 3 password/github/alice's secret again?") {
		t.Fatalf("confirm:\n%s", s)
	}
	a.press("n")
	if f.secrets[github] != "gh-pass" || a.ov == nil || a.ov.kind != panelHistory {
		t.Fatalf("no restored it, or closed the history (secret %q)", f.secrets[github])
	}
	a.press("r", "wait", "y")
	if f.secrets[github] != "old-2" || !strings.Contains(a.screen(), "Restored an earlier secret of password/github/alice") {
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
	if s := a.screen(); len(f.entries) != 2 || !strings.Contains(s, "2 entries") || !strings.Contains(s, "Moved password/github/alice to the trash") {
		t.Fatalf("after delete:\n%s", s)
	}
	a.press("ctrl+k", "t")
	if s := a.screen(); !strings.Contains(s, "password/github/alice") || !strings.Contains(s, "deleted") {
		t.Fatalf("trash:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); len(f.entries) != 3 || !strings.Contains(s, "3 entries") {
		t.Fatalf("put back:\n%s", s)
	}
	// The selection moved on to the TOTP entry when github left the list.
	a.press("ctrl+k", "d", "wait", "y", "ctrl+k", "t", "x")
	if s := a.screen(); !strings.Contains(s, "Delete totp/github/alice for good?") {
		t.Fatalf("confirm for good:\n%s", s)
	}
	a.press("wait", "y")
	if len(f.trash) != 0 || !strings.Contains(a.screen(), "Deleted totp/github/alice for good") {
		t.Errorf("for good: trash %v", f.trash)
	}
}

// Lock now locks the app, and the agent.
func TestActionLockNow(t *testing.T) {
	f := newFake()
	agentLocked := false
	a := newApp(t, f, Options{LockAgent: func() error { agentLocked = true; return nil }})
	a.press("ctrl+k")
	if !strings.Contains(a.screen(), "lock now, and sesh's agent") {
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
	if !strings.Contains(s, "old-30") || !strings.Contains(s, "trash id 31") || !strings.Contains(s, "put back") || strings.Count(s, "\n") != a.height-1 {
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
	if s := a.screen(); a.ov == nil || !strings.Contains(s, "another entry has that name") || !strings.Contains(s, "password/github/alice") {
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
