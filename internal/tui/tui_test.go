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
	a.Model = New(opts)
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
	cmd := a.copySelected()
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
	m := New(Options{Vault: slow, Now: time.Now, IdleTimeout: time.Minute})
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
	if !strings.Contains(s, "ssid home␛[2Jpassword hunter2") || !strings.Contains(s, "⇧↑↓ scroll") || strings.Contains(s, "line 39") {
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
