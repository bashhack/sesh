package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
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
	entries  []vault.Entry
	reads    []string // "secret <key> <reading>" or "code <key>"
	kept     int      // keep-alives
	closed   bool
	changed  bool
	searched int
}

func (f *fakeVault) Search(q string) ([]vault.Entry, error) {
	f.searched++
	var out []vault.Entry
	for _, e := range f.entries {
		if strings.Contains(e.Key.String(), q) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeVault) Secret(k vault.Key, reading string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reads = append(f.reads, "secret "+k.String()+" "+reading)
	return []byte(f.secrets[k]), nil
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

// It opens on every entry, with the TOTP entry's code and countdown, read
// without an audit; typing narrows the list.
func TestSearchAndCodes(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	want, err := totp.CodeAt([]byte(seed), totp.Params{}, a.now)
	if err != nil {
		t.Fatal(err)
	}
	s := a.screen()
	for _, w := range []string{"3 entries", "password  github (alice)", "work", "api key", want[:3] + " " + want[3:] + "   5s"} {
		if !strings.Contains(s, w) {
			t.Errorf("screen missing %q:\n%s", w, s)
		}
	}
	if !slices.Equal(f.reads, []string{"code totp/github/alice"}) {
		t.Errorf("reads = %q", f.reads)
	}
	// The code changes with the clock; the key isn't read again.
	a.tick(10 * time.Second)
	if s := a.screen(); !strings.Contains(s, "25s") || len(f.reads) != 1 {
		t.Errorf("after 10s, reads %q:\n%s", f.reads, s)
	}
	a.press("gitl")
	if s := a.screen(); !strings.Contains(s, "› gitl") || !strings.Contains(s, "1 entry") || strings.Contains(s, "github") {
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
	if !slices.Equal(a.copied, []string{"gh-pass"}) || !strings.Contains(a.screen(), "Copied password/github/alice; the clipboard clears in 30s.") {
		t.Errorf("copied %q:\n%s", a.copied, a.screen())
	}
	a.press("down", "enter")
	want, err := totp.CodeAt([]byte(seed), totp.Params{}, a.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.copied) != 2 || a.copied[1] != want || !strings.Contains(a.screen(), "Copied totp/github/alice's code") {
		t.Errorf("copied %q, want the code %s:\n%s", a.copied, want, a.screen())
	}
	if !slices.Contains(f.reads, "secret password/github/alice in sesh ui, to copy it") || !slices.Contains(f.reads, "secret totp/github/alice in sesh ui, to copy its code") {
		t.Errorf("reads = %q", f.reads)
	}
	// The message goes after a few seconds.
	a.tick(6 * time.Second)
	if s := a.screen(); strings.Contains(s, "Copied") || !strings.Contains(s, "Enter copy") {
		t.Errorf("after 6s:\n%s", s)
	}
	failing := newApp(t, newFake(), Options{Copy: func(string) error { return errors.New("no clipboard") }})
	failing.press("enter")
	if s := failing.screen(); !strings.Contains(s, "Couldn't copy: no clipboard") || failing.quit {
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
	f.err = Locked("The vault's master password was changed by another sesh command.")
	a.press("enter")
	s := a.screen()
	if a.v != nil || !strings.Contains(s, "master password was changed by another sesh command") || !strings.Contains(s, "Touch ID") {
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
	if s := a.screen(); !strings.Contains(s, "4 entries") || !strings.Contains(s, "note      wifi") {
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
	if s := a.screen(); !strings.Contains(s, "› gitl ") || strings.Count(s, "\n") >= a.height {
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
