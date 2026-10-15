package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// Ctrl-K i, e exports the vault: the form checks the password, asks once about an easy one, and the export is written.
func TestExport(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{IsWeak: func(pw []byte) bool { return string(pw) == "password" }})
	a.press("ctrl+g", "i", "e")
	if a.form == nil || a.form.title != "Export the vault" {
		t.Fatalf("form %+v", a.form)
	}
	fill := func(file, pw, again string) {
		a.press("shift+tab", "shift+tab", "ctrl+u", file, "tab", "ctrl+u", pw, "tab", "ctrl+u", again, "enter")
	}
	for _, c := range []struct{ file, pw, again, wantSub string }{
		{"", "export-pass-1", "export-pass-1", "Type where to put it."},
		{"~/b.enc", "short", "short", "at least 8 characters"},
		{"~/b.enc", "export-pass-1", "export-pass-2", "don't match"},
		{"~/b.enc", "password", "password", "Press Enter again to use it anyway"},
	} {
		fill(c.file, c.pw, c.again)
		if a.form == nil || !strings.Contains(a.form.err, c.wantSub) || len(f.exports) != 0 {
			t.Fatalf("%+v: exports %q, form %+v", c, f.exports, a.form)
		}
	}
	// Enter again: the easy one is used.
	a.press("enter")
	if !slices.Equal(f.exports, []string{"~/b.enc password false"}) {
		t.Fatalf("an easy password, Enter again: exports %q", f.exports)
	}
	a.press("ctrl+g", "i", "e")
	inputs := a.form.inputs
	fill("~/c.enc", "export-pass-1", "export-pass-1")
	if f.exports[1] != "~/c.enc export-pass-1 false" || a.form != nil || !strings.Contains(a.screen(), "Exported 3 entries to ~/c.enc.") {
		t.Errorf("exports %q, form %v\n%s", f.exports, a.form != nil, a.screen())
	}
	// What was typed is wiped once it's written.
	for _, in := range inputs[1:] {
		if strings.Trim(string(in.secret), "\x00") != "" {
			t.Errorf("%s still holds %q", in.label, in.secret)
		}
	}
}

// An export's result that comes after a lock and unlock leaves the form opened since alone.
func TestExportAcrossLock(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	_, write := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	// Written, its result held back until after the lock and unlock.
	result := write()
	a.run(a.lock("You locked it."))
	if !strings.Contains(a.lockedWhy, "The export may or may not have been written: look at ~/b.enc") {
		t.Errorf("locked: %q", a.lockedWhy)
	}
	a.run(func() tea.Msg { return unlockedMsg{v: newFake()} })
	a.press("ctrl+g", "i", "e")
	open := a.form
	a.run(func() tea.Msg { return result })
	if a.form == nil || a.form != open {
		t.Error("the old export's result closed the form opened since")
	}
	// Locked before it's written: the password it was handed is wiped.
	b := newApp(t, newFake(), Options{})
	b.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	typed := b.form.inputs[1].secret
	_, write = b.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	b.run(b.lock("You locked it."))
	if msg := write(); msg != nil || strings.Trim(string(typed), "\x00") != "" {
		t.Errorf("not written: %v, %q", msg, typed)
	}
}

// A file there already is said, and Enter again replaces it; another file asks again.
func TestExportReplaces(t *testing.T) {
	f := newFake()
	f.exported = map[string]bool{"~/b.enc": true, "~/c.enc": true}
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "~/b.enc already exists. Press Enter again to replace it.") {
		t.Fatalf("form %+v", a.form)
	}
	a.press("shift+tab", "shift+tab", "ctrl+u", "~/c.enc", "enter", "enter", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "~/c.enc already exists") {
		t.Fatalf("another file: %q, form %+v", f.exports, a.form)
	}
	a.press("enter")
	if a.form != nil || f.exports[len(f.exports)-1] != "~/c.enc export-pass-1 true" {
		t.Errorf("exports %q", f.exports)
	}
}

// A failure keeps the form; a lock while it's written locks; Ctrl-C quits once it's written.
func TestExportFails(t *testing.T) {
	f := newFake()
	a := newApp(t, f, Options{})
	a.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	f.err = Locked("sesh's agent locked the vault.")
	a.press("enter")
	if a.v != nil {
		t.Error("not locked")
	}
	h := newFake()
	c := newApp(t, h, Options{})
	c.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	h.err = errors.New("permission denied")
	c.press("enter")
	if c.form == nil || c.form.saving || c.form.err != "Not exported: permission denied." {
		t.Errorf("a failure: form %+v", c.form)
	}
	g := newFake()
	b := newApp(t, g, Options{})
	b.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	_, write := b.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	b.press("ctrl+c")
	if b.quit || !strings.Contains(b.screen(), "Quitting once the export is written") {
		t.Fatalf("quit %v\n%s", b.quit, b.screen())
	}
	inputs := b.form.inputs
	b.run(write)
	if !b.quit || b.Afterword() != "Exported 3 entries to ~/b.enc." {
		t.Errorf("quit %v, said after %q", b.quit, b.Afterword())
	}
	for _, in := range inputs[1:] {
		if strings.Trim(string(in.secret), "\x00") != "" {
			t.Errorf("quitting, %s still holds %q", in.label, in.secret)
		}
	}
	// One that fails says so after.
	k := newFake()
	q := newApp(t, k, Options{})
	q.press("ctrl+g", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	k.err = errors.New("disk full")
	_, write = q.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	q.press("ctrl+c")
	q.run(write)
	if !q.quit || q.Afterword() != "The vault wasn't exported: disk full" {
		t.Errorf("quit %v, said after %q", q.quit, q.Afterword())
	}
}

// A secret handed to a read that never runs, the app having locked first, is wiped.
func TestWipeUnread(t *testing.T) {
	secret := []byte("export-pass-1")
	if msg := wipeUnread(secret, func() tea.Msg { return nil })(); msg != nil || strings.Trim(string(secret), "\x00") != "" {
		t.Errorf("not run: %v, %q", msg, secret)
	}
	kept := []byte("export-pass-1")
	if msg := wipeUnread(kept, func() tea.Msg { return "ran" })(); msg != "ran" || string(kept) != "export-pass-1" {
		t.Errorf("run: %v, %q", msg, kept)
	}
}
