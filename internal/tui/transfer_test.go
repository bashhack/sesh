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
	a.press("ctrl+k", "i", "e")
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
	fill("~/b.enc", "export-pass-1", "export-pass-1")
	if !slices.Equal(f.exports, []string{"~/b.enc export-pass-1 false"}) || a.form != nil || !strings.Contains(a.screen(), "Exported 3 entries to ~/b.enc.") {
		t.Errorf("exports %q, form %v\n%s", f.exports, a.form != nil, a.screen())
	}
}

// A file there already is said, and Enter again replaces it; another file asks again.
func TestExportReplaces(t *testing.T) {
	f := newFake()
	f.exported = map[string]bool{"~/b.enc": true, "~/c.enc": true}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1", "enter")
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
	a.press("ctrl+k", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	f.err = Locked("sesh's agent locked the vault.")
	a.press("enter")
	if a.v != nil {
		t.Error("not locked")
	}
	h := newFake()
	c := newApp(t, h, Options{})
	c.press("ctrl+k", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	h.err = errors.New("permission denied")
	c.press("enter")
	if c.form == nil || c.form.saving || c.form.err != "Not exported: permission denied." {
		t.Errorf("a failure: form %+v", c.form)
	}
	g := newFake()
	b := newApp(t, g, Options{})
	b.press("ctrl+k", "i", "e", "~/b.enc", "tab", "export-pass-1", "tab", "export-pass-1")
	_, write := b.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	b.press("ctrl+c")
	if b.quit || !strings.Contains(b.screen(), "Quitting once the export is written") {
		t.Fatalf("quit %v\n%s", b.quit, b.screen())
	}
	b.run(write)
	if !b.quit || b.Afterword() != "Exported 3 entries to ~/b.enc." {
		t.Errorf("quit %v, said after %q", b.quit, b.Afterword())
	}
}
