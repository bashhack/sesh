package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// importApp is the app with a fake import: two entries, one the vault has, its export asking for a password.
func importApp(t *testing.T) (*app, *fakeVault) {
	t.Helper()
	f := newFake()
	f.importPassword = "bw-pass-1234"
	f.importing = &fakeImport{plans: map[string]ImportPlan{
		"":          {Summary: "Found 2 items in the Bitwarden export.\n\nTo import (1):\n  password/new\n\nAlready in the vault (1):\n  password/github/alice", Count: 1, Clashes: 1},
		"skip":      {Summary: "Found 2 items.\n\nAlready in the vault, left as they are (1):\n  password/github/alice", Count: 1, Clashes: 1},
		"overwrite": {Summary: "Found 2 items.\n\nAlready in the vault, to be replaced (1):\n  password/github/alice", Count: 2, Clashes: 1},
	}}
	return newApp(t, f, Options{}), f
}

// Ctrl-K i, b imports from Bitwarden: the file, then the password the export asks for, then a preview, where s or o
// says what's done with those the vault has, and y imports.
func TestImport(t *testing.T) {
	a, f := importApp(t)
	a.press("ctrl+k", "i", "b")
	if a.form == nil || a.form.title != "Import from Bitwarden" {
		t.Fatalf("form %+v", a.form)
	}
	a.press("~/bw.json", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "The Bitwarden export is protected by a password: type it below.") {
		t.Fatalf("asked for the password: form %+v", a.form)
	}
	a.press("enter")
	if a.form == nil || a.form.err != "Type the export's password." {
		t.Fatalf("no password typed: form %+v", a.form)
	}
	a.press("bw-pass-1234", "enter")
	if a.form != nil || a.ov == nil || a.ov.kind != panelImport || !strings.Contains(a.screen(), "Found 2 items in the Bitwarden export.") {
		t.Fatalf("starts %q, panel %+v", f.starts, a.ov)
	}
	if f.starts[1] != `bitwarden ["~/bw.json"] bw-pass-1234` {
		t.Errorf("starts %q", f.starts)
	}
	a.press("wait", "y")
	if a.ov == nil || !strings.Contains(a.ov.err, "s leaves them as they are, o replaces them") || slices.Contains(f.importing.asked, "apply") {
		t.Fatalf("y before choosing: %+v", a.ov)
	}
	a.press("s")
	if s := a.screen(); !strings.Contains(s, "left as they are") || !strings.Contains(s, "import 1 entry") {
		t.Fatalf("skip:\n%s", s)
	}
	a.press("o")
	if s := a.screen(); !strings.Contains(s, "to be replaced") || !strings.Contains(s, "import 2 entries") {
		t.Fatalf("overwrite:\n%s", s)
	}
	// A y in the same breath as the key that changed the plan doesn't import it.
	a.press("y")
	if slices.Contains(f.importing.asked, "apply") {
		t.Fatal("imported at once")
	}
	a.press("wait", "y")
	if !slices.Equal(f.importing.asked, []string{"plan ", "plan skip", "plan overwrite", "apply"}) || !f.importing.closed {
		t.Errorf("asked %q, closed %v", f.importing.asked, f.importing.closed)
	}
	if a.ov == nil || a.ov.kind != panelNotice || !strings.Contains(a.ov.question, "Imported 2 entries from Bitwarden.") {
		t.Errorf("after: %+v", a.ov)
	}
	a.press("enter")
	if a.ov == nil || a.ov.title != "Import and export" {
		t.Errorf("back to %+v", a.ov)
	}
}

// Esc from the preview, or the app locking, lets the import go, wiped; nothing is imported.
func TestImportCancelled(t *testing.T) {
	a, f := importApp(t)
	f.importPassword = ""
	a.press("ctrl+k", "i", "b", "~/bw.json", "enter", "esc")
	if !f.importing.closed || slices.Contains(f.importing.asked, "apply") || a.ov == nil || a.ov.title != "Import and export" {
		t.Errorf("Esc: asked %q, closed %v, panel %+v", f.importing.asked, f.importing.closed, a.ov)
	}
	b, g := importApp(t)
	g.importPassword = ""
	b.press("ctrl+k", "i", "b", "~/bw.json", "enter")
	b.run(b.lock("You locked it."))
	if !g.importing.closed {
		t.Error("the lock didn't let the import go")
	}
}

// Google Authenticator takes several files, separated by commas; none typed, the form says so.
func TestImportFiles(t *testing.T) {
	a, f := importApp(t)
	f.importPassword = ""
	a.press("ctrl+k", "i", "g", "enter")
	if a.form == nil || a.form.err != "Type the file to import." {
		t.Fatalf("form %+v", a.form)
	}
	a.press("~/a.png, ~/b.png", "enter")
	if len(f.starts) != 1 || f.starts[0] != `google-authenticator ["~/a.png" "~/b.png"] ` {
		t.Errorf("starts %q", f.starts)
	}
}

// previewApp is the app showing an import's preview, the vault having none of its entries.
func previewApp(t *testing.T, plans map[string]ImportPlan) (*app, *fakeVault) {
	t.Helper()
	f := newFake()
	f.importing = &fakeImport{plans: plans}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "i", "b", "~/bw.json", "enter")
	if a.ov == nil || a.ov.kind != panelImport {
		t.Fatalf("panel %+v", a.ov)
	}
	return a, f
}

// Enter on the preview's lines does nothing; it doesn't end the app.
func TestImportPreviewEnter(t *testing.T) {
	a, _ := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.\nTo import (1):\n  password/new", Count: 1}})
	a.press("enter")
	if a.quit || a.ov == nil || a.ov.kind != panelImport {
		t.Errorf("quit %v, panel %+v", a.quit, a.ov)
	}
}

// While the import is written Esc doesn't let it go: it carries on to the end. Ctrl-C quits once it's written.
func TestImportEscWhileApplied(t *testing.T) {
	a, f := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	a.now = a.now.Add(time.Second)
	_, apply := a.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	a.press("esc")
	if f.importing.closed || a.ov == nil || a.ov.kind != panelImport || !strings.Contains(a.screen(), "quit once it's written") {
		t.Fatalf("closed %v, panel %+v\n%s", f.importing.closed, a.ov, a.screen())
	}
	a.run(apply)
	if !f.importing.closed || a.ov == nil || a.ov.kind != panelNotice {
		t.Errorf("after: closed %v, panel %+v", f.importing.closed, a.ov)
	}
	// Ctrl-C quits once it's written, saying what it did.
	b, g := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	b.now = b.now.Add(time.Second)
	_, apply = b.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	b.press("ctrl+c")
	if s := b.screen(); b.quit || !strings.Contains(s, "Quitting once the import is written") || strings.Contains(s, "quit once it's written") {
		t.Fatalf("quit %v\n%s", b.quit, b.screen())
	}
	b.run(apply)
	if !b.quit || b.Afterword() != "Imported 2 entries from Bitwarden." || !g.importing.closed {
		t.Errorf("quit %v, said after %q, closed %v", b.quit, b.Afterword(), g.importing.closed)
	}
}

// The vault changing while the import is written, as the import changes it, leaves its panel to say what it did; a
// lock says an import was being written.
func TestImportChangedWhileApplied(t *testing.T) {
	a, f := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	a.now = a.now.Add(time.Second)
	_, apply := a.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	f.changed = true
	a.tick(time.Second)
	if a.ov == nil || a.ov.kind != panelImport || f.importing.closed {
		t.Fatalf("changed: closed %v, panel %+v", f.importing.closed, a.ov)
	}
	a.run(apply)
	if a.ov == nil || a.ov.kind != panelNotice || a.ov.question != "Imported 2 entries from Bitwarden." {
		t.Errorf("after: %+v", a.ov)
	}
	// The entry's menu the import was opened from, made before the change, isn't gone back to.
	a.press("enter")
	if a.ov == nil || a.ov.title != "Import and export" {
		t.Fatalf("back to %+v", a.ov)
	}
	a.press("esc")
	if a.ov != nil {
		t.Errorf("under the import and export panel: %+v", a.ov)
	}
	b, _ := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	b.now = b.now.Add(time.Second)
	b.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	b.run(b.lock("You locked it."))
	if !strings.HasPrefix(b.lockedWhy, "You locked it. An import was being written") {
		t.Errorf("locked: %q", b.lockedWhy)
	}
}

// A lock that stops the import says how far it got, once; quitting, that's said after.
func TestImportLockedWhileApplied(t *testing.T) {
	const why = "sesh's agent locked the vault. The import stopped, having imported 2 entries."
	a, f := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 3.", Count: 3}})
	f.importing.applyTo = func() (string, error) { return "", Locked(why) }
	a.press("wait", "y")
	if a.v != nil || a.lockedWhy != why {
		t.Errorf("locked %v: %q", a.v == nil, a.lockedWhy)
	}
	b, g := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 3.", Count: 3}})
	g.importing.applyTo = func() (string, error) { return "", Locked(why) }
	b.now = b.now.Add(time.Second)
	_, apply := b.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	b.press("ctrl+c")
	b.run(apply)
	if !b.quit || b.Afterword() != why {
		t.Errorf("quit %v, said after %q", b.quit, b.Afterword())
	}
}

// A result from an import that isn't the one shown leaves the preview alone.
func TestImportStaleResult(t *testing.T) {
	a, f := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	a.run(func() tea.Msg { return importedMsg{in: &importing{}, said: "FROM ANOTHER", epoch: a.epoch} })
	if a.ov == nil || a.ov.kind != panelImport || f.importing.closed {
		t.Errorf("closed %v, panel %+v", f.importing.closed, a.ov)
	}
}

// An import that stops partway says what it imported; one that fails first says nothing was.
func TestImportApplyFails(t *testing.T) {
	for err, want := range map[string]string{
		"imported 1 entry, then password/x failed: boom": "The import stopped: imported 1 entry, then password/x failed: boom",
		"disk full": "Not imported: disk full",
	} {
		a, f := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 2.", Count: 2}})
		f.importing.applyTo = func() (string, error) { return "", errors.New(err) }
		a.press("wait", "y")
		if a.ov == nil || a.ov.kind != panelNotice || a.ov.question != want {
			t.Errorf("%s: %+v", err, a.ov)
		}
	}
}

// Each source's letter on the panel opens its form.
func TestImportLetters(t *testing.T) {
	for _, s := range importSources {
		a := newApp(t, newFake(), Options{})
		a.press("ctrl+k", "i", s.key)
		if a.form == nil || a.form.title != "Import from "+s.name {
			t.Errorf("%s: form %+v", s.key, a.form)
		}
	}
}

// A plan that fails leaves nothing to import: y does nothing, and s or o plans again.
func TestImportPlanFails(t *testing.T) {
	f := newFake()
	f.importing = &fakeImport{
		plans:   map[string]ImportPlan{"": {Summary: "Found 2.", Count: 1, Clashes: 1}, "overwrite": {Summary: "Found 2, replacing.", Count: 2, Clashes: 1}},
		failing: map[string]error{"skip": errors.New("the file is gone")},
	}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "i", "b", "~/bw.json", "enter", "s")
	if a.ov == nil || !strings.Contains(a.ov.err, "Not read: the file is gone") || strings.Contains(a.screen(), "Found 2.") {
		t.Fatalf("after a failed plan: %+v\n%s", a.ov, a.screen())
	}
	a.press("wait", "y")
	if slices.Contains(f.importing.asked, "apply") || !strings.Contains(a.ov.err, "Not read: the file is gone") {
		t.Fatalf("y after a failed plan: asked %q, said %q", f.importing.asked, a.ov.err)
	}
	a.press("o")
	if s := a.screen(); !strings.Contains(s, "replacing") || strings.Contains(s, "Not read") || a.ov.err != "" {
		t.Errorf("o after a failed plan:\n%s", s)
	}
}

// A plan from an import let go doesn't show in the next one's preview.
func TestImportStalePlan(t *testing.T) {
	f := newFake()
	first := &fakeImport{plans: map[string]ImportPlan{"": {Summary: "FROM THE FIRST", Count: 7}}}
	f.importing = first
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "i", "b", "~/a.json")
	_, read := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	started := read()
	_, plan := a.Update(started)
	held := plan
	a.press("esc")
	f.importing = &fakeImport{plans: map[string]ImportPlan{"": {Summary: "FROM THE SECOND", Count: 1}}}
	a.press("b", "~/b.json", "enter")
	a.run(held)
	if s := a.screen(); strings.Contains(s, "FROM THE FIRST") || !strings.Contains(s, "FROM THE SECOND") {
		t.Errorf("the second import's preview:\n%s", s)
	}
}

// Another command changing the vault closes the preview, and lets the import go; so does quitting.
func TestImportLetGo(t *testing.T) {
	a, f := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	f.changed = true
	a.tick(time.Second)
	if a.ov != nil || !f.importing.closed {
		t.Errorf("vault changed: panel %+v, closed %v", a.ov, f.importing.closed)
	}
	b, g := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 1}})
	b.Close()
	if !g.importing.closed {
		t.Error("quitting didn't let the import go")
	}
}

// With nothing to import, what to do about the file is still said; a narrow window keeps every letter's key.
func TestImportNothingAndNarrow(t *testing.T) {
	a, _ := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 1.", Count: 0, After: "Delete ~/bw.json now."}})
	a.press("wait", "y")
	if a.ov == nil || a.ov.err != "Nothing to import. Delete ~/bw.json now." {
		t.Errorf("nothing: %+v", a.ov)
	}
	b, _ := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 2.", Count: 1, Clashes: 1}})
	b.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	s := b.screen()
	if !strings.Contains(s, " s ") || !strings.Contains(s, " o ") {
		t.Errorf("narrow, the keys:\n%s", s)
	}
	// A plan that failed keeps its letters too, on one line.
	c, g := previewApp(t, map[string]ImportPlan{"": {Summary: "Found 2.", Count: 1, Clashes: 1}})
	g.importing.failing = map[string]error{"skip": errors.New("the file is gone")}
	c.press("s")
	c.Update(tea.WindowSizeMsg{Width: 44, Height: 14})
	if s := c.screen(); !strings.Contains(s, " s ") || !strings.Contains(s, " o ") || !strings.Contains(s, "esc") || strings.Contains(s, "read it again") {
		t.Errorf("narrow, a failed plan's keys:\n%s", s)
	}
}

// One file's path keeps its commas; a long line of the summary is wrapped, not cut.
func TestImportPathsAndLongLines(t *testing.T) {
	f := newFake()
	long := "  " + strings.Repeat("word ", 30) + "end"
	f.importing = &fakeImport{plans: map[string]ImportPlan{"": {Summary: long, Count: 1}}}
	a := newApp(t, f, Options{})
	a.press("ctrl+k", "i", "b", "~/export, 2026.json", "enter")
	if len(f.starts) != 1 || f.starts[0] != `bitwarden ["~/export, 2026.json"] ` {
		t.Errorf("starts %q", f.starts)
	}
	if s := a.screen(); strings.Contains(s, "word…") || !strings.Contains(s, "word end") {
		t.Errorf("the long line:\n%s", s)
	}
	// Wrapped again when the window narrows.
	a.Update(tea.WindowSizeMsg{Width: 50, Height: 40})
	if s := a.screen(); strings.Contains(s, "word…") || strings.Count(s, "word") != 30 || !strings.Contains(s, "end") {
		t.Errorf("narrowed, the long line:\n%s", s)
	}
}
