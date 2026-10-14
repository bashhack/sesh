package tui

import (
	"slices"
	"strings"
	"testing"
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
