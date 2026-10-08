package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

var aliceKey = vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}

// detailsOf reads an entry's details from the vault.
func detailsOf(t *testing.T, env *rekeyTestEnv, k vault.Key) vault.Details {
	t.Helper()
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	d, err := store.Details(k)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fieldList(d *vault.Details) string {
	var parts []string
	for _, f := range d.Fields {
		s := f.Name + "=" + string(f.Value)
		if f.Secret {
			s += " (secret)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// The URL, plain and secret fields, and notes are set, changed, and
// removed with sesh edit's flags, and it says what changed.
func TestEdit_Details(t *testing.T) {
	env := editVault(t)
	out, _, err := runEditOut(t, "4321\n", false, "password/github/alice", "--url", "https://github.com/login",
		"--field", "recovery-email=alice@example.com", "--field", "note=a=b", "--secret-field", "pin")
	if err != nil || out != "✅ password/github/alice: URL added, field recovery-email added, field note added, field pin added\n" {
		t.Fatalf("set: %q, %v", out, err)
	}
	d := detailsOf(t, env, aliceKey)
	if d.URL != "https://github.com/login" || fieldList(&d) != "recovery-email=alice@example.com, note=a=b, pin=4321 (secret)" {
		t.Errorf("details = %q, %s", d.URL, fieldList(&d))
	}
	// Notes come whole from stdin, line breaks and all.
	if got, _, err := runEditOut(t, "line one\nline two\n", false, "password/github/alice", "--notes"); err != nil || got != "✅ password/github/alice: notes added\n" {
		t.Fatalf("notes: %q, %v", got, err)
	}
	if d := detailsOf(t, env, aliceKey); string(d.Notes) != "line one\nline two\n" {
		t.Errorf("notes = %q", d.Notes)
	}
	out, _, err = runEditOut(t, "", false, "password/github/alice", "--url", "", "--remove-field", "PIN", "--remove-field", "note")
	if err != nil || out != "✅ password/github/alice: URL removed, field pin removed, field note removed\n" {
		t.Fatalf("remove: %q, %v", out, err)
	}
	// Empty notes remove them.
	if got, _, err := runEditOut(t, "", false, "password/github/alice", "--notes"); err != nil || got != "✅ password/github/alice: notes removed\n" {
		t.Fatalf("empty notes: %q, %v", got, err)
	}
	if d := detailsOf(t, env, aliceKey); d.URL != "" || d.Notes != nil || fieldList(&d) != "recovery-email=alice@example.com" {
		t.Errorf("after removing: %q %q %s", d.URL, d.Notes, fieldList(&d))
	}
}

// At a terminal, a secret field is asked for hidden, and notes are typed
// until Ctrl-D.
func TestEdit_DetailsAtATerminal(t *testing.T) {
	env := editVault(t)
	old := readSecret
	t.Cleanup(func() { readSecret = old })
	readSecret = func() ([]byte, error) { return []byte("4321"), nil }
	_, stderr, err := runEditOut(t, "typed notes\n", true, "password/github/alice", "--secret-field", "pin", "--notes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "Value for pin: ") || !strings.Contains(stderr, "Type the notes for password/github/alice, then press Ctrl-D on a new line:") {
		t.Errorf("prompts = %q", stderr)
	}
	if d := detailsOf(t, env, aliceKey); string(d.Notes) != "typed notes\n" || fieldList(&d) != "pin=4321 (secret)" {
		t.Errorf("details = %q, %s", d.Notes, fieldList(&d))
	}
}

// --editor opens $VISUAL or $EDITOR on the current notes, in a private
// folder that's gone afterwards; what's saved, less the newline the
// editor ends the file with, becomes the notes.
func TestEdit_NotesInAnEditor(t *testing.T) {
	env := editVault(t)
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncp \"$1\" '"+seen+"'\necho \"$1\" >> '"+seen+".path'\nprintf 'edited\\nnotes\\n' > \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script)
	if _, _, err := runEditOut(t, "first\n", false, "password/github/alice", "--notes"); err != nil {
		t.Fatal(err)
	}
	out, _, err := runEditOut(t, "", true, "password/github/alice", "--notes", "--editor")
	if err != nil || out != "✅ password/github/alice: notes changed\n" {
		t.Fatalf("--editor: %q, %v", out, err)
	}
	if b, err := os.ReadFile(seen); err != nil || string(b) != "first\n" {
		t.Errorf("the editor was given %q, %v; want the current notes", b, err)
	}
	if d := detailsOf(t, env, aliceKey); string(d.Notes) != "edited\nnotes" {
		t.Errorf("notes = %q", d.Notes)
	}
	path, err := os.ReadFile(seen + ".path")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(strings.TrimSpace(string(path)))); !os.IsNotExist(err) {
		t.Errorf("the editor's folder is still there: %v", err)
	}
}

func TestEdit_DetailsRefused(t *testing.T) {
	editVault(t)
	for _, tc := range []struct {
		stdin, wantSub string
		args           []string
	}{
		{"", "a secure note can't have notes", []string{"secure_note/recovery", "--notes"}},
		{"", "--field wants name=value", []string{"password/github/alice", "--field", "pin"}},
		{"", `the field name "url" is reserved`, []string{"password/github/alice", "--field", "url=x"}},
		{"", "--editor opens the notes in your editor: add --notes", []string{"password/github/alice", "--editor"}},
		{"", "--editor needs a terminal", []string{"password/github/alice", "--notes", "--editor"}},
		{"", `the field "pin" is set twice`, []string{"password/github/alice", "--field", "pin=1", "--secret-field", "PIN"}},
		{"", `the field "pin" is both set and removed`, []string{"password/github/alice", "--field", "pin=1", "--remove-field", "pin"}},
		{"a\nb\n", "without a terminal, only one value can come from stdin", []string{"password/github/alice", "--notes", "--secret-field", "pin"}},
		{"a\nb\n", "a secret field's value is one line", []string{"password/github/alice", "--secret-field", "pin"}},
		{"", `there's no field "nope" to remove; it has no fields`, []string{"password/github/alice", "--remove-field", "nope"}},
		{"", "nothing to change: the entry already has that URL", []string{"password/github/alice", "--url", ""}},
	} {
		if _, _, err := runEditOut(t, tc.stdin, false, tc.args...); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("edit %q = %v, want an error containing %q", tc.args, err, tc.wantSub)
		}
	}
}

// A rename to a secure note can remove the notes in the same edit.
func TestEdit_RenameToANoteRemovingNotes(t *testing.T) {
	env := editVault(t)
	if _, _, err := runEditOut(t, "some notes", false, "password/gitlab", "--notes"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runEditOut(t, "", false, "password/gitlab", "--type", "secure_note"); err == nil || !strings.Contains(err.Error(), "remove the notes first") {
		t.Errorf("rename keeping notes = %v, want refused", err)
	}
	out, _, err := runEditOut(t, "", false, "password/gitlab", "--type", "secure_note", "--notes")
	if err != nil || out != "✅ secure_note/gitlab: renamed from password/gitlab and notes removed\n" {
		t.Fatalf("rename removing notes: %q, %v", out, err)
	}
	if d := detailsOf(t, env, vault.Key{Kind: vault.KindNote, Service: "gitlab"}); d.Notes != nil {
		t.Errorf("notes = %q", d.Notes)
	}
}
