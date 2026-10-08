package provider

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// detailsFlags parses args into DetailsFlags.
func detailsFlags(t *testing.T, args ...string) *DetailsFlags {
	t.Helper()
	var f DetailsFlags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return &f
}

func useEditor(t *testing.T, body string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script)
}

// Notes written in an editor carry the notes they were written from, so
// the change is refused if those changed meanwhile.
func TestRead_EditorKeepsTheNotesItStartedFrom(t *testing.T) {
	useEditor(t, `printf 'new notes\n' > "$1"`)
	f := detailsFlags(t, "--notes", "--editor")
	c, err := f.Change(vault.KindPassword, vault.KindPassword, true)
	if err != nil {
		t.Fatal(err)
	}
	in := &DetailsInput{Terminal: true, Stderr: &bytes.Buffer{}, Notes: func() ([]byte, error) { return []byte("old notes"), nil }}
	if err := f.Read(c, in); err != nil {
		t.Fatal(err)
	}
	if string(c.Notes) != "new notes" || !c.HasNotesBase || string(c.NotesBase) != "old notes" {
		t.Fatalf("change = notes %q, base %q (%v)", c.Notes, c.NotesBase, c.HasNotesBase)
	}
	d := vault.Details{Notes: []byte("changed meanwhile")}
	if _, err := c.Apply(&d); !errors.Is(err, vault.ErrNotesChanged) {
		t.Errorf("Apply after a change meanwhile = %v, want ErrNotesChanged", err)
	}
}

// Ctrl-C while the editor runs is the editor's: sesh carries on, and the
// file is gone afterwards.
func TestEditNotes_InterruptIsTheEditors(t *testing.T) {
	where := filepath.Join(t.TempDir(), "where")
	useEditor(t, `echo "$1" > '`+where+`'; kill -INT `+strconv.Itoa(os.Getpid())+`; sleep 0.2; printf 'kept\n' > "$1"`)
	got, err := EditNotes([]byte("before"))
	if err != nil || string(got) != "kept" {
		t.Fatalf("EditNotes = %q, %v", got, err)
	}
	path, err := os.ReadFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(strings.TrimSpace(string(path)))); !os.IsNotExist(err) {
		t.Errorf("the editor's folder is still there: %v", err)
	}
}

// A secret field's value read from stdin is refused when it's too big,
// not cut to its first line.
func TestRead_SecretFieldTooBig(t *testing.T) {
	f := detailsFlags(t, "--secret-field", "pin")
	c, err := f.Change(vault.KindPassword, vault.KindPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("A", vault.MaxDetailsSize) + "\nsecond line"
	err = f.Read(c, &DetailsInput{Stdin: strings.NewReader(big), Stderr: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "the value for pin is over 1048576 bytes") {
		t.Errorf("Read = %v", err)
	}
}

// What a change can't do to an entry is found from its readable part.
func TestCheckAgainst(t *testing.T) {
	e := vault.Entry{Fields: []vault.Field{{Name: "pin", Secret: true}, {Name: "email", Value: []byte("a@b")}}}
	for _, tc := range []struct {
		wantSub string
		c       vault.DetailsChange
	}{
		{`there's no field "nope" to remove; its fields: pin, email`, vault.DetailsChange{Remove: []string{"nope"}}},
		{"pin is a secret field: set it with --secret-field pin", vault.DetailsChange{Set: []vault.Field{{Name: "PIN", Value: []byte("1")}}}},
		{"", vault.DetailsChange{Set: []vault.Field{{Name: "email", Value: []byte("1"), Secret: true}}, Remove: []string{"PIN"}}},
	} {
		err := CheckAgainst(&e, &tc.c)
		if (tc.wantSub == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantSub)) {
			t.Errorf("CheckAgainst(%+v) = %v, want %q", tc.c, err, tc.wantSub)
		}
	}
	if err := CheckAgainst(&vault.Entry{}, &vault.DetailsChange{Remove: []string{"x"}}); err == nil || !strings.Contains(err.Error(), "it has no fields") {
		t.Errorf("a new entry: %v", err)
	}
}
