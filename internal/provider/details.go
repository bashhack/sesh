package provider

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// DetailsFlags are the flags that change an entry's details: --url,
// --notes (with --editor), --field, --secret-field, and --remove-field.
// sesh edit and the password manager's store share them.
type DetailsFlags struct {
	url                          urlFlag
	fields, secretFields, remove listFlag
	notes, editor                bool
}

// urlFlag is --url. given tells --url "" (remove it) from no flag.
type urlFlag struct {
	value string
	given bool
}

func (f *urlFlag) String() string { return f.value }

func (f *urlFlag) Set(v string) error {
	f.value, f.given = v, true
	return nil
}

// listFlag is a flag given once per value.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, " ") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// Register defines the flags on fs.
func (f *DetailsFlags) Register(fs FlagSet) {
	fs.Var(&f.url, "url", `Its web address ("" removes it)`)
	fs.BoolVar(&f.notes, "notes", false, "Notes, from stdin (empty removes them)")
	fs.BoolVar(&f.editor, "editor", false, "With --notes: write them in $VISUAL or $EDITOR")
	fs.Var(&f.fields, "field", "Set a field: name=value (repeat for more)")
	fs.Var(&f.secretFields, "secret-field", "Set a secret field, typed hidden or from stdin (repeat for more)")
	fs.Var(&f.remove, "remove-field", "Remove a field (repeat for more)")
}

// FlagInfo describes the flags, for help and shell completion.
func (f *DetailsFlags) FlagInfo() []FlagInfo {
	return []FlagInfo{
		{Name: "url", Type: "string", Description: `Its web address ("" removes it)`},
		{Name: "notes", Type: "bool", Description: "Notes, from stdin (empty removes them)"},
		{Name: "editor", Type: "bool", Description: "With --notes: write them in $VISUAL or $EDITOR"},
		{Name: "field", Type: "string", Description: "Set a field: name=value (repeat for more)"},
		{Name: "secret-field", Type: "string", Description: "Set a secret field, typed hidden or from stdin (repeat for more)"},
		{Name: "remove-field", Type: "string", Description: "Remove a field (repeat for more)"},
	}
}

// Given reports whether any of the flags was given.
func (f *DetailsFlags) Given() bool {
	return f.url.given || f.notes || f.editor || len(f.fields)+len(f.secretFields)+len(f.remove) > 0
}

// Fields are the --field values as given, for a command that reads
// --field another way, as get takes a field's name.
func (f *DetailsFlags) Fields() []string { return f.fields }

// GivenBesidesField reports whether any of the flags other than --field
// was given.
func (f *DetailsFlags) GivenBesidesField() bool {
	return f.url.given || f.notes || f.editor || len(f.secretFields)+len(f.remove) > 0
}

// OnlyURL reports whether --url is the only one given.
func (f *DetailsFlags) OnlyURL() bool {
	return f.url.given && !f.notes && len(f.fields)+len(f.secretFields)+len(f.remove) == 0
}

// Editor reports whether the notes are to be written in an editor.
func (f *DetailsFlags) Editor() bool { return f.editor }

// FromStdin is how many values the flags read from stdin without a
// terminal: the notes, unless written in an editor, and each secret field.
func (f *DetailsFlags) FromStdin() int {
	n := len(f.secretFields)
	if f.notes && !f.editor {
		n++
	}
	return n
}

// Change is the change the flags ask for, for an entry becoming one of
// kind (from one of fromKind), without the values still to be read (see
// Read); nil when none is given. What can be refused without the vault is
// refused here.
func (f *DetailsFlags) Change(fromKind, kind vault.Kind, terminal bool) (*vault.DetailsChange, error) {
	if f.editor && !f.notes {
		return nil, errors.New("--editor opens the notes in your editor: add --notes")
	}
	if f.editor && !terminal {
		return nil, errors.New("--editor needs a terminal to open your editor in")
	}
	if f.notes && fromKind == vault.KindNote && kind == vault.KindNote {
		return nil, errors.New("a secure note can't have notes: its secret is the note")
	}
	if !f.Given() {
		return nil, nil
	}
	c := &vault.DetailsChange{SetNotes: f.notes}
	if f.url.given {
		c.URL = &f.url.value
	}
	type naming struct{ name, how string }
	named := map[string]naming{}
	name := func(n, how string) error {
		if err := vault.CheckFieldName(n); err != nil {
			return err
		}
		if was, ok := named[strings.ToLower(n)]; ok {
			switch {
			case was.how != how:
				return fmt.Errorf("the field %q is both set and removed", was.name)
			case was.name != n:
				return fmt.Errorf("the field %q is %s twice (as %q)", was.name, how, n)
			}
			return fmt.Errorf("the field %q is %s twice", n, how)
		}
		named[strings.ToLower(n)] = naming{n, how}
		return nil
	}
	for _, kv := range f.fields {
		n, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("--field wants name=value, not %q; for a secret field, use --secret-field %s", kv, kv)
		}
		if err := name(n, "set"); err != nil {
			return nil, err
		}
		c.Set = append(c.Set, vault.Field{Name: n, Value: []byte(v)})
	}
	for _, n := range f.secretFields {
		if err := name(n, "set"); err != nil {
			return nil, err
		}
		c.Set = append(c.Set, vault.Field{Name: n, Secret: true})
	}
	for _, n := range f.remove {
		if err := name(n, "removed"); err != nil {
			return nil, err
		}
		c.Remove = append(c.Remove, n)
	}
	return c, nil
}

// DetailsInput is where Read reads values from.
type DetailsInput struct {
	Stdin  io.Reader
	Stderr io.Writer
	// ReadSecret reads a line typed at the terminal without showing it.
	ReadSecret func() ([]byte, error)
	// Notes returns the entry's current notes, for an editor to start
	// from; the caller zeroes them. Nil starts from none.
	Notes func() ([]byte, error)
	// Name is the entry, for prompts.
	Name     string
	Terminal bool
	// KeepNotes says that notes ended at once at a terminal keep the
	// notes as they are, rather than cancelling the command.
	KeepNotes bool
}

// Read reads the values c still needs: each secret field, asked for hidden
// at a terminal or read as a line from stdin, then the notes, typed until
// Ctrl-D, read from stdin, or written in an editor.
func (f *DetailsFlags) Read(c *vault.DetailsChange, in *DetailsInput) error {
	for i := range c.Set {
		fl := &c.Set[i]
		if !fl.Secret {
			continue
		}
		var v []byte
		var err error
		if in.Terminal {
			fmt.Fprintf(in.Stderr, "Value for %s: ", fl.Name) //nolint:errcheck // prompt
			v, err = in.ReadSecret()
			fmt.Fprintln(in.Stderr) //nolint:errcheck // ends the prompt line
		} else {
			// Room for the value and the line break that ends it.
			v, err = io.ReadAll(io.LimitReader(in.Stdin, vault.MaxDetailsSize+3))
			v = bytes.TrimSuffix(bytes.TrimSuffix(v, []byte("\n")), []byte("\r"))
			if err == nil && len(v) > vault.MaxDetailsSize {
				secure.SecureZeroBytes(v)
				return fmt.Errorf("the value for %s is over %d bytes, the most an entry holds; nothing changed", fl.Name, vault.MaxDetailsSize)
			}
			if err == nil && bytes.ContainsAny(v, "\r\n") {
				secure.SecureZeroBytes(v)
				return errors.New("a secret field's value is one line, and this has several; nothing changed")
			}
		}
		if err != nil {
			secure.SecureZeroBytes(v)
			return fmt.Errorf("read the value for %s: %w", fl.Name, err)
		}
		if len(v) == 0 {
			return fmt.Errorf("the value for %s is empty; nothing changed", fl.Name)
		}
		fl.Value = v
	}
	if !c.SetNotes {
		return nil
	}
	var notes []byte
	var err error
	if f.editor {
		var current []byte
		if in.Notes != nil {
			if current, err = in.Notes(); err != nil {
				return err
			}
		}
		notes, err = EditNotes(current)
		// The new notes replace these, so they must still be the entry's
		// when the change is written.
		c.NotesBase, c.HasNotesBase = current, true
	} else {
		if in.Terminal {
			alone := "changes nothing"
			if in.KeepNotes {
				alone = "keeps the notes as they are"
			}
			fmt.Fprintf(in.Stderr, "Type the notes for %s, then press Ctrl-D on a new line (Ctrl-D alone %s):\n", in.Name, alone) //nolint:errcheck // prompt
		}
		notes, err = io.ReadAll(io.LimitReader(in.Stdin, vault.MaxDetailsSize+1))
		if err == nil && in.Terminal && len(notes) == 0 {
			return ErrNothingTyped
		}
	}
	if err != nil {
		secure.SecureZeroBytes(notes)
		return fmt.Errorf("read the notes: %w", err)
	}
	if len(notes) > vault.MaxDetailsSize {
		secure.SecureZeroBytes(notes)
		return fmt.Errorf("the notes are over %d bytes, the most an entry holds; nothing changed", vault.MaxDetailsSize)
	}
	c.Notes = notes
	return nil
}

// ErrNothingTyped is notes ended at once at a terminal: nothing changes.
// Piped-in empty notes remove them instead.
var ErrNothingTyped = errors.New("nothing typed")

// CheckAgainst refuses, before any value is read, what c can't do to the
// entry e (none for a new entry): remove a field it doesn't have, or put a
// plain value in place of a secret field.
func CheckAgainst(e *vault.Entry, c *vault.DetailsChange) error {
	names := make([]string, len(e.Fields))
	for i, fl := range e.Fields {
		names[i] = fl.Name
	}
	find := func(name string) int {
		for i, n := range names {
			if strings.EqualFold(n, name) {
				return i
			}
		}
		return -1
	}
	for _, name := range c.Remove {
		if find(name) < 0 {
			return vault.NoFieldToRemove(name, names)
		}
	}
	for _, fl := range c.Set {
		if i := find(fl.Name); i >= 0 && e.Fields[i].Secret && !fl.Secret {
			return fmt.Errorf("%s is a secret field: set it with --secret-field %s, or remove it first to make it plain", names[i], names[i])
		}
	}
	return nil
}

// ZeroChange overwrites the notes and secret values c holds.
func ZeroChange(c *vault.DetailsChange) {
	secure.SecureZeroBytes(c.Notes)
	secure.SecureZeroBytes(c.NotesBase)
	for _, fl := range c.Set {
		if fl.Secret {
			secure.SecureZeroBytes(fl.Value)
		}
	}
}

// EditNotes opens notes in the user's editor ($VISUAL, then $EDITOR,
// then vi), in a folder only they can read, in memory (/dev/shm) where
// the system has one, and returns what was saved, less the newline an
// editor ends a file with; the notes themselves when the file is as it
// was. Afterwards the file's bytes are overwritten and the folder
// removed, even when sesh is interrupted or its terminal closes meanwhile;
// the editor may keep its own copies, such as swap files.
func EditNotes(notes []byte) (_ []byte, err error) {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	base := ""
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		base = "/dev/shm"
	}
	dir, err := os.MkdirTemp(base, "sesh-notes-")
	if err != nil {
		return nil, fmt.Errorf("make a folder for the editor: %w", err)
	}
	path := filepath.Join(dir, "notes.txt")
	var once sync.Once
	cleanUp := func() { once.Do(func() { wipe(path); _ = os.RemoveAll(dir) }) } //nolint:errcheck // best effort

	// While the editor runs, Ctrl-C and Ctrl-\ are the editor's, as git
	// has it; a closed terminal or a request to stop cleans up first. The
	// file goes before the handling stops, so no signal finds it there.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM)
	done := make(chan struct{})
	defer func() { cleanUp(); signal.Stop(sigs); close(done) }()
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig == syscall.SIGHUP || sig == syscall.SIGTERM {
					cleanUp()
					fmt.Fprintln(os.Stderr, "Stopped while the editor was open; nothing changed.") //nolint:errcheck // best effort
					os.Exit(1)
				}
			case <-done:
				return
			}
		}
	}()

	if err := os.WriteFile(path, notes, 0o600); err != nil {
		return nil, fmt.Errorf("write the notes for the editor: %w", err)
	}
	// Through sh, so an editor given with flags ("code --wait") works.
	cmd := exec.Command("sh", "-c", editor+` "$1"`, "sh", path) //nolint:gosec // the user's own editor setting
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "SESH_MASTER_PASSWORD=") })
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("the editor (%s) failed: %w; nothing changed", editor, err)
	}
	file, err := os.Open(path) //nolint:gosec // the file made above
	if err != nil {
		return nil, fmt.Errorf("read the notes back: %w", err)
	}
	defer file.Close() //nolint:errcheck // read only
	saved, err := io.ReadAll(io.LimitReader(file, vault.MaxDetailsSize+2))
	if err != nil {
		secure.SecureZeroBytes(saved)
		return nil, fmt.Errorf("read the notes back: %w", err)
	}
	if bytes.Equal(saved, notes) {
		secure.SecureZeroBytes(saved)
		return bytes.Clone(notes), nil
	}
	return bytes.TrimSuffix(bytes.TrimSuffix(saved, []byte("\n")), []byte("\r")), nil
}

// wipe overwrites the file at path with zeros, in place, before it's
// removed. A file system that writes changes elsewhere, as APFS and
// copy-on-write ones do, can still hold the old bytes until reused.
func wipe(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // the file EditNotes made
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck // best effort
	if info, err := f.Stat(); err == nil {
		_, _ = f.WriteAt(make([]byte, info.Size()), 0) //nolint:errcheck // best effort
		_ = f.Sync()                                   //nolint:errcheck // best effort
	}
}
