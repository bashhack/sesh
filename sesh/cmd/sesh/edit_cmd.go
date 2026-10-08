package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// readSecret reads a typed secret without echoing it; tests replace it.
var readSecret = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }

// editFlags are sesh edit's flags.
type editFlags struct {
	service, username, kind string
	length                  int
	secret, generate        bool
	noSymbols, force        bool
}

// addEditFlags defines sesh edit's flags on fs.
func addEditFlags(fs *flag.FlagSet) *editFlags {
	f := &editFlags{}
	fs.StringVar(&f.service, "service", "", "New service name")
	fs.StringVar(&f.username, "username", "", `New username ("" removes it)`)
	fs.StringVar(&f.kind, "type", "", "New kind: password, api_key, or secure_note")
	fs.BoolVar(&f.secret, "secret", false, "Type a new secret (a note reads stdin)")
	fs.BoolVar(&f.generate, "generate", false, "Generate a new password")
	fs.IntVar(&f.length, "length", 24, "Generated password length")
	fs.BoolVar(&f.noSymbols, "no-symbols", false, "Generate without symbols")
	fs.BoolVar(&f.force, "force", false, "Don't ask before taking an AWS entry out of the AWS provider")
	return f
}

const editUsage = `Usage: sesh edit <id> [flags]
  Rename an entry, change its username or kind, or give it a new secret.
  With no flags, at a terminal, it asks, with the current values as defaults.

  sesh edit password/github/alice --service github-work
  sesh edit password/github/alice --username alicia     ("" removes it)
  sesh edit password/github/alice --secret              (or --generate [--length N] [--no-symbols])
  sesh edit api_key/openai --type password              (password, api_key, secure_note)

Entry IDs are what --list shows.`

// runEdit is `sesh edit <id>`: rename an entry, change its username or
// kind, or give it a new secret. Everything that needs no vault is checked
// before unlocking it.
func runEdit(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, editUsage)
		return err
	}
	// The ID comes first; the flags after it.
	id, rest := args[0], args[1:]
	if strings.HasPrefix(id, "-") {
		return errors.New("name the entry first: sesh edit <id> [flags]")
	}
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	f := addEditFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh edit edits one entry; got %q after its flags", strings.Join(fs.Args(), " "))
	}
	from, err := vault.ParseKey(id)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	terminal := app.StdinIsTerminal != nil && app.StdinIsTerminal()
	asked := len(set) == 0
	if asked && !terminal {
		return errors.New("nothing to change: give --service, --username, --type, --secret, or --generate (or run it at a terminal to be asked)")
	}
	to, err := plannedKey(from, f, set)
	if err != nil {
		return err
	}
	if err := checkEditSecret(from, to, f); err != nil {
		return err
	}
	if !asked && to == from && !f.secret && !f.generate {
		return errors.New("nothing to change: the entry already has that name and kind")
	}

	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	if err := store.Exists(from); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			if h := password.CaseHint(store, from); h != "" {
				err = fmt.Errorf("%w; %s", err, h)
			}
		}
		return err
	}

	if asked {
		if to, f, err = askEdit(app, from); err != nil {
			return err
		}
		if to == from && !f.secret && !f.generate {
			_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
			return err
		}
	}
	if from.Kind == vault.KindTOTP && from.Service == vault.AWSKey("").Service && to.Service != from.Service && !f.force {
		if !terminal {
			return errors.New("this is an AWS profile's MFA entry, and a new service name takes it out of the AWS provider; add --force to do it anyway")
		}
		yes, err := promptYesNo(app.Stdin, app.Stderr, fmt.Sprintf("%s is an AWS profile's MFA entry; renamed to service %q, `sesh --service aws` won't find it. Rename it anyway? [y/N]: ", from, to.Service))
		if err != nil || !yes {
			if err == nil {
				_, err = fmt.Fprintln(app.Stderr, "Nothing changed.")
			}
			return err
		}
	}

	var e database.EntryEdit
	if to != from {
		e.To = &to
	}
	if f.secret || f.generate {
		secret, err := newSecret(app, to, f, terminal)
		if err != nil {
			return err
		}
		defer secure.SecureZeroBytes(secret)
		e.Secret = secret
	}
	detail, err := store.Edit(from, e)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ %s: %s\n", to, detail)
	return err
}

// plannedKey is the entry's key after the flags set says were given.
func plannedKey(from vault.Key, f *editFlags, set map[string]bool) (vault.Key, error) {
	to := from
	if set["service"] {
		to.Service = f.service
	}
	if set["username"] {
		to.Username = f.username
	}
	if set["type"] {
		to.Kind = vault.Kind(f.kind)
		if err := checkKindChange(from.Kind, to.Kind); err != nil {
			return vault.Key{}, err
		}
	}
	if err := to.Validate(); err != nil {
		return vault.Key{}, err
	}
	return to, nil
}

// checkKindChange refuses a change of kind other than among password,
// api_key, and secure_note: a TOTP secret needs a valid key and code
// settings, which totp-store and the setup wizard give it.
func checkKindChange(from, to vault.Kind) error {
	if from == to {
		return nil
	}
	if !to.Valid() {
		return fmt.Errorf("unknown --type %q: use password, api_key, or secure_note", to)
	}
	if from == vault.KindTOTP || to == vault.KindTOTP {
		return errors.New("a TOTP entry's kind can't change, nor can another become one: store a TOTP secret with --action totp-store or sesh --service totp --setup")
	}
	return nil
}

// checkEditSecret refuses a new secret the entry's kind can't take.
func checkEditSecret(from, to vault.Key, f *editFlags) error {
	switch {
	case f.secret && f.generate:
		return errors.New("--secret and --generate both give a new secret; choose one")
	case (f.secret || f.generate) && from.Kind == vault.KindTOTP:
		return errors.New("a TOTP entry's secret comes with its code settings: store it again with --action totp-store, or sesh --service totp --setup")
	case f.generate && to.Kind == vault.KindNote:
		return errors.New("a note isn't generated: give it with --secret")
	case f.generate && f.length < 1:
		return fmt.Errorf("--length wants 1 or more, got %d", f.length)
	}
	return nil
}

// askEdit asks, at a terminal, what to change about the entry at from, with
// its current values as defaults.
func askEdit(app *App, from vault.Key) (vault.Key, *editFlags, error) {
	f := &editFlags{length: 24}
	to := from
	ask := func(prompt, current string) (string, error) {
		answer, err := readLine(app.Stdin, app.Stderr, prompt)
		if err != nil {
			return "", err
		}
		if answer == "" {
			return current, nil
		}
		return answer, nil
	}
	var err error
	if to.Service, err = ask(fmt.Sprintf("Service name [%s]: ", from.Service), from.Service); err != nil {
		return from, nil, err
	}
	current := from.Username
	prompt := fmt.Sprintf("Username [%s] (- removes it): ", current)
	if current == "" {
		prompt = "Username (none; Enter keeps none): "
	}
	if to.Username, err = ask(prompt, current); err != nil {
		return from, nil, err
	}
	if to.Username == "-" {
		to.Username = ""
	}
	if from.Kind != vault.KindTOTP {
		kind, err := ask(fmt.Sprintf("Type [%s] (password, api_key, secure_note): ", from.Kind), string(from.Kind))
		if err != nil {
			return from, nil, err
		}
		to.Kind = vault.Kind(kind)
		if err := checkKindChange(from.Kind, to.Kind); err != nil {
			return from, nil, err
		}
	}
	if err := to.Validate(); err != nil {
		return from, nil, err
	}
	if from.Kind != vault.KindTOTP {
		if f.secret, err = promptYesNo(app.Stdin, app.Stderr, "Change the secret? [y/N]: "); err != nil {
			return from, nil, err
		}
	}
	return to, f, nil
}

// newSecret is the entry's new secret: generated, or typed (hidden at a
// terminal; a note, or anything without a terminal, read from stdin).
func newSecret(app *App, to vault.Key, f *editFlags, terminal bool) ([]byte, error) {
	if f.generate {
		opts := password.DefaultGenerateOptions()
		opts.Length = f.length
		opts.Symbols = !f.noSymbols
		secret, err := password.GeneratePassword(opts)
		if err != nil {
			return nil, err
		}
		if password.IsWeak(secret, to.Service, to.Username) {
			fmt.Fprintln(app.Stderr, "⚠️  A password this short is easy to guess; use --length 12 or more.") //nolint:errcheck // best-effort warning
		}
		return secret, nil
	}
	var secret []byte
	var err error
	switch {
	case to.Kind == vault.KindNote:
		if terminal {
			fmt.Fprintf(app.Stderr, "Enter the new note for %s (end with Ctrl+D):\n", to) //nolint:errcheck // prompt
		}
		secret, err = io.ReadAll(app.Stdin)
	case terminal:
		fmt.Fprintf(app.Stderr, "New %s for %s: ", to.Kind, to) //nolint:errcheck // prompt
		secret, err = readSecret()
		fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
	default:
		var line string
		line, err = readAnswer(app.Stdin)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		secret = []byte(line)
	}
	if err != nil {
		return nil, fmt.Errorf("read the new secret: %w", err)
	}
	if len(secret) == 0 {
		return nil, errors.New("the new secret is empty; nothing changed")
	}
	if to.Kind == vault.KindPassword && password.IsWeak(secret, to.Service, to.Username) {
		fmt.Fprintln(app.Stderr, "⚠️  This password is easy to guess: a cracking program would likely find it in under 100 million tries. It's stored; for a strong one, use --generate.") //nolint:errcheck // best-effort warning
	}
	return secret, nil
}
