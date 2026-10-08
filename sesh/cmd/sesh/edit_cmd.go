package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// readSecret reads a typed secret without echoing it; tests replace it.
var readSecret = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }

// editFlags are sesh edit's flags.
type editFlags struct {
	service, username, kind string
	details                 provider.DetailsFlags
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
	f.details.Register(fs)
	return f
}

const editUsage = `Usage: sesh edit <id> [flags]
  Rename an entry, change its username or kind, give it a new secret, or
  change its URL, notes, or custom fields. With no flags, at a terminal, it
  asks for the name, kind and secret, with the current values as defaults.

  sesh edit password/github/alice --service github-work
  sesh edit password/github/alice --username alicia     ("" removes it)
  sesh edit password/github/alice --secret              (or --generate [--length N] [--no-symbols])
  sesh edit api_key/openai --type password              (password, api_key, secure_note)
  sesh edit password/github/alice --url https://github.com/login   ("" removes it)
  sesh edit password/github/alice --field recovery-email=alice@example.com
  sesh edit password/github/alice --secret-field pin    (asks, hidden)
  sesh edit password/github/alice --remove-field pin
  sesh edit password/github/alice --notes [--editor]    (stdin, or $EDITOR; empty removes them)

Entry IDs are what --list shows.`

// errEditCancelled is input ending at a question: nothing changes.
var errEditCancelled = errors.New("nothing changed")

// runEdit is `sesh edit <id>`: rename an entry, change its username or
// kind, or give it a new secret. Everything that needs no vault is checked
// before unlocking it, and a new name before a new secret is asked for.
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
	fs.Usage = func() { fmt.Fprintln(app.Stderr, editUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
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
	if (set["length"] || set["no-symbols"]) && !f.generate {
		return errors.New("--length and --no-symbols shape a generated password: add --generate")
	}

	terminal := app.StdinIsTerminal != nil && app.StdinIsTerminal()
	asked := len(set) == 0 || (len(set) == 1 && set["force"])
	if asked && !terminal {
		return errors.New("nothing to change: give --service, --username, --type, --secret, --generate, --url, --notes, --field, --secret-field, or --remove-field (or run it at a terminal to be asked)")
	}
	to, err := plannedKey(from, f, set)
	if err != nil {
		return err
	}
	if err := checkEditSecret(from, to, f); err != nil {
		return err
	}
	change, err := f.details.Change(from.Kind, to.Kind, terminal)
	if err != nil {
		return err
	}
	if !terminal {
		fromStdin := f.details.FromStdin()
		if f.secret && !f.generate {
			fromStdin++
		}
		if fromStdin > 1 {
			return errors.New("without a terminal, only one value can come from stdin: give the new secret, the notes, and each secret field in separate edits")
		}
	}
	if !asked && to == from && !f.secret && !f.generate && change == nil {
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
	// What the details change can't do to this entry is refused before
	// anything is typed.
	if change != nil {
		current, err := store.Lookup(from)
		if err != nil {
			return err
		}
		if err := provider.CheckAgainst(&current, change); err != nil {
			return err
		}
	}

	if asked {
		to, err = askNames(app, from)
		if errors.Is(err, errEditCancelled) {
			_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
			return err
		}
		if err != nil {
			return err
		}
	}
	// A new name another entry has is refused before a new secret is asked
	// for; the edit checks it again as it writes.
	if to != from {
		if err := store.Exists(to); err == nil {
			return fmt.Errorf("another entry has that name: %s; delete or rename that one first", to)
		}
	}
	if asked && from.Kind != vault.KindTOTP {
		answer, err := readLine(app.Stdin, app.Stderr, "Change the secret? [y/N]: ")
		if errors.Is(err, io.EOF) {
			_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
			return err
		}
		if err != nil {
			return err
		}
		f.secret = isYes(answer)
	}
	if asked && to == from && !f.secret {
		_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
		return err
	}
	// An AWS profile's MFA entry is totp/aws/<profile>; any other name
	// takes it out of the AWS provider.
	if from == vault.AWSKey(from.Username) && to != vault.AWSKey(to.Username) && !f.force {
		if !terminal {
			return errors.New("this is an AWS profile's MFA entry, and its new name takes it out of the AWS provider; add --force to do it anyway")
		}
		yes, err := promptYesNo(app.Stdin, app.Stderr, fmt.Sprintf("%s is an AWS profile's MFA entry; as %s, `sesh --service aws` won't find it. Rename it anyway? [y/N]: ", from, to))
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
	weak := false
	if f.secret || f.generate {
		secret, w, err := newSecret(app, to, f, terminal)
		if err != nil {
			return err
		}
		defer secure.SecureZeroBytes(secret)
		e.Secret, weak = secret, w
	}
	if change != nil {
		defer provider.ZeroChange(change)
		in := &provider.DetailsInput{
			Stdin: app.Stdin, Stderr: app.Stderr, ReadSecret: readSecret, Name: to.String(), Terminal: terminal,
			Notes: func() ([]byte, error) {
				d, err := store.Details(from, "notes")
				if err != nil {
					return nil, err
				}
				notes := d.Notes
				d.Notes = nil
				d.Zero()
				return notes, nil
			},
		}
		if err := f.details.Read(change, in); err != nil {
			if errors.Is(err, provider.ErrNothingTyped) {
				_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
				return err
			}
			return err
		}
		e.Details = change
	}
	detail, err := store.Edit(from, e)
	if err != nil {
		if errors.Is(err, database.ErrNothingToChange) {
			if f.details.Editor() {
				_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
				return err
			}
			if f.details.OnlyURL() {
				return errors.New("nothing to change: the entry already has that URL")
			}
			return errors.New("nothing to change: the entry already has those details")
		}
		if errors.Is(err, database.ErrNameTaken) || errors.Is(err, database.ErrEntryChanged) || errors.Is(err, database.ErrVaultKeyChanged) || errors.Is(err, vault.ErrNotFound) {
			return err
		}
		// Anything else, such as the agent locking meanwhile, wrote nothing.
		return fmt.Errorf("nothing was changed: %w", err)
	}
	if _, err := fmt.Fprintf(app.Stdout, "✅ %s: %s\n", to, detail); err != nil {
		return err
	}
	if weak {
		if f.generate {
			fmt.Fprintln(app.Stderr, "⚠️  A password this short is easy to guess; use --length 12 or more.") //nolint:errcheck // best-effort warning
		} else {
			fmt.Fprintln(app.Stderr, "⚠️  This password is easy to guess: a cracking program would likely find it in under 100 million tries. It's stored; for a strong one, use --generate.") //nolint:errcheck // best-effort warning
		}
	}
	return nil
}

// isYes reports whether answer is y or yes, in any case.
func isYes(answer string) bool {
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
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
		return fmt.Errorf("unknown type %q: use password, api_key, or secure_note", to)
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

// askNames asks, at a terminal, for the entry's new service name, username,
// and kind, with the current ones as defaults, asking again after an answer
// that can't be. The end of input is errEditCancelled.
func askNames(app *App, from vault.Key) (vault.Key, error) {
	ask := func(prompt, current string, check func(string) error) (string, error) {
		for {
			answer, err := readLine(app.Stdin, app.Stderr, prompt)
			if errors.Is(err, io.EOF) {
				return "", errEditCancelled
			}
			if err != nil {
				return "", err
			}
			if answer == "" {
				answer = current
			}
			if err := check(answer); err != nil {
				fmt.Fprintf(app.Stderr, "❌ %v\n", err) //nolint:errcheck // asked again
				continue
			}
			return answer, nil
		}
	}
	to := from
	var err error
	if to.Service, err = ask(fmt.Sprintf("Service name [%s]: ", from.Service), from.Service, func(v string) error {
		if v == "" {
			return errors.New("the service name is empty")
		}
		return vault.CheckName("service name", v)
	}); err != nil {
		return from, err
	}
	prompt := fmt.Sprintf("Username [%s] (- removes it): ", from.Username)
	if from.Username == "" {
		prompt = "Username (none; Enter keeps none): "
	}
	if to.Username, err = ask(prompt, from.Username, func(v string) error {
		if v == "-" {
			return nil
		}
		return vault.CheckName("username", v)
	}); err != nil {
		return from, err
	}
	if to.Username == "-" {
		to.Username = ""
	}
	if from.Kind != vault.KindTOTP {
		kind, err := ask(fmt.Sprintf("Type [%s] (password, api_key, secure_note): ", from.Kind), string(from.Kind), func(v string) error {
			return checkKindChange(from.Kind, vault.Kind(v))
		})
		if err != nil {
			return from, err
		}
		to.Kind = vault.Kind(kind)
	}
	return to, nil
}

// newSecret is the entry's new secret, and whether it's easy to guess:
// generated, or typed (hidden at a terminal; a note, or anything without a
// terminal, read from stdin, up to the size an entry can hold).
func newSecret(app *App, to vault.Key, f *editFlags, terminal bool) ([]byte, bool, error) {
	if f.generate {
		opts := password.DefaultGenerateOptions()
		opts.Length = f.length
		opts.Symbols = !f.noSymbols
		secret, err := password.GeneratePassword(opts)
		if err != nil {
			return nil, false, err
		}
		return secret, password.IsWeak(secret, to.Service, to.Username), nil
	}
	var secret []byte
	var err error
	switch {
	case terminal && to.Kind != vault.KindNote:
		fmt.Fprintf(app.Stderr, "New %s for %s: ", to.Kind, to) //nolint:errcheck // prompt
		secret, err = readSecret()
		fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
	default:
		if terminal {
			fmt.Fprintf(app.Stderr, "Enter the new note for %s (end with Ctrl+D):\n", to) //nolint:errcheck // prompt
		}
		secret, err = io.ReadAll(io.LimitReader(app.Stdin, database.MaxSecretSize+1))
		if err == nil && len(secret) > database.MaxSecretSize {
			secure.SecureZeroBytes(secret)
			return nil, false, fmt.Errorf("the new secret is over %d bytes, the most an entry holds; nothing changed", database.MaxSecretSize)
		}
		if err == nil && to.Kind != vault.KindNote {
			// A password or API key is one line: the newline that ends it,
			// \n or \r\n, isn't part of it.
			secret = bytes.TrimSuffix(bytes.TrimSuffix(secret, []byte("\n")), []byte("\r"))
			if bytes.ContainsAny(secret, "\r\n") {
				secure.SecureZeroBytes(secret)
				return nil, false, fmt.Errorf("a %s is one line, and this has several; keep multi-line text as a note (--type secure_note). Nothing changed", to.Kind)
			}
		}
	}
	if err != nil {
		return nil, false, fmt.Errorf("read the new secret: %w", err)
	}
	if len(secret) == 0 {
		return nil, false, errors.New("the new secret is empty; nothing changed")
	}
	return secret, to.Kind == vault.KindPassword && password.IsWeak(secret, to.Service, to.Username), nil
}
