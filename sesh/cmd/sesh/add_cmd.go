package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

const addUsage = `Usage: sesh add password|key|note|totp [<name>] [flags]
  Add an entry. A password or API key is typed hidden, or read from a pipe;
  a note is read until Ctrl-D, or from a pipe. A TOTP entry takes its key
  typed (or an otpauth:// link pasted), or read from a QR code on screen with
  --qr. With no name at a terminal, sesh asks for one.

  sesh add password github --username alice
  sesh add password github --generate             (copies it as it's saved)
  sesh add key openai
  echo "door code 4711" | sesh add note house
  sesh add totp github --qr
  sesh add password bank --folder money --tag important --url https://bank.example

Flags:
  --username U          Its username
  --generate            A password: generate one ([--length N] [--no-symbols])
  --qr                  A TOTP entry: read its key from a QR code on screen
  --folder F, --tag T   File it (--tag repeats)
  --url U, --notes [--editor], --field n=v, --secret-field n
                        Its URL, notes (stdin, or $EDITOR), and fields
  --force               Replace an entry of that name without asking`

// addKinds are the words sesh add takes for a kind.
var addKinds = map[string]vault.Kind{
	"password": vault.KindPassword,
	"key":      vault.KindAPIKey, "api_key": vault.KindAPIKey, "api-key": vault.KindAPIKey, "apikey": vault.KindAPIKey,
	"note": vault.KindNote, "secure_note": vault.KindNote,
	"totp": vault.KindTOTP,
}

// addFlags are sesh add's flags.
type addFlags struct {
	username string
	filing   provider.FilingFlags
	details  provider.DetailsFlags
	length   int
	generate bool
	noSymbol bool
	qr       bool
	force    bool
}

// addAddFlags defines sesh add's flags on fs.
func addAddFlags(fs *flag.FlagSet) *addFlags {
	f := &addFlags{}
	fs.StringVar(&f.username, "username", "", "Its username")
	fs.BoolVar(&f.generate, "generate", false, "Generate the password")
	fs.IntVar(&f.length, "length", 24, "Generated password length")
	fs.BoolVar(&f.noSymbol, "no-symbols", false, "Generate without symbols")
	fs.BoolVar(&f.qr, "qr", false, "Read a TOTP key from a QR code on screen")
	fs.BoolVar(&f.force, "force", false, "Replace an entry of that name without asking")
	f.filing.Register(fs)
	f.details.Register(fs)
	return f
}

// runAdd is sesh add: a new entry of any kind.
func runAdd(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, addUsage)
		return err
	}
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	f := addAddFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, addUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(words) == 0 {
		return errors.New("say what to add: sesh add password|key|note|totp <name>")
	}
	kind, ok := addKinds[strings.ToLower(words[0])]
	if !ok {
		return fmt.Errorf("sesh add takes a kind first (password, key, note, or totp), not %q", words[0])
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	switch {
	case (set["length"] || set["no-symbols"]) && !f.generate:
		return errors.New("--length and --no-symbols shape a generated password: add --generate")
	case f.generate && kind != vault.KindPassword:
		return fmt.Errorf("--generate makes a password; %s comes from wherever it was issued", map[vault.Kind]string{vault.KindAPIKey: "an API key", vault.KindNote: "a note", vault.KindTOTP: "a TOTP key"}[kind])
	case f.qr && kind != vault.KindTOTP:
		return errors.New("--qr reads a TOTP entry's key: sesh add totp <name> --qr")
	}
	terminal := app.StdinIsTerminal != nil && app.StdinIsTerminal()
	name := strings.Join(words[1:], " ")
	// A TOTP entry's name can come from its QR code or otpauth:// link.
	if name == "" && kind != vault.KindTOTP {
		if !terminal {
			return fmt.Errorf("name the entry: sesh add %s <name>", words[0])
		}
		if name, err = askName(app); err != nil {
			return err
		}
	}
	if name != "" {
		if err := (vault.Key{Kind: kind, Service: name, Username: f.username}).Validate(); err != nil {
			return err
		}
	}
	change, err := f.details.Change(kind, kind, terminal)
	if err != nil {
		return err
	}
	if !terminal && change != nil {
		fromStdin := f.details.FromStdin()
		if !f.generate && !f.qr {
			fromStdin++
		}
		if fromStdin > 1 {
			return errors.New("without a terminal, only one value can come from stdin: add the entry, then the rest with sesh edit")
		}
	}

	opts := password.DefaultGenerateOptions()
	opts.Length = f.length
	opts.Symbols = !f.noSymbol
	if f.generate {
		if err := opts.Check(); err != nil {
			return fmt.Errorf("--length: %w", err)
		}
	}

	cfg, err := settings()
	if err != nil {
		return err
	}
	// The first entry makes the vault, as a first run does.
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	if kind == vault.KindTOTP {
		return addTOTP(app, store, name, f, change, terminal)
	}
	k := vault.Key{Kind: kind, Service: name, Username: f.username}
	if err := checkAddChange(store, k, change); err != nil {
		return err
	}
	if err := confirmReplace(app, store, k, f.force, terminal); err != nil {
		return err
	}
	replacing := store.Exists(k) == nil
	var secret []byte
	if f.generate {
		if secret, err = password.GeneratePassword(opts); err != nil {
			return err
		}
	} else if secret, err = readEntrySecret(app, k, terminal); err != nil {
		return err
	}
	defer secure.SecureZeroBytes(secret)
	mgr := password.NewManager(store)
	if err := readDetails(app, mgr, k, &f.details, change, terminal); err != nil {
		return err
	}
	if change != nil {
		defer provider.ZeroChange(change)
	}
	if err := mgr.StorePasswordWithDetails(k.Service, k.Username, secret, kind, f.filing.Filing(), change); err != nil {
		return err
	}
	said := "✅ Added " + password.EntryName(k)
	if replacing {
		said = "✅ Replaced " + password.EntryName(k)
	}
	if f.generate {
		switch err := app.ClipboardCopy(string(secret)); {
		case err != nil:
			said += "; its password couldn't be copied (" + err.Error() + "): sesh get " + quoteName(k) + " prints it"
		case app.settings.ClipboardTimeout > 0:
			said += ", and copied its password; the clipboard clears in " + app.settings.ClipboardTimeout.String()
		default:
			said += ", and copied its password"
		}
	}
	if _, err := fmt.Fprintln(app.Stderr, said); err != nil {
		return err
	}
	if kind == vault.KindPassword && password.IsWeak(secret, k.Service, k.Username) {
		fix := "sesh edit " + quoteName(k) + " --generate"
		if f.generate {
			fix = "use --length 12 or more"
		}
		_, err := fmt.Fprintf(app.Stderr, "⚠️  This password is easy to guess: a cracking program would likely find it in under 100 million tries. For a strong one: %s\n", fix)
		return err
	}
	return nil
}

// quoteName is k as a command names it, quoted for the shell.
func quoteName(k vault.Key) string {
	return shell.Quote(k.String())
}

// askName asks for the new entry's name at the terminal.
func askName(app *App) (string, error) {
	name, err := readLine(app.Stdin, app.Stderr, "Name: ")
	name = strings.TrimSpace(name)
	if name == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return "", errors.New("no name given; nothing added")
	}
	return name, nil
}

// checkAddChange refuses, before anything is typed, details the entry
// being replaced (or a new one) can't take.
func checkAddChange(store *database.Store, k vault.Key, change *vault.DetailsChange) error {
	if change == nil {
		return nil
	}
	current, err := store.Lookup(k)
	if err != nil && !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	return provider.CheckAgainst(&current, change)
}

// confirmReplace asks before k is added over an entry of that name, or
// beside one whose name differs only in case; without a terminal, it
// refuses unless force.
func confirmReplace(app *App, store *database.Store, k vault.Key, force, terminal bool) error {
	if force {
		return nil
	}
	mgr := password.NewManager(store)
	name := password.EntryName(k)
	var refusal, question string
	exists, err := mgr.EntryExists(k.Service, k.Username, k.Kind)
	if err != nil {
		return err
	}
	if exists {
		refusal = fmt.Sprintf("%s already exists; add --force to replace it, or change it with sesh edit", name)
		question = fmt.Sprintf("%s already exists. Replace it? [y/N]: ", name)
	} else {
		twins, err := mgr.CaseTwins(k)
		if err != nil {
			return err
		}
		if len(twins) == 0 {
			return nil
		}
		twin := password.EntryName(twins[0])
		refusal = fmt.Sprintf("%s already exists, and names are case-sensitive; use that name, or add --force to add %s too", twin, name)
		question = fmt.Sprintf("%s already exists, and names are case-sensitive. Add %s as well? [y/N]: ", twin, name)
	}
	if !terminal {
		return errors.New(refusal)
	}
	yes, err := promptYesNo(app.Stdin, app.Stderr, question)
	if err != nil {
		return err
	}
	if !yes {
		return errors.New("nothing added")
	}
	return nil
}

// readEntrySecret reads the new entry k's secret: a note until the end of
// the input, a password or API key typed hidden at a terminal, or its one
// line from a pipe.
func readEntrySecret(app *App, k vault.Key, terminal bool) ([]byte, error) {
	var secret []byte
	var err error
	switch {
	case terminal && k.Kind != vault.KindNote:
		fmt.Fprintf(app.Stderr, "%s for %s: ", secretLabel(k.Kind), password.EntryName(k)) //nolint:errcheck // prompt
		secret, err = readSecret()
		fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
	default:
		if terminal {
			fmt.Fprintf(app.Stderr, "Type the note for %s (end with Ctrl-D):\n", password.EntryName(k)) //nolint:errcheck // prompt
		}
		secret, err = io.ReadAll(io.LimitReader(app.Stdin, database.MaxSecretSize+1))
		if err == nil && len(secret) > database.MaxSecretSize {
			secure.SecureZeroBytes(secret)
			return nil, fmt.Errorf("that's over %d bytes, the most an entry holds; nothing added", database.MaxSecretSize)
		}
		if err == nil && k.Kind != vault.KindNote {
			// A password or API key is one line: the newline that ends
			// it, \n or \r\n, isn't part of it.
			secret = bytes.TrimSuffix(bytes.TrimSuffix(secret, []byte("\n")), []byte("\r"))
			if bytes.ContainsAny(secret, "\r\n") {
				secure.SecureZeroBytes(secret)
				return nil, fmt.Errorf("a %s is one line, and this has several; keep multi-line text as a note. Nothing added", kindName(k.Kind))
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read the %s: %w", strings.ToLower(secretLabel(k.Kind)), err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("the %s is empty; nothing added", strings.ToLower(secretLabel(k.Kind)))
	}
	return secret, nil
}

// readDetails reads what change takes from the user: notes and secret
// fields, after the secret.
func readDetails(app *App, mgr *password.Manager, k vault.Key, flags *provider.DetailsFlags, change *vault.DetailsChange, terminal bool) error {
	if change == nil {
		return nil
	}
	in := &provider.DetailsInput{
		Stdin: app.Stdin, Stderr: app.Stderr, ReadSecret: readSecret, Name: k.String(), Terminal: terminal, KeepNotes: true,
		Notes: func() ([]byte, error) { return mgr.Notes(k) },
	}
	err := flags.Read(change, in)
	if errors.Is(err, provider.ErrNothingTyped) {
		// Notes ended at once at a terminal leave the notes as they are.
		change.SetNotes = false
		return nil
	}
	return err
}

// scanQR reads a TOTP key from a QR code on screen; tests replace it.
var scanQR = qrcode.ScanQRCodeFull

// addTOTP adds a TOTP entry, its key typed, pasted as an otpauth:// link,
// or read from a QR code on screen. A link or code names the account,
// which is its username unless --username says otherwise, and the issuer,
// which names the entry when no name is given.
func addTOTP(app *App, store *database.Store, name string, f *addFlags, change *vault.DetailsChange, terminal bool) error {
	username := f.username
	var key []byte
	var params totp.Params
	if f.qr {
		info, err := scanQR()
		if err != nil {
			return fmt.Errorf("read the QR code: %w", err)
		}
		normalized, err := totp.ValidateAndNormalizeSecret(info.Secret)
		if err != nil {
			return fmt.Errorf("the QR code's key can't be used: %w", err)
		}
		key = []byte(normalized)
		params = totp.Params{Issuer: info.Issuer, Algorithm: info.Algorithm, Digits: info.Digits, Period: info.Period}
		if username == "" {
			username = info.Account
		}
		if name == "" {
			name = info.Issuer
		}
		if name == "" {
			return errors.New("the QR code doesn't name its service: give a name, sesh add totp <name> --qr")
		}
	} else {
		var typed []byte
		var err error
		if terminal {
			prompt := "TOTP key (or otpauth:// link): "
			if name != "" {
				prompt = "TOTP key (or otpauth:// link) for " + password.EntryName(vault.Key{Kind: vault.KindTOTP, Service: name, Username: username}) + ": "
			}
			fmt.Fprint(app.Stderr, prompt) //nolint:errcheck // prompt
			typed, err = readSecret()
			fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
		} else {
			var line string
			line, err = readAnswer(app.Stdin)
			if errors.Is(err, io.EOF) {
				err = nil
			}
			typed = []byte(line)
		}
		if err != nil {
			return fmt.Errorf("read the TOTP key: %w", err)
		}
		defer secure.SecureZeroBytes(typed)
		read, p, err := readTOTPKey(typed)
		if err != nil {
			return err
		}
		key = read
		if p != nil {
			params = *p
		}
		// A link names its service and account, as a QR code does.
		if text := strings.TrimSpace(string(typed)); strings.HasPrefix(strings.ToLower(text), "otpauth://") {
			if info, err := qrcode.ExtractTOTPFullInfo(text); err == nil {
				if username == "" {
					username = info.Account
				}
				if name == "" {
					name = info.Issuer
				}
			}
		}
		if name == "" {
			if !terminal {
				return errors.New("name the entry: sesh add totp <name>")
			}
			if name, err = askName(app); err != nil {
				return err
			}
		}
	}
	defer secure.SecureZeroBytes(key)
	k := vault.Key{Kind: vault.KindTOTP, Service: name, Username: username}
	if err := k.Validate(); err != nil {
		return fmt.Errorf("can't name the entry %q: %w", password.EntryName(k), err)
	}
	if err := checkAddChange(store, k, change); err != nil {
		return err
	}
	if err := confirmReplace(app, store, k, f.force, terminal); err != nil {
		return err
	}
	replacing := store.Exists(k) == nil
	mgr := password.NewManager(store)
	if err := readDetails(app, mgr, k, &f.details, change, terminal); err != nil {
		return err
	}
	if change != nil {
		defer provider.ZeroChange(change)
	}
	if err := saveTOTP(store, k, key, params, f.filing.Filing(), change); err != nil {
		return err
	}
	said := "✅ Added " + password.EntryName(k)
	if replacing {
		said = "✅ Replaced " + password.EntryName(k)
	}
	if !params.IsDefault() {
		algorithm, digits, period := cmpOr(params.Algorithm, "SHA1"), params.Digits, params.Period
		if digits == 0 {
			digits = 6
		}
		if period == 0 {
			period = 30
		}
		said += fmt.Sprintf(" (codes: %s, %d digits, every %ds)", algorithm, digits, period)
	}
	_, err := fmt.Fprintln(app.Stderr, said+"; sesh code "+quoteName(k)+" prints its code")
	return err
}

// saveTOTP stores TOTP entry k with its key and code settings: a new one
// with its details in one write, or one being replaced with them changed
// after.
func saveTOTP(store *database.Store, k vault.Key, key []byte, params totp.Params, filing vault.Filing, change *vault.DetailsChange) error {
	switch err := store.Exists(k); {
	case err == nil:
		mgr := password.NewManager(store)
		if err := mgr.StoreTOTPSecretWithParams(k.Service, k.Username, string(key), params, filing); err != nil {
			return err
		}
		if change == nil {
			return nil
		}
		_, err := store.Edit(k, database.EntryEdit{Details: change})
		if errors.Is(err, database.ErrNothingToChange) {
			return nil
		}
		return err
	case !errors.Is(err, vault.ErrNotFound):
		return err
	}
	ent := vault.Entry{Key: k}
	ent.Settings.TOTP = params
	filing.Apply(&ent)
	var d vault.Details
	if change != nil {
		if change.URL != nil {
			d.URL = *change.URL
		}
		d.Notes, d.Fields = change.Notes, change.Set
	}
	return store.SaveWithDetails(&ent, key, &d)
}
