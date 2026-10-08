package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

const showUsage = `Usage: sesh show <id> [--reveal] [--format json]
  Show an entry: its URL, folder, tags, notes and custom fields. Its secret,
  notes and secret fields stay hidden, and aren't read, unless --reveal.

  sesh show password/github/alice
  sesh show password/github/alice --reveal

Entry IDs are what --list shows.`

// addShowFlags defines sesh show's flags on fs.
func addShowFlags(fs *flag.FlagSet) (reveal *bool, format *string) {
	return fs.Bool("reveal", false, "Show the secret, notes and secret fields"),
		fs.String("format", "text", "Output format: text or json")
}

// hidden stands in for a value show doesn't reveal.
const hidden = "••••••••"

// secretLabel names an entry's secret by its kind.
func secretLabel(k vault.Kind) string {
	switch k {
	case vault.KindAPIKey:
		return "API key"
	case vault.KindTOTP:
		return "TOTP secret"
	case vault.KindNote:
		return "Note"
	}
	return "Password"
}

// runShow is `sesh show <id>`: everything about one entry. Without
// --reveal it reads only what's stored readable; with it, the secret and
// details are decrypted too, which the audit log records as access.
func runShow(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, showUsage)
		return err
	}
	id, rest := args[0], args[1:]
	if strings.HasPrefix(id, "-") {
		return errors.New("name the entry first: sesh show <id> [--reveal] [--format json]")
	}
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	reveal, format := addShowFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, showUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh show shows one entry; got %q after its flags", strings.Join(fs.Args(), " "))
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("--format is text or json, not %q", *format)
	}
	k, err := vault.ParseKey(id)
	if err != nil {
		return err
	}

	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	e, err := store.Lookup(k)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			if h := password.CaseHint(store, k); h != "" {
				err = fmt.Errorf("%w; %s", err, h)
			}
		}
		return err
	}
	shown := shownEntry{e: &e, d: vault.Details{URL: e.URL, Fields: e.Fields}}
	if *reveal {
		if shown.secret, err = store.Get(k); err != nil {
			return err
		}
		defer secure.SecureZeroBytes(shown.secret)
		if shown.d, err = store.Details(k); err != nil {
			return err
		}
		defer shown.d.Zero()
	}
	if *format == "json" {
		return shown.writeJSON(app, *reveal)
	}
	_, err = fmt.Fprint(app.Stdout, shown.text(*reveal))
	return err
}

// shownEntry is what show prints: the entry, its details (secret values
// and notes only when revealed), and its secret, when revealed.
type shownEntry struct {
	e      *vault.Entry
	secret []byte
	d      vault.Details
}

// text lays the entry out as rows of a label and a value, the custom
// fields under their own heading.
func (s *shownEntry) text(reveal bool) string {
	type row struct{ label, value string }
	var rows []row
	if s.e.URL != "" {
		rows = append(rows, row{"URL", s.e.URL})
	}
	if s.e.Folder != "" {
		rows = append(rows, row{"Folder", s.e.Folder})
	}
	if len(s.e.Tags) > 0 {
		rows = append(rows, row{"Tags", strings.Join(s.e.Tags, ", ")})
	}
	if reveal {
		rows = append(rows, row{secretLabel(s.e.Kind), string(s.secret)})
		if len(s.d.Notes) > 0 {
			rows = append(rows, row{"Notes", string(s.d.Notes)})
		}
	} else {
		rows = append(rows, row{secretLabel(s.e.Kind), hidden + "   (--reveal)"})
		if s.e.HasNotes {
			rows = append(rows, row{"Notes", hidden + "   (--reveal)"})
		}
	}
	width := 0
	for _, r := range rows {
		width = max(width, len(r.label))
	}
	var b strings.Builder
	b.WriteString(s.e.Key.String() + "\n")
	for _, r := range rows {
		writeRow(&b, "  ", r.label, width+2, r.value)
	}
	if len(s.d.Fields) == 0 {
		return b.String()
	}
	b.WriteString("  Fields\n")
	names := make([]string, len(s.d.Fields))
	width = 0
	for i, f := range s.d.Fields {
		names[i] = f.Name
		if f.Secret {
			names[i] += " (secret)"
		}
		width = max(width, len(names[i]))
	}
	for i, f := range s.d.Fields {
		value := string(f.Value)
		if f.Secret && !reveal {
			value = hidden
		}
		writeRow(&b, "    ", names[i], width+3, value)
	}
	return b.String()
}

// writeRow writes label, padded to width, and value after indent; a
// value's further lines line up under its first, and the newline ending
// its last one adds no empty line.
func writeRow(b *strings.Builder, indent, label string, width int, value string) {
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	fmt.Fprintf(b, "%s%-*s%s\n", indent, width, label, lines[0])
	for _, l := range lines[1:] {
		fmt.Fprintf(b, "%s%*s%s\n", indent, width, "", l)
	}
}

// writeJSON prints the entry as JSON; the secret, notes and secret values
// only when revealed.
func (s *shownEntry) writeJSON(app *App, reveal bool) error {
	type field struct {
		Name   string `json:"name"`
		Value  string `json:"value,omitempty"`
		Secret bool   `json:"secret,omitempty"`
	}
	out := struct {
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Secret    *string   `json:"secret,omitempty"`
		Notes     *string   `json:"notes,omitempty"`
		ID        string    `json:"id"`
		Kind      string    `json:"kind"`
		Service   string    `json:"service"`
		Username  string    `json:"username,omitempty"`
		URL       string    `json:"url,omitempty"`
		Folder    string    `json:"folder,omitempty"`
		Tags      []string  `json:"tags,omitempty"`
		Fields    []field   `json:"fields,omitempty"`
		HasNotes  bool      `json:"has_notes,omitempty"`
	}{
		ID: s.e.Key.String(), Kind: string(s.e.Kind), Service: s.e.Service, Username: s.e.Username,
		URL: s.e.URL, Folder: s.e.Folder, Tags: s.e.Tags, HasNotes: s.e.HasNotes,
		CreatedAt: s.e.CreatedAt, UpdatedAt: s.e.UpdatedAt,
	}
	if reveal {
		secret := string(s.secret)
		out.Secret = &secret
		if len(s.d.Notes) > 0 {
			notes := string(s.d.Notes)
			out.Notes = &notes
		}
	}
	for _, f := range s.d.Fields {
		jf := field{Name: f.Name, Secret: f.Secret}
		if !f.Secret || reveal {
			jf.Value = string(f.Value)
		}
		out.Fields = append(out.Fields, jf)
	}
	b, err := json.MarshalIndent(out, "", "  ") //nolint:gosec // --reveal prints the secrets by request
	if err != nil {
		return fmt.Errorf("marshal JSON output: %w", err)
	}
	_, err = fmt.Fprintln(app.Stdout, string(b))
	return err
}
