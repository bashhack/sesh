package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/vault"
)

// entryWordsHelp says how a command's <entry> is named.
const entryWordsHelp = `<entry> is a few words of its name or username, as sesh ui's search takes them
("github alice"; a kind word such as totp or note narrows), or its ID. When
several entries match, sesh asks which at a terminal; elsewhere, it lists them.`

// errNoChoice is the question of which entry going unanswered.
var errNoChoice = errors.New("no entry chosen")

// findEntries are the entries words name, best first: the one entry with
// that ID when the words make one, otherwise those sesh ui's search finds
// for them (a word may be a kind, such as "totp" or "note"), of kind only
// when it's given.
func findEntries(store vault.Store, words []string, kind vault.Kind) ([]password.Entry, error) {
	// An ID can have spaces in it (password/My Bank), typed as one word or
	// several.
	if id := strings.Join(words, " "); strings.Contains(id, "/") {
		if k, err := vault.ParseKey(id); err == nil {
			// Only whether it's there: a damaged entry can still be named,
			// to delete it.
			err := store.Exists(k)
			switch {
			case errors.Is(err, vault.ErrNotFound):
				if h := password.CaseHint(store, k); h != "" {
					return nil, fmt.Errorf("%w; %s", err, h)
				}
				return nil, err
			case err != nil:
				return nil, err
			case kind != "" && k.Kind != kind:
				return nil, fmt.Errorf("%s isn't a %s entry", k, kindName(kind))
			}
			return []password.Entry{{ID: k.String(), Service: k.Service, Username: k.Username, Type: k.Kind}}, nil
		}
	}
	return password.NewManager(store).SearchIn(strings.Join(words, " "), &password.ListFilter{EntryType: kind})
}

// keyOf is the key of a search result.
func keyOf(e *password.Entry) vault.Key {
	return vault.Key{Kind: e.Type, Service: e.Service, Username: e.Username}
}

// resolveEntry is the one entry words name, of kind when it's given: the
// only match, or, when several match, the one chosen at the terminal.
// Without a terminal, several matches are an error that lists them.
func resolveEntry(app *App, store vault.Store, words []string, kind vault.Kind) (vault.Key, error) {
	if len(words) == 0 {
		return vault.Key{}, errors.New("name the entry: a few words of its name or username, or its ID")
	}
	found, err := findEntries(store, words, kind)
	if err != nil {
		return vault.Key{}, err
	}
	query := strings.Join(words, " ")
	switch {
	case len(found) == 0:
		what := "entry"
		if kind != "" {
			what = kindName(kind) + " entry"
		}
		return vault.Key{}, fmt.Errorf("no %s matches %q; sesh search finds entries by any part of their name or username", what, query)
	case len(found) == 1:
		return keyOf(&found[0]), nil
	case app.StdinIsTerminal == nil || !app.StdinIsTerminal():
		var b strings.Builder
		fmt.Fprintf(&b, "%q matches %d entries; name one by its ID:", query, len(found))
		for i := range found {
			fmt.Fprintf(&b, "\n  %s", found[i].ID)
		}
		return vault.Key{}, errors.New(b.String())
	}
	if err := writeChoices(app.Stderr, query, found); err != nil {
		return vault.Key{}, err
	}
	for {
		if _, err := fmt.Fprintf(app.Stderr, "Which one? [1-%d, Enter to cancel]: ", len(found)); err != nil {
			return vault.Key{}, err
		}
		line, err := readAnswer(app.Stdin)
		line = strings.TrimSpace(line)
		if line == "" {
			if err != nil && !errors.Is(err, io.EOF) {
				return vault.Key{}, fmt.Errorf("read the answer: %w", err)
			}
			return vault.Key{}, errNoChoice
		}
		if n, perr := strconv.Atoi(line); perr == nil && n >= 1 && n <= len(found) {
			return keyOf(&found[n-1]), nil
		}
		if err != nil {
			return vault.Key{}, errNoChoice
		}
		if _, err := fmt.Fprintf(app.Stderr, "Type a number from 1 to %d.\n", len(found)); err != nil {
			return vault.Key{}, err
		}
	}
}

// writeChoices lists the entries a query matched, numbered, for the user
// to choose from.
func writeChoices(w io.Writer, query string, found []password.Entry) error {
	if _, err := fmt.Fprintf(w, "%q matches %d entries:\n", query, len(found)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i := range found {
		e := &found[i]
		if _, err := fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", i+1, password.EntryName(keyOf(e)), kindName(e.Type), e.Folder); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// resolveEach is the entries args name: one entry's ID, spaces and all;
// several IDs, one each, in order and without repeats; otherwise words
// naming one entry, as elsewhere. IDs that are also, joined, another
// entry's ID are refused, as either. The bool says the words were a
// search, so what was found should be said.
func resolveEach(app *App, store vault.Store, args []string) ([]vault.Key, bool, error) {
	if k, err := vault.ParseKey(strings.Join(args, " ")); err == nil && store.Exists(k) == nil {
		if len(args) > 1 && allEntryIDs(store, args) {
			return nil, false, fmt.Errorf("%s is one entry's ID, and %d others' too: for the one, quote it (%s); for the others, name them one at a time", quoteArgs(args), len(args), shell.Quote(k.String()))
		}
		return []vault.Key{k}, false, nil
	}
	for _, a := range args {
		if _, err := vault.ParseKey(a); err != nil {
			k, err := resolveEntry(app, store, args, "")
			if err != nil {
				return nil, false, err
			}
			return []vault.Key{k}, true, nil
		}
	}
	var keys []vault.Key
	seen := map[vault.Key]bool{}
	for _, a := range args {
		k, err := resolveEntry(app, store, []string{a}, "")
		if err != nil {
			return nil, false, err
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys, false, nil
}

// allEntryIDs says whether each of args is an entry's ID.
func allEntryIDs(store vault.Store, args []string) bool {
	for _, a := range args {
		k, err := vault.ParseKey(a)
		if err != nil || store.Exists(k) != nil {
			return false
		}
	}
	return true
}

// quoteArgs is args as typed, each quoted for the shell where it must be.
func quoteArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shell.Quote(a)
	}
	return strings.Join(q, " ")
}

// keyList is keys' IDs, as a list to read.
func keyList(keys []vault.Key) string {
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.String()
	}
	return strings.Join(ids, ", ")
}

// kindName is a kind as said to the user.
func kindName(k vault.Kind) string {
	switch k {
	case vault.KindAPIKey:
		return "API key"
	case vault.KindTOTP:
		return "TOTP"
	case vault.KindNote:
		return "note"
	}
	return "password"
}
