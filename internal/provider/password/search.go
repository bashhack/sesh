package password

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/shell"
)

// searchPasswords prints the entries matching p.query, best first, to
// stdout: a table, or JSON with --format json. --entry-type keeps one
// kind. What isn't the results goes to stderr through DisplayInfo: a "no
// entries" line with any close names, or, for a single match, the command
// that uses it.
func (p *Provider) searchPasswords(mgr *password.Manager) (provider.Credentials, error) {
	entries, err := mgr.SearchIn(p.query, p.filter())
	if err != nil {
		return provider.Credentials{}, err
	}
	creds := provider.Credentials{Provider: p.Name()}

	if p.format == "json" {
		if entries == nil {
			entries = []password.Entry{}
		}
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		if _, err := fmt.Fprintf(p.stdout, "%s\n", b); err != nil {
			return provider.Credentials{}, err
		}
		return creds, nil
	}

	if len(entries) == 0 {
		kind := ""
		if p.entryType != "" {
			kind = p.entryType + " "
		}
		creds.DisplayInfo = fmt.Sprintf("No %sentries%s matching %q", kind, p.scope(), p.query)
		if hint := p.NoMatchHint(); hint != "" {
			creds.DisplayInfo += ": " + hint
		} else if names, err := mgr.SuggestionsIn(p.query, p.filter()); err == nil && len(names) > 0 {
			creds.DisplayInfo += ". Did you mean: " + strings.Join(names, ", ") + "?"
		}
		return creds, nil
	}

	if _, err := fmt.Fprint(p.stdout, p.searchTable(entries)); err != nil {
		return provider.Credentials{}, err
	}
	if len(entries) == 1 {
		creds.DisplayInfo = useCommand(&entries[0])
	}
	return creds, nil
}

// searchTable lays entries out in columns under a "Found" line, bolding
// the query's words in names and usernames when stdout is a terminal
// that allows color.
func (p *Provider) searchTable(entries []password.Entry) string {
	// FOLDER and TAGS only when an entry has one.
	var folders, tags bool
	for i := range entries {
		folders = folders || entries[i].Folder != ""
		tags = tags || len(entries[i].Tags) > 0
	}
	row := func(name, user, kind, folder, tagList, updated string) []string {
		r := []string{name, user, kind}
		if folders {
			r = append(r, folder)
		}
		if tags {
			r = append(r, tagList)
		}
		return append(r, updated)
	}
	rows := [][]string{row("NAME", "USER", "KIND", "FOLDER", "TAGS", "UPDATED")}
	for i := range entries {
		e := &entries[i]
		rows = append(rows, row(e.Service, e.Username, string(e.Type), e.Folder, strings.Join(e.Tags, " "), e.UpdatedAt.Local().Format("2006-01-02 15:04")))
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for c, cell := range r {
			widths[c] = max(widths[c], utf8.RuneCountInString(cell))
		}
	}

	bold := stdoutIsTerminal() && os.Getenv("NO_COLOR") == ""
	words := strings.Fields(strings.ToLower(p.query))
	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %s matching %q:\n", entryCount(len(entries)), p.query)
	for i, r := range rows {
		sb.WriteString(" ")
		for c, cell := range r {
			shown := cell
			if bold && i > 0 && c < 2 {
				shown = highlightWords(cell, words)
			}
			sb.WriteString(" " + shown)
			if c < len(r)-1 {
				sb.WriteString(strings.Repeat(" ", widths[c]-utf8.RuneCountInString(cell)+1))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// useCommand is the command that copies e, for a search with one match:
// its secret, or for a TOTP entry its current code.
func useCommand(e *password.Entry) string {
	action, label := "get", "Copy it: "
	if e.Type == password.EntryTypeTOTP {
		action, label = "totp-generate", "Copy a code: "
	}
	args := []string{"sesh", "--service", "password", "--action", action, "--service-name", shell.Quote(e.Service)}
	if e.Username != "" {
		args = append(args, "--username", shell.Quote(e.Username))
	}
	if e.Type != password.EntryTypePassword && e.Type != password.EntryTypeTOTP {
		args = append(args, "--entry-type", string(e.Type))
	}
	return label + strings.Join(append(args, "--clip"), " ")
}

// highlightWords bolds every place a word appears in text, ignoring case.
// Text or words that aren't plain ASCII are left as they are: lowercasing
// can change their byte lengths (Turkish "İ" becomes "i\u0307"), so the
// offsets found in the lowercased text wouldn't fit the original.
func highlightWords(text string, words []string) string {
	if !isASCII(text) {
		return text
	}
	lower := strings.ToLower(text)
	var spans [][2]int
	for _, w := range words {
		if w == "" || !isASCII(w) {
			continue
		}
		for from := 0; ; {
			i := strings.Index(lower[from:], w)
			if i < 0 {
				break
			}
			spans = append(spans, [2]int{from + i, from + i + len(w)})
			from += i + 1
		}
	}
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	var sb strings.Builder
	at := 0
	for i := 0; i < len(spans); {
		start, end := spans[i][0], spans[i][1]
		for i++; i < len(spans) && spans[i][0] <= end; i++ {
			end = max(end, spans[i][1])
		}
		sb.WriteString(text[at:start] + "\033[1m" + text[start:end] + "\033[0m")
		at = end
	}
	sb.WriteString(text[at:])
	return sb.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
