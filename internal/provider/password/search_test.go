package password

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

// searchProvider returns a provider over the named entries (type/service
// [/username]), updated one day apart in order, set up to search query.
func searchProvider(t *testing.T, query string, names ...string) (*Provider, *strings.Builder) {
	t.Helper()
	store := vault.NewMemStore()
	for i, n := range names {
		k, err := vault.ParseKey(n)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(&vault.Entry{Key: k, UpdatedAt: time.Date(2026, 1, i+1, 9, 30, 0, 0, time.UTC)}, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := newTestProvider(store)
	var out strings.Builder
	p.stdout = &out
	p.action = "search"
	p.query = query
	stubStdoutIsTerminal(t, false)
	return p, &out
}

func stubStdoutIsTerminal(t *testing.T, v bool) {
	t.Helper()
	orig := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return v }
	t.Cleanup(func() { stdoutIsTerminal = orig })
}

// day is how the table shows the n-th test entry's update time.
func day(n int) string {
	return time.Date(2026, 1, n, 9, 30, 0, 0, time.UTC).Local().Format("2006-01-02 15:04")
}

func TestSearch_PrintsATableToStdout(t *testing.T) {
	p, out := searchProvider(t, "github", "password/github/alice", "totp/github/alice", "api_key/openai", "password/github-enterprise")
	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	want := `Found 3 entries matching "github":
  NAME               USER   KIND      UPDATED
  github             alice  totp      ` + day(2) + `
  github             alice  password  ` + day(1) + `
  github-enterprise         password  ` + day(4) + `
`
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
	if creds.DisplayInfo != "" {
		t.Errorf("DisplayInfo = %q, want nothing on stderr for several matches", creds.DisplayInfo)
	}
}

func TestSearch_JSONGoesToStdout(t *testing.T) {
	p, out := searchProvider(t, "github", "password/github/alice", "api_key/openai")
	p.format = "json"
	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	var got []password.Entry
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("stdout isn't JSON: %v\n%s", err, out.String())
	}
	if len(got) != 1 || got[0].Service != "github" || got[0].Username != "alice" {
		t.Errorf("JSON entries = %+v, want github/alice", got)
	}
	if creds.DisplayInfo != "" {
		t.Errorf("DisplayInfo = %q, want nothing on stderr", creds.DisplayInfo)
	}

	p, out = searchProvider(t, "nothing", "password/github/alice")
	p.format = "json"
	if _, err := p.GetCredentials(); err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if out.String() != "[]\n" {
		t.Errorf("stdout for no matches = %q, want an empty JSON list", out.String())
	}
}

func TestSearch_NoMatch(t *testing.T) {
	tests := map[string]struct {
		query, entryType string
		want             string
	}{
		"suggests a close name": {query: "gihtub", want: `No entries matching "gihtub". Did you mean: github?`},
		"nothing close":         {query: "zzzzzz", want: `No entries matching "zzzzzz"`},
		"names the kind":        {query: "openai", entryType: "totp", want: `No totp entries matching "openai"`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, out := searchProvider(t, tc.query, "password/github/alice", "api_key/openai")
			p.entryType = tc.entryType
			creds, err := p.GetCredentials()
			if err != nil {
				t.Fatalf("GetCredentials: %v", err)
			}
			if creds.DisplayInfo != tc.want {
				t.Errorf("DisplayInfo = %q, want %q", creds.DisplayInfo, tc.want)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", out.String())
			}
		})
	}
}

func TestSearch_EntryTypeNarrows(t *testing.T) {
	p, out := searchProvider(t, "github", "password/github/alice", "totp/github/alice", "password/gitlab")
	p.entryType = "totp"
	if _, err := p.GetCredentials(); err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "totp") || strings.Contains(got, "password") {
		t.Errorf("stdout =\n%s\nwant only the TOTP entry", got)
	}
}

func TestSearch_OneMatchSaysHowToUseIt(t *testing.T) {
	tests := map[string]struct {
		entry string
		want  string
	}{
		"password": {entry: "password/github/alice",
			want: "Copy it: sesh --service password --action get --service-name github --username alice --clip"},
		"api key without a username": {entry: "api_key/openai",
			want: "Copy it: sesh --service password --action get --service-name openai --entry-type api_key --clip"},
		"note": {entry: "secure_note/passport",
			want: "Copy it: sesh --service password --action get --service-name passport --entry-type secure_note --clip"},
		"totp": {entry: "totp/github/alice",
			want: "Copy a code: sesh --service password --action totp-generate --service-name github --username alice --clip"},
		"quotes what the shell would split": {entry: "password/my bank/o'brien",
			want: `Copy it: sesh --service password --action get --service-name 'my bank' --username 'o'\''brien' --clip`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, _ := searchProvider(t, strings.Split(tc.entry, "/")[1], tc.entry)
			creds, err := p.GetCredentials()
			if err != nil {
				t.Fatalf("GetCredentials: %v", err)
			}
			if creds.DisplayInfo != tc.want {
				t.Errorf("DisplayInfo =\n  %s\nwant\n  %s", creds.DisplayInfo, tc.want)
			}
		})
	}
}

func TestSearch_HighlightsOnlyAtATerminal(t *testing.T) {
	const bold = "\033[1m"
	tests := map[string]struct {
		noColor  string
		terminal bool
		want     bool
	}{
		"terminal":          {terminal: true, want: true},
		"pipe":              {terminal: false, want: false},
		"NO_COLOR set":      {terminal: true, noColor: "1", want: false},
		"NO_COLOR is empty": {terminal: true, noColor: "", want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, out := searchProvider(t, "hub", "password/github/alice", "password/github/bob")
			stubStdoutIsTerminal(t, tc.terminal)
			t.Setenv("NO_COLOR", tc.noColor)
			if _, err := p.GetCredentials(); err != nil {
				t.Fatalf("GetCredentials: %v", err)
			}
			if got := strings.Contains(out.String(), bold); got != tc.want {
				t.Errorf("highlighted = %v, want %v:\n%q", got, tc.want, out.String())
			}
		})
	}
}

func TestHighlightWords(t *testing.T) {
	const on, off = "\033[1m", "\033[0m"
	tests := map[string]struct {
		text  string
		want  string
		words []string
	}{
		"start":                   {text: "github", words: []string{"git"}, want: on + "git" + off + "hub"},
		"middle":                  {text: "my-github-account", words: []string{"github"}, want: "my-" + on + "github" + off + "-account"},
		"ignores case":            {text: "GitHub", words: []string{"github"}, want: on + "GitHub" + off},
		"two words":               {text: "aws-console", words: []string{"aws", "console"}, want: on + "aws" + off + "-" + on + "console" + off},
		"overlapping words merge": {text: "github", words: []string{"git", "thu"}, want: on + "githu" + off + "b"},
		"no match":                {text: "stripe", words: []string{"github"}, want: "stripe"},
		"matched without punctuation isn't marked": {text: "my-bank", words: []string{"mybank"}, want: "my-bank"},
		// Turkish "İ" lowercases to "i\u0307" (two bytes becomes three), so
		// byte offsets could land mid-rune; leave such text plain.
		"non-ASCII text":  {text: "İstanbul", words: []string{"stan"}, want: "İstanbul"},
		"non-ASCII query": {text: "strasse", words: []string{"ß"}, want: "strasse"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := highlightWords(tc.text, tc.words); got != tc.want {
				t.Errorf("highlightWords(%q, %q) = %q, want %q", tc.text, tc.words, got, tc.want)
			}
		})
	}
}
