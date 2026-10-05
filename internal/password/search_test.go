package password

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
)

// searchVault is a manager over a realistic set of entries, updated one day
// apart in the order listed (the last is the most recent).
func searchVault(t *testing.T) *Manager {
	t.Helper()
	const user = "testuser"
	names := []string{
		"password/github/alice",
		"totp/github/alice",
		"password/gitlab/alice-work",
		"password/github-enterprise/alice",
		"api_key/github/ci-bot",
		"api_key/openai",
		"api_key/stripe-live",
		"password/aws-console/admin",
		"totp/aws-console/admin",
		"password/my-bank/marc",
		"password/snowbank",
		"secure_note/passport",
		"secure_note/wifi-home",
		"password/netflix/family",
	}
	entries := make([]keychain.KeychainEntry, len(names))
	for i, n := range names {
		entries[i] = keychain.KeychainEntry{
			Service:     "sesh-password/" + n,
			Account:     user,
			Description: strings.SplitN(n, "/", 2)[0] + " for " + n,
			UpdatedAt:   time.Date(2026, 1, i+1, 0, 0, 0, 0, time.UTC),
		}
	}
	return NewManager(&mocks.MockProvider{
		ListEntriesFunc: func(string) ([]keychain.KeychainEntry, error) { return entries, nil },
	}, user)
}

// label names an entry as the tests list it: type/service[/username].
func label(e *Entry) string {
	s := string(e.Type) + "/" + e.Service
	if e.Username != "" {
		s += "/" + e.Username
	}
	return s
}

func TestSearchEntries(t *testing.T) {
	m := searchVault(t)
	tests := map[string]struct {
		query string
		want  []string // best match first
	}{
		// Matching anywhere in the name; ties go to the most recently updated.
		"exact name, then names starting with it": {query: "github", want: []string{
			"api_key/github/ci-bot", "totp/github/alice", "password/github/alice", "password/github-enterprise/alice"}},
		"anywhere in a word": {query: "hub", want: []string{
			"api_key/github/ci-bot", "password/github-enterprise/alice", "totp/github/alice", "password/github/alice"}},
		"start of a word before inside one": {query: "bank", want: []string{"password/my-bank/marc", "password/snowbank"}},
		"ignores case":                      {query: "GitLab", want: []string{"password/gitlab/alice-work"}},
		"trims spaces":                      {query: "  openai ", want: []string{"api_key/openai"}},

		// Punctuation in names doesn't have to be typed.
		"without the dash":   {query: "mybank", want: []string{"password/my-bank/marc"}},
		"without the dash 2": {query: "awsconsole", want: []string{"totp/aws-console/admin", "password/aws-console/admin"}},

		// Usernames, after names.
		"username": {query: "alice", want: []string{
			"password/github-enterprise/alice", "totp/github/alice", "password/github/alice", "password/gitlab/alice-work"}},
		"part of a username": {query: "work", want: []string{"password/gitlab/alice-work"}},

		// Every word has to match: the name, the username, or the kind.
		"name and username": {query: "github alice", want: []string{
			"totp/github/alice", "password/github/alice", "password/github-enterprise/alice"}},
		"name and kind":      {query: "github totp", want: []string{"totp/github/alice"}},
		"kind and name":      {query: "key github", want: []string{"api_key/github/ci-bot"}},
		"one word unmatched": {query: "github nothing", want: nil},

		// Kind words.
		"totp":    {query: "totp", want: []string{"totp/aws-console/admin", "totp/github/alice"}},
		"2fa":     {query: "2fa", want: []string{"totp/aws-console/admin", "totp/github/alice"}},
		"api key": {query: "key", want: []string{"api_key/stripe-live", "api_key/openai", "api_key/github/ci-bot"}},
		"token":   {query: "tokens", want: []string{"api_key/stripe-live", "api_key/openai", "api_key/github/ci-bot"}},
		"note":    {query: "notes", want: []string{"secure_note/wifi-home", "secure_note/passport"}},
		"passwords": {query: "password", want: []string{
			"password/netflix/family", "password/snowbank", "password/my-bank/marc", "password/aws-console/admin",
			"password/github-enterprise/alice", "password/gitlab/alice-work", "password/github/alice"}},
		"part of a kind word is only a name search": {query: "pass", want: []string{"secure_note/passport"}},

		// sesh's own labels aren't searched.
		"storage prefix": {query: "sesh", want: nil},
		"description":    {query: "for", want: nil},
		"account":        {query: "testuser", want: nil},
		"empty":          {query: "  ", want: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries, err := m.SearchEntries(tc.query)
			if err != nil {
				t.Fatalf("SearchEntries(%q): %v", tc.query, err)
			}
			var got []string
			for i := range entries {
				got = append(got, label(&entries[i]))
			}
			if strings.Join(got, ", ") != strings.Join(tc.want, ", ") {
				t.Errorf("SearchEntries(%q) =\n  %v\nwant\n  %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestSearchSuggestions(t *testing.T) {
	m := searchVault(t)
	tests := map[string]struct {
		query string
		want  []string
	}{
		"swapped letters":                 {query: "gihtub", want: []string{"github"}},
		"missing letter":                  {query: "netflx", want: []string{"netflix"}},
		"one letter off":                  {query: "pasport", want: []string{"passport"}},
		"part of a name":                  {query: "consle", want: []string{"console"}},
		"username":                        {query: "alcie", want: []string{"alice"}},
		"kind word":                       {query: "totpp", want: []string{"totp"}},
		"ignores case":                    {query: "GIHTUB", want: []string{"github"}},
		"nothing close":                   {query: "zzzzzz", want: nil},
		"short words need a closer match": {query: "gtx", want: nil},
		"several words":                   {query: "gihtub alice", want: nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := m.SearchSuggestions(tc.query)
			if err != nil {
				t.Fatalf("SearchSuggestions(%q): %v", tc.query, err)
			}
			if strings.Join(got, ", ") != strings.Join(tc.want, ", ") {
				t.Errorf("SearchSuggestions(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestSearchSuggestions_KindWordsOnlyForKindsInTheVault(t *testing.T) {
	entries := []keychain.KeychainEntry{
		{Service: "sesh-password/password/github/alice", Account: "testuser"},
		{Service: "sesh-password/api_key/openai", Account: "testuser"},
	}
	m := NewManager(&mocks.MockProvider{
		ListEntriesFunc: func(string) ([]keychain.KeychainEntry, error) { return entries, nil },
	}, "testuser")
	for query, want := range map[string]string{
		"2fa":   "",      // no TOTP entries: "mfa" would find nothing either
		"notes": "",      // no notes
		"tokn":  "token", // API keys exist
	} {
		got, err := m.SearchSuggestions(query)
		if err != nil {
			t.Fatalf("SearchSuggestions(%q): %v", query, err)
		}
		if strings.Join(got, ", ") != want {
			t.Errorf("SearchSuggestions(%q) = %v, want %q", query, got, want)
		}
	}
}

func TestSearch_ListError(t *testing.T) {
	m := NewManager(&mocks.MockProvider{
		ListEntriesFunc: func(string) ([]keychain.KeychainEntry, error) {
			return nil, errors.New("store unavailable")
		},
	}, "testuser")
	if _, err := m.SearchEntries("github"); err == nil || !strings.Contains(err.Error(), "store unavailable") {
		t.Errorf("SearchEntries error = %v, want it to contain %q", err, "store unavailable")
	}
	if _, err := m.SearchSuggestions("gihtub"); err == nil || !strings.Contains(err.Error(), "store unavailable") {
		t.Errorf("SearchSuggestions error = %v, want it to contain %q", err, "store unavailable")
	}
}
