package password

import (
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// Search matches each word of a query against the parts of an entry the
// user named: its service name and username, and the host of its URL. A
// word can instead name the entry's kind ("totp", "key", "note", ...).
// Every word has to match.
// sesh's own labels (the stored name's prefix, the OS account, the
// generated description) are never searched, and neither is any secret.

// kindWords are the words a search takes as naming an entry type. Only
// whole words count, so "pass" is a name search, not "password".
var kindWords = map[string]EntryType{
	"password": EntryTypePassword, "passwords": EntryTypePassword,
	"totp": EntryTypeTOTP, "otp": EntryTypeTOTP, "2fa": EntryTypeTOTP, "mfa": EntryTypeTOTP,
	"api_key": EntryTypeAPIKey, "api-key": EntryTypeAPIKey, "apikey": EntryTypeAPIKey, "api": EntryTypeAPIKey,
	"key": EntryTypeAPIKey, "keys": EntryTypeAPIKey, "token": EntryTypeAPIKey, "tokens": EntryTypeAPIKey,
	"secure_note": EntryTypeNote, "secure-note": EntryTypeNote, "note": EntryTypeNote, "notes": EntryTypeNote,
}

// Ranks of a word's match, lower being better. A field match is one of
// matchExact..matchInside; a username match adds userRank to it, and a
// match in the URL's host hostRank.
const (
	matchExact  = iota // the whole field: "github"
	matchPrefix        // the field's start: "git" in "github"
	matchWord          // a later word's start: "bank" in "my-bank"
	matchInside        // anywhere else: "hub" in "github"
	userRank
	hostRank = 2 * userRank
	kindRank = 3 * userRank
)

// separators split a name into words, and may be left out of a query:
// "mybank" finds "my-bank".
const separators = " -_./@:+"

// SearchEntries returns the entries matching every word of query, ignoring
// case and surrounding spaces, best match first. A word matches anywhere
// in an entry's service name (ranked best when it is the whole name, then
// its start, then a word's start, then anywhere), then its username in the
// same order, then its URL's host, then its kind. An entry's rank adds up
// its words'; the most recently updated comes first among equals. An
// empty query matches nothing.
func (m *Manager) SearchEntries(query string) ([]Entry, error) {
	return m.SearchIn(query, &ListFilter{})
}

// SearchIn is SearchEntries over the entries in's kind, folder, and tags
// let through; its other fields are ignored.
func (m *Manager) SearchIn(query string, in *ListFilter) ([]Entry, error) {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return nil, nil
	}
	entries, err := m.list(in)
	if err != nil {
		return nil, err
	}

	type hit struct {
		entry Entry
		rank  int
	}
	var hits []hit
	for i := range entries {
		if r := entryRank(&entries[i], words); r >= 0 {
			hits = append(hits, hit{entries[i], r})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := &hits[i], &hits[j]
		switch {
		case a.rank != b.rank:
			return a.rank < b.rank
		case !a.entry.UpdatedAt.Equal(b.entry.UpdatedAt):
			return a.entry.UpdatedAt.After(b.entry.UpdatedAt)
		case a.entry.Service != b.entry.Service:
			return a.entry.Service < b.entry.Service
		case a.entry.Username != b.entry.Username:
			return a.entry.Username < b.entry.Username
		default:
			return a.entry.Type < b.entry.Type
		}
	})
	results := make([]Entry, len(hits))
	for i := range hits {
		results[i] = hits[i].entry
	}
	return results, nil
}

// entryRank sums the ranks of words against e, or returns -1 if any word
// doesn't match.
func entryRank(e *Entry, words []string) int {
	total := 0
	for _, w := range words {
		r := wordRank(e, w)
		if r < 0 {
			return -1
		}
		total += r
	}
	return total
}

func wordRank(e *Entry, w string) int {
	if r := fieldRank(e.Service, w); r >= 0 {
		return r
	}
	if r := fieldRank(e.Username, w); r >= 0 {
		return userRank + r
	}
	if r := fieldRank(urlHost(e.URL), w); r >= 0 {
		return hostRank + r
	}
	if t, ok := kindWords[w]; ok && t == e.Type {
		return kindRank
	}
	return -1
}

// urlHost is the host of an entry's URL, without a port; "" for none. A
// URL without a scheme ("github.com/login") is read as a web address.
func urlHost(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// fieldRank ranks where w appears in field, or returns -1. Without a
// match as typed, it compares both with separators removed.
func fieldRank(field, w string) int {
	f := strings.ToLower(field)
	if f == "" {
		return -1
	}
	switch {
	case f == w:
		return matchExact
	case strings.HasPrefix(f, w):
		return matchPrefix
	case startsWord(f, w):
		return matchWord
	case strings.Contains(f, w):
		return matchInside
	}
	fs, ws := squash(f), squash(w)
	switch {
	case ws == "":
		return -1
	case fs == ws:
		return matchExact
	case strings.HasPrefix(fs, ws):
		return matchPrefix
	case strings.Contains(fs, ws):
		return matchInside
	}
	return -1
}

// startsWord reports whether w starts one of f's words after the first.
func startsWord(f, w string) bool {
	for i := 1; i < len(f); i++ {
		if strings.IndexByte(separators, f[i-1]) >= 0 && strings.HasPrefix(f[i:], w) {
			return true
		}
	}
	return false
}

func squash(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(separators, r) {
			return -1
		}
		return r
	}, s)
}

// SearchSuggestions returns the names closest to a one-word query, for a
// "did you mean" when it matched nothing: service names, usernames, the
// words within them, and the kind words of kinds the vault holds (so each
// suggestion finds something), at the smallest edit distance found
// (letters added, removed, changed, or swapped). A word of up to four
// letters allows one edit, a longer one two. A query of several words
// gets no suggestions.
func (m *Manager) SearchSuggestions(query string) ([]string, error) {
	return m.SuggestionsIn(query, &ListFilter{})
}

// SuggestionsIn is SearchSuggestions from the entries in's kind, folder,
// and tags let through.
func (m *Manager) SuggestionsIn(query string, in *ListFilter) ([]string, error) {
	words := strings.Fields(strings.ToLower(query))
	if len(words) != 1 {
		return nil, nil
	}
	w := words[0]
	entries, err := m.list(in)
	if err != nil {
		return nil, err
	}

	candidates := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(s)
		if s == "" {
			return
		}
		candidates[s] = true
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(separators, r) }) {
			candidates[part] = true
		}
	}
	kinds := map[EntryType]bool{}
	for i := range entries {
		add(entries[i].Service)
		add(entries[i].Username)
		kinds[entries[i].Type] = true
	}
	for k, t := range kindWords {
		if kinds[t] {
			candidates[k] = true
		}
	}

	limit := 2
	if utf8.RuneCountInString(w) <= 4 {
		limit = 1
	}
	var best []string
	for c := range candidates {
		d := editDistance(w, c)
		switch {
		case d == 0 || d > limit:
		case d < limit:
			limit, best = d, []string{c}
		default:
			best = append(best, c)
		}
	}
	sort.Strings(best)
	return best, nil
}

// editDistance counts the single-letter additions, removals, changes, and
// swaps of neighbours that turn a into b (optimal string alignment).
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	prev2 := make([]int, len(y)+1)
	prev := make([]int, len(y)+1)
	cur := make([]int, len(y)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(x); i++ {
		cur[0] = i
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && x[i-1] == y[j-2] && x[i-2] == y[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(y)]
}
