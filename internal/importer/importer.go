// Package importer holds what every source sesh import reads has in
// common: the entries it found, and fitting other apps' names to sesh's
// rules.
package importer

import (
	"strings"
	"time"
	"unicode"

	"github.com/bashhack/sesh/internal/vault"
)

// Entry is an entry an import found: what it would store, or why it can't
// (Skip).
type Entry struct {
	Created  time.Time
	Updated  time.Time
	Key      vault.Key
	Name     string // as the source names it
	Skip     string
	Folder   string
	Secret   []byte
	Tags     []string
	Changes  []string // what changed on the way, said in the summary
	Details  vault.Details
	Settings vault.Settings
}

// FitFolder fits a folder path from another app to sesh's folder rules:
// each "/"-separated part keeps its letters, digits, "-", "_" and ".",
// anything else becoming "-"; runs of "-" become one, and a part is
// trimmed of "-" and "." at its ends. Empty parts are dropped. "" is no
// folder.
func FitFolder(path string) string {
	var parts []string
	for part := range strings.SplitSeq(path, "/") {
		if p := fitLabel(part); p != "" && vault.CheckFolder(p) == nil {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "/")
}

// FitFieldName fits a field name from another app to sesh's field-name
// rules, as FitFolder does a folder part, and to its length; one that
// would be a reserved name, or empty, gets "-field" added.
func FitFieldName(name string) string {
	n := fitLabel(name)
	if r := []rune(n); len(r) > vault.MaxFieldNameLength-len("-field") {
		n = strings.Trim(string(r[:vault.MaxFieldNameLength-len("-field")]), "-.")
	}
	if n == "" || vault.CheckFieldName(n) != nil {
		n += "-field"
	}
	return strings.TrimPrefix(n, "-")
}

// FitName fits an item's name or username to sesh's name rules: "/"
// becomes "-", control and invisible characters go, spaces at the ends
// are trimmed, and it's cut to the longest name sesh holds.
func FitName(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > vault.MaxNameLength {
		s = strings.TrimSpace(string(r[:vault.MaxNameLength]))
	}
	return s
}

// fitLabel is s with only letters, digits (and their marks), "-", "_" and
// "."; anything else becomes "-", runs of "-" become one, and "-" and "."
// are trimmed from the ends.
func fitLabel(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || (i > 0 && unicode.In(r, unicode.Mn, unicode.Mc)):
			if unicode.Is(unicode.Cf, r) {
				continue
			}
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-.")
}
