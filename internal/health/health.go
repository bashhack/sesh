// Package health finds what's wrong with the secrets in a vault: weak
// passwords, secrets used on more than one entry, and ones not changed in
// a long time.
package health

import (
	"crypto/sha256"
	"slices"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// Checker checks entries one at a time, as their secrets are read, and
// keeps no secret: a secret used again is found by its SHA-256 alone.
type Checker struct {
	// IsWeak says whether a password is easy to guess, given words it
	// shouldn't lean on; nil checks none.
	IsWeak func(pw []byte, hints ...string) bool

	seen map[[sha256.Size]byte][]vault.Key
	Now  time.Time
	r    Report
	// OldAfter is how long a secret can go unchanged before it's old; 0
	// checks none.
	OldAfter time.Duration
}

// Report is what a check found. Each list is in name order.
type Report struct {
	Weak       []vault.Key
	Reused     [][]vault.Key // the entries sharing each secret
	Old        []Aged
	Unreadable []vault.Key // entries whose secret doesn't decrypt, so weren't checked
	Checked    int         // the secrets checked
}

// Aged is an entry whose secret is old: when it last changed.
type Aged struct {
	Changed time.Time
	Key     vault.Key
}

// Problems is how many things the report found.
func (r *Report) Problems() int {
	n := len(r.Weak) + len(r.Old) + len(r.Unreadable)
	for _, g := range r.Reused {
		n += len(g)
	}
	return n
}

// Kinds are the kinds of entry whose secrets are checked: passwords and API
// keys. A TOTP key or a secure note's text isn't a secret people pick,
// reuse, or change on a schedule, so it needn't be read.
var Kinds = []vault.Kind{vault.KindPassword, vault.KindAPIKey}

func checked(k vault.Kind) bool { return slices.Contains(Kinds, k) }

// Add checks e, whose secret is secret, or which couldn't be read (err),
// as EachSecret hands it over. Only passwords are rated; passwords and API
// keys are checked for reuse and age. An empty password is weak.
func (c *Checker) Add(e *vault.Entry, secret []byte, err error) error {
	if !checked(e.Kind) {
		return nil
	}
	if err != nil {
		c.r.Unreadable = append(c.r.Unreadable, e.Key)
		return nil
	}
	c.r.Checked++
	if len(secret) == 0 {
		if e.Kind == vault.KindPassword {
			c.r.Weak = append(c.r.Weak, e.Key)
		}
		return nil
	}
	if c.seen == nil {
		c.seen = map[[sha256.Size]byte][]vault.Key{}
	}
	sum := sha256.Sum256(secret)
	c.seen[sum] = append(c.seen[sum], e.Key)
	if c.OldAfter > 0 && !e.UpdatedAt.IsZero() && c.Now.Sub(e.UpdatedAt) >= c.OldAfter {
		c.r.Old = append(c.r.Old, Aged{Key: e.Key, Changed: e.UpdatedAt})
	}
	if e.Kind != vault.KindPassword {
		return nil
	}
	if c.IsWeak != nil && c.IsWeak(secret, e.Service, e.Username) {
		c.r.Weak = append(c.r.Weak, e.Key)
	}
	return nil
}

// Report is what's been found.
func (c *Checker) Report() Report {
	r := c.r
	byName := func(a, b vault.Key) int { return strings.Compare(a.String(), b.String()) }
	r.Reused = nil
	for _, keys := range c.seen {
		if len(keys) > 1 {
			g := slices.Clone(keys)
			slices.SortFunc(g, byName)
			r.Reused = append(r.Reused, g)
		}
	}
	slices.SortFunc(r.Reused, func(a, b []vault.Key) int { return byName(a[0], b[0]) })
	r.Weak = slices.Clone(r.Weak)
	slices.SortFunc(r.Weak, byName)
	r.Old = slices.Clone(r.Old)
	slices.SortFunc(r.Old, func(a, b Aged) int { return byName(a.Key, b.Key) })
	r.Unreadable = slices.Clone(r.Unreadable)
	slices.SortFunc(r.Unreadable, byName)
	return r
}
