package syncfolder

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Merged is what Merge makes of two versions of an entry.
type Merged struct {
	// Record is the merged entry, with the changes both had seen. Its
	// computer and change time are for the caller to set, as it writes it,
	// and its own change to count (Versions.Next).
	*Record
	// Conflicts names what both versions changed, each its own way: the
	// newer change was kept ("secret", "notes", "field pin", ...).
	Conflicts []string
	// Lost is the secret the older version had, when both changed it: it's
	// in the merged entry's history.
	Lost []byte
}

// Merge merges two versions of an entry, ours and theirs, against base, the
// version both were last synced at (nil when there's none: they were
// never synced together):
//
//   - what only one changed, from base, is taken from it;
//   - what both changed, each its own way, is taken from the newer (the
//     one changed later, by Changed), unless one already had the other's
//     value (it merged it before): then there's nothing to settle.
//     Nothing secret of the older's is lost: its secret goes into the
//     history, its notes below the newer's, a secret field it changed is
//     kept as another field, named for its computer;
//   - tags and custom fields merge one by one, and code settings each on
//     its own; a file entry's file name goes with its file;
//   - earlier secrets are those either has, each once, less those either
//     forgot on purpose (Forgotten);
//   - an entry edited (or restored) in one and deleted (to the trash, or
//     for good) in the other comes back, with the edit.
//
// It's the same whichever version is ours, so two computers merging the
// same versions make the same entry. The versions aren't changed; the
// merged one shares nothing with them.
func Merge(base, ours, theirs *Record) Merged {
	return MergeWith(base, ours, theirs, Beside{Notes: true, Fields: true})
}

// Beside says what of the older's Merge keeps beside the newer's where both
// changed it: its notes, its secret fields.
type Beside struct{ Notes, Fields bool }

// Wipe zeroes the merged entry's secrets, and the older secret lost.
func (m Merged) Wipe() {
	if m.Record != nil {
		m.Record.Wipe()
	}
	secure.SecureZeroBytes(m.Lost)
}

// MergeWith is Merge, keeping beside the newer's only what of the older's
// beside says: for an entry the older's don't all fit in (too many
// fields, notes too long).
func MergeWith(base, ours, theirs *Record, beside Beside) (m Merged) {
	if base == nil {
		base = &Record{}
	}
	newer, older := ours, theirs
	if newerOf(theirs, ours) {
		newer, older = theirs, ours
	}
	m = Merged{Record: &Record{}}
	defer func() { m.Versions = ours.Versions.Join(theirs.Versions) }()
	switch {
	case !ours.Purged.IsZero() && !theirs.Purged.IsZero():
		m.Purged = earliest(ours.Purged, theirs.Purged)
		return m
	case !ours.Purged.IsZero() && !kept(base, theirs):
		m.Purged = ours.Purged
		return m
	case !theirs.Purged.IsZero() && !kept(base, ours):
		m.Purged = theirs.Purged
		return m
	case !ours.Purged.IsZero():
		// Deleted for good in ours, edited or restored in theirs: it comes
		// back, as theirs has it.
		return copyOf(theirs)
	case !theirs.Purged.IsZero():
		return copyOf(ours)
	}
	r := m.Record
	r.Forgotten = mergeForgotten(ours.Forgotten, theirs.Forgotten)
	oursNewer := newer == ours
	type name struct {
		kind              vault.Kind
		service, username string
	}
	n := pick(&m, "name", oursNewer, name{base.Kind, base.Service, base.Username},
		name{ours.Kind, ours.Service, ours.Username}, name{theirs.Kind, theirs.Service, theirs.Username}, eq[name])
	r.Kind, r.Service, r.Username = n.kind, n.service, n.username
	r.URL = pick(&m, "URL", oursNewer, base.URL, ours.URL, theirs.URL, eq[string])
	r.Folder = pick(&m, "folder", oursNewer, base.Folder, ours.Folder, theirs.Folder, eq[string])
	r.Settings.AWSMFADevice = pick(&m, "MFA device", oursNewer, base.Settings.AWSMFADevice, ours.Settings.AWSMFADevice, theirs.Settings.AWSMFADevice, eq[string])
	r.Settings.TOTP = pick(&m, "code settings", oursNewer, base.Settings.TOTP, ours.Settings.TOTP, theirs.Settings.TOTP, eq)
	r.Notes = mergeNotes(&m, base.Notes, newer, older, beside.Notes)
	r.Tags = mergeTags(base.Tags, ours.Tags, theirs.Tags)
	var overflow []Field
	r.Fields, overflow = mergeFields(&m, base.Fields, newer, older, beside.Fields)
	// Kept beside, but the entry has all the fields it can: in its notes.
	for _, f := range overflow {
		if len(r.Notes) > 0 {
			r.Notes = append(r.Notes, "\n\n"...)
		}
		r.Notes = append(r.Notes, "— "+f.Name+" —\n"...)
		r.Notes = append(r.Notes, f.Value...)
	}

	// The secret: the one changed, or the newer's (unless one already
	// replaced the other's: that one's); the update time and a file's name
	// follow it, as they say when it last changed and what it is.
	secretFrom := ours
	switch {
	case bytes.Equal(ours.Secret, base.Secret):
		secretFrom = theirs
	case bytes.Equal(theirs.Secret, base.Secret), bytes.Equal(ours.Secret, theirs.Secret):
	case hasEarlier(theirs.History, ours.Secret) && !hasEarlier(ours.History, theirs.Secret):
		secretFrom = theirs
	case hasEarlier(ours.History, theirs.Secret) && !hasEarlier(theirs.History, ours.Secret):
	default:
		m.Conflicts = append(m.Conflicts, "secret")
		secretFrom = newer
		m.Lost = bytes.Clone(older.Secret)
	}
	r.Secret = bytes.Clone(secretFrom.Secret)
	r.Updated = secretFrom.Updated
	r.Settings.FileName = secretFrom.Settings.FileName
	if bytes.Equal(ours.Secret, theirs.Secret) {
		r.Updated = latest(ours.Updated, theirs.Updated)
		r.Settings.FileName = pick(&m, "file name", oursNewer, base.Settings.FileName, ours.Settings.FileName, theirs.Settings.FileName, eq[string])
	}
	r.Created = earliest(ours.Created, theirs.Created)
	// Whichever secret isn't kept goes into the history, replaced when and
	// where the kept one was made: either computer may keep fewer earlier
	// secrets than the other, so neither's history may have it.
	history := slices.Concat(ours.History, theirs.History)
	replacedAt := secretFrom.Updated
	if replacedAt.IsZero() {
		replacedAt = secretFrom.Changed
	}
	for _, side := range []*Record{ours, theirs} {
		if len(side.Secret) > 0 && !bytes.Equal(side.Secret, r.Secret) {
			history = append(history, Earlier{ReplacedAt: replacedAt, Computer: secretFrom.Computer, FileName: side.Settings.FileName, Secret: side.Secret})
		}
	}
	r.History = mergeHistory(history, r.Forgotten, r.Secret)

	// In the trash: as either changed it, the earlier deletion if both
	// did; but an entry edited where it wasn't deleted comes back.
	switch {
	case ours.Deleted.Equal(base.Deleted):
		r.Deleted = theirs.Deleted
	case theirs.Deleted.Equal(base.Deleted):
		r.Deleted = ours.Deleted
	case ours.Deleted.IsZero() || theirs.Deleted.IsZero():
		// Restored in one, deleted again in the other.
		r.Deleted = newer.Deleted
	default:
		r.Deleted = earliest(ours.Deleted, theirs.Deleted)
	}
	if !r.Deleted.IsZero() && ((ours.Deleted.IsZero() && edited(base, ours)) || (theirs.Deleted.IsZero() && edited(base, theirs))) {
		r.Deleted = time.Time{}
	}
	return m
}

// pick is what of a value of an entry's (called name) the merge keeps:
// the one changed from b, o or t; both changed their own ways, the newer's,
// noted in m.
func pick[T any](m *Merged, name string, oursNewer bool, b, o, t T, eq func(a, b T) bool) T {
	switch {
	case eq(o, b):
		return t
	case eq(t, b), eq(o, t):
		return o
	}
	m.Conflicts = append(m.Conflicts, name)
	if oursNewer {
		return o
	}
	return t
}

func eq[T comparable](a, b T) bool { return a == b }

// kept says whether r's entry was edited or restored from the trash since
// base: kept on purpose, so a deletion elsewhere doesn't take it.
func kept(base, r *Record) bool {
	return edited(base, r) || (!base.Deleted.IsZero() && r.Deleted.IsZero())
}

// newerOf says whether a was changed after b: by Changed, then, for the
// same time, by computer, version and what they hold, so both computers
// order any two alike.
func newerOf(a, b *Record) bool {
	if c := a.Changed.Compare(b.Changed); c != 0 {
		return c > 0
	}
	if c := strings.Compare(a.Computer, b.Computer); c != 0 {
		return c > 0
	}
	if x, y := a.Versions.total(), b.Versions.total(); x != y {
		return x > y
	}
	if c := bytes.Compare(a.Secret, b.Secret); c != 0 {
		return c > 0
	}
	return bytes.Compare(a.Notes, b.Notes) > 0
}

// edited says whether r's entry differs from base's in what it holds (not
// whether it's in the trash).
func edited(base, r *Record) bool {
	return base.Kind != r.Kind || base.Service != r.Service || base.Username != r.Username ||
		base.URL != r.URL || base.Folder != r.Folder || !bytes.Equal(base.Secret, r.Secret) ||
		!bytes.Equal(base.Notes, r.Notes) || base.Settings != r.Settings ||
		!slices.Equal(vault.NormalizeTags(base.Tags), vault.NormalizeTags(r.Tags)) ||
		!slices.EqualFunc(base.Fields, r.Fields, sameField)
}

func sameField(a, b Field) bool {
	return a.Name == b.Name && a.Secret == b.Secret && bytes.Equal(a.Value, b.Value)
}

func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero(), a.Before(b):
		return a
	}
	return b
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// copyOf is r, its secrets copied, as a merge's result: brought back from
// a deletion for good elsewhere, in the trash only if r is.
func copyOf(r *Record) Merged {
	c := *r
	c.Secret, c.Notes = bytes.Clone(r.Secret), bytes.Clone(r.Notes)
	c.Tags = slices.Clone(r.Tags)
	c.Forgotten = slices.Clone(r.Forgotten)
	c.Fields = slices.Clone(r.Fields)
	for i := range c.Fields {
		c.Fields[i].Value = bytes.Clone(c.Fields[i].Value)
	}
	c.History = slices.Clone(r.History)
	for i := range c.History {
		c.History[i].Secret = bytes.Clone(c.History[i].Secret)
	}
	c.Purged = time.Time{}
	return Merged{Record: &c}
}

// from names where an older version was made, for what's kept of it
// beside the newer: "laptop, 2026-10-16 14:02 UTC".
func from(r *Record) string {
	if r.Changed.IsZero() {
		return r.Computer
	}
	return r.Computer + ", " + r.Changed.UTC().Format("2006-01-02 15:04 UTC")
}

// mergeNotes is the notes the one that changed them has; both changed
// them their own ways, the newer's, with the older's below them under a
// line naming where they're from, unless one has the other's already.
func mergeNotes(m *Merged, base []byte, newer, older *Record, beside bool) []byte {
	switch {
	case bytes.Equal(older.Notes, base):
		return bytes.Clone(newer.Notes)
	case bytes.Equal(newer.Notes, base), bytes.Equal(newer.Notes, older.Notes):
		return bytes.Clone(older.Notes)
	case len(older.Notes) > 0 && bytes.Contains(newer.Notes, older.Notes):
		return bytes.Clone(newer.Notes)
	case len(newer.Notes) > 0 && bytes.Contains(older.Notes, newer.Notes):
		return bytes.Clone(older.Notes)
	}
	m.Conflicts = append(m.Conflicts, "notes")
	out := bytes.Clone(newer.Notes)
	if !beside {
		return out
	}
	if len(out) > 0 {
		out = append(out, "\n\n"...)
	}
	out = append(out, "— from "+from(older)+" —\n"...)
	return append(out, older.Notes...)
}

// mergeTags is the tags either added to base's, less those either removed.
func mergeTags(base, ours, theirs []string) []string {
	in := slices.Contains[[]string]
	var out []string
	for _, t := range vault.NormalizeTags(slices.Concat(base, ours, theirs)) {
		switch {
		case in(base, t) && (!in(ours, t) || !in(theirs, t)):
			// Removed by one.
		case in(ours, t) || in(theirs, t):
			out = append(out, t)
		}
	}
	return out
}

// mergeFields merges custom fields one by one, by name (in any case, as
// an entry's are told apart): one only one changed, added or removed is
// as it has it; one both changed their own ways is the newer's, and a
// secret one whose value the older changed is kept as another field,
// named for its computer, unless the newer has that value already. They're in the
// newer's order, then those only the older has, in its; those kept
// beside last.
func mergeFields(m *Merged, base []Field, newer, older *Record, beside bool) (out, overflow []Field) {
	find := func(fs []Field, name string) (Field, bool) {
		i := slices.IndexFunc(fs, func(f Field) bool { return strings.EqualFold(f.Name, name) })
		if i < 0 {
			return Field{}, false
		}
		return fs[i], true
	}
	var names []string
	for _, f := range slices.Concat(newer.Fields, older.Fields, base) {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, f.Name) }) {
			names = append(names, f.Name)
		}
	}
	var besides []Field
	for _, n := range names {
		b, inB := find(base, n)
		nw, inN := find(newer.Fields, n)
		ol, inO := find(older.Fields, n)
		same := func(x Field, inX bool, y Field, inY bool) bool { return inX == inY && (!inX || sameField(x, y)) }
		f, keep := nw, inN
		switch {
		case same(ol, inO, b, inB):
		case same(nw, inN, b, inB), same(nw, inN, ol, inO):
			f, keep = ol, inO
		default:
			m.Conflicts = append(m.Conflicts, "field "+n)
			has := slices.ContainsFunc(newer.Fields, func(g Field) bool { return bytes.Equal(g.Value, ol.Value) })
			changedValue := !inB || !bytes.Equal(ol.Value, b.Value)
			if beside && inO && ol.Secret && changedValue && !has {
				besides = append(besides, Field{Name: ol.Name, Value: ol.Value, Secret: true})
			}
		}
		if keep {
			f.Value = bytes.Clone(f.Value)
			out = append(out, f)
		}
	}
	for _, f := range besides {
		f.Name, f.Value = besideName(f.Name, older.Computer, out), bytes.Clone(f.Value)
		if len(out) >= vault.MaxFields {
			overflow = append(overflow, f)
			continue
		}
		out = append(out, f)
	}
	return out, overflow
}

// besideName is the name a field kept beside another of the same name
// gets: "pin-laptop", the computer's name made fit for a field's, kept
// short enough, numbered if fields has it already.
func besideName(name, computer string, fields []Field) string {
	var c strings.Builder
	for _, r := range computer {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' {
			c.WriteRune(r)
		} else {
			c.WriteRune('-')
		}
	}
	suffix := strings.Trim(c.String(), "-")
	if suffix == "" {
		suffix = "other"
	}
	fit := func(base, tail string) string {
		if rs := []rune(base); len(rs)+len([]rune(tail)) > vault.MaxFieldNameLength {
			base = string(rs[:max(vault.MaxFieldNameLength-len([]rune(tail)), 1)])
		}
		return base + tail
	}
	out := fit(name, "-"+suffix)
	for i := 2; slices.ContainsFunc(fields, func(g Field) bool { return strings.EqualFold(g.Name, out) }); i++ {
		out = fit(name, fmt.Sprintf("-%s-%d", suffix, i))
	}
	return out
}

// Forget is how an earlier secret forgotten on purpose is named in
// Forgotten: its SHA-256 in hex. The record is sealed, so the hash is
// never seen without the vault's key.
func Forget(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:])
}

// mergeForgotten is the secrets either forgot, each once, when last
// forgotten, in order.
func mergeForgotten(ours, theirs []Forgotten) []Forgotten {
	var out []Forgotten
	for _, f := range slices.Concat(ours, theirs) {
		if i := slices.IndexFunc(out, func(g Forgotten) bool { return g.Hash == f.Hash }); i >= 0 {
			if f.At.After(out[i].At) {
				out[i].At = f.At
			}
			continue
		}
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Forgotten) int { return cmp.Compare(a.Hash, b.Hash) })
	return out
}

// forgottenOne says whether e was forgotten on purpose: its secret was,
// after it was replaced.
func forgottenOne(e *Earlier, forgotten []Forgotten) bool {
	if len(forgotten) == 0 {
		return false
	}
	h := Forget(e.Secret)
	return slices.ContainsFunc(forgotten, func(f Forgotten) bool { return f.Hash == h && !e.ReplacedAt.After(f.At) })
}

// hasEarlier says whether hs has secret among its earlier secrets.
func hasEarlier(hs []Earlier, secret []byte) bool {
	return slices.ContainsFunc(hs, func(e Earlier) bool { return bytes.Equal(e.Secret, secret) })
}

// mergeHistory is the earlier secrets of hs, each secret once (when it was
// first replaced), less those forgotten and the current secret, the
// newest first. Neither computer's history.keep trims it: each trims its
// own.
func mergeHistory(hs []Earlier, forgotten []Forgotten, current []byte) []Earlier {
	hs = slices.Clone(hs)
	slices.SortStableFunc(hs, func(a, b Earlier) int {
		return cmp.Or(a.ReplacedAt.Compare(b.ReplacedAt), cmp.Compare(a.Computer, b.Computer), cmp.Compare(a.FileName, b.FileName), bytes.Compare(a.Secret, b.Secret))
	})
	var out []Earlier
	for _, e := range hs {
		if bytes.Equal(e.Secret, current) || hasEarlier(out, e.Secret) || forgottenOne(&e, forgotten) {
			continue
		}
		e.Secret = bytes.Clone(e.Secret)
		out = append(out, e)
	}
	slices.Reverse(out)
	return out
}
