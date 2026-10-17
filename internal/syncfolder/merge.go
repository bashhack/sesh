package syncfolder

import (
	"bytes"
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// Merged is what Merge makes of two versions of an entry.
type Merged struct {
	// Record is the merged entry. Its version, computer and change time
	// are for the caller to set, as it writes it.
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
//     one changed later, by Changed); the older's secret goes into the
//     history;
//   - tags and custom fields merge one by one, as do earlier secrets: those
//     either kept are kept, those either forgot are forgotten;
//   - an entry edited in one and deleted (to the trash, or for good) in the
//     other comes back, with the edit.
//
// It's the same whichever version is ours, so two computers merging the
// same versions make the same entry. The versions aren't changed; the
// merged one shares nothing with them.
func Merge(base, ours, theirs *Record) Merged {
	if base == nil {
		base = &Record{}
	}
	newer, older := ours, theirs
	if newerOf(theirs, ours) {
		newer, older = theirs, ours
	}
	m := Merged{Record: &Record{}}
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
	r.Notes = bytes.Clone(pick(&m, "notes", oursNewer, base.Notes, ours.Notes, theirs.Notes, bytes.Equal))
	r.Settings = pick(&m, "settings", oursNewer, base.Settings, ours.Settings, theirs.Settings, eq[vault.Settings])
	r.Tags = mergeTags(base.Tags, ours.Tags, theirs.Tags)
	r.Fields = mergeFields(&m, base.Fields, ours.Fields, theirs.Fields, oursNewer)

	// The secret: the one changed, or the newer's; the update time follows
	// it, as it says when the secret last changed.
	secretFrom := ours
	switch {
	case bytes.Equal(ours.Secret, base.Secret):
		secretFrom = theirs
	case bytes.Equal(theirs.Secret, base.Secret), bytes.Equal(ours.Secret, theirs.Secret):
	default:
		m.Conflicts = append(m.Conflicts, "secret")
		secretFrom = newer
		m.Lost = bytes.Clone(older.Secret)
	}
	r.Secret = bytes.Clone(secretFrom.Secret)
	r.Updated = secretFrom.Updated
	if bytes.Equal(ours.Secret, theirs.Secret) {
		r.Updated = latest(ours.Updated, theirs.Updated)
	}
	r.Created = earliest(ours.Created, theirs.Created)
	r.History = mergeHistory(base.History, ours.History, theirs.History)
	if m.Lost != nil {
		r.History = append(r.History, Earlier{ReplacedAt: newer.Changed, Computer: newer.Computer, FileName: older.Settings.FileName, Secret: bytes.Clone(m.Lost)})
		slices.SortStableFunc(r.History, func(a, b Earlier) int { return b.ReplacedAt.Compare(a.ReplacedAt) })
	}

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
// same time, by computer and version, so both computers order them alike.
func newerOf(a, b *Record) bool {
	if c := a.Changed.Compare(b.Changed); c != 0 {
		return c > 0
	}
	if c := strings.Compare(a.Computer, b.Computer); c != 0 {
		return c > 0
	}
	return a.Version > b.Version
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

// copyOf is r, its secrets copied, as a merge's result.
func copyOf(r *Record) Merged {
	c := *r
	c.Secret, c.Notes = bytes.Clone(r.Secret), bytes.Clone(r.Notes)
	c.Tags = slices.Clone(r.Tags)
	c.Fields = slices.Clone(r.Fields)
	for i := range c.Fields {
		c.Fields[i].Value = bytes.Clone(c.Fields[i].Value)
	}
	c.History = slices.Clone(r.History)
	for i := range c.History {
		c.History[i].Secret = bytes.Clone(c.History[i].Secret)
	}
	c.Purged, c.Deleted = time.Time{}, time.Time{}
	return Merged{Record: &c}
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
// as it has it; one both changed their own ways is the newer's. They're in
// the newer's order, then those only the older has, in its.
func mergeFields(m *Merged, base, ours, theirs []Field, oursNewer bool) []Field {
	find := func(fs []Field, name string) (Field, bool) {
		i := slices.IndexFunc(fs, func(f Field) bool { return strings.EqualFold(f.Name, name) })
		if i < 0 {
			return Field{}, false
		}
		return fs[i], true
	}
	newer, older := ours, theirs
	if !oursNewer {
		newer, older = theirs, ours
	}
	var names []string
	for _, f := range slices.Concat(newer, older, base) {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, f.Name) }) {
			names = append(names, f.Name)
		}
	}
	var out []Field
	for _, n := range names {
		b, inB := find(base, n)
		o, inO := find(ours, n)
		t, inT := find(theirs, n)
		same := func(x Field, inX bool, y Field, inY bool) bool { return inX == inY && (!inX || sameField(x, y)) }
		var f Field
		var keep bool
		switch {
		case same(o, inO, b, inB):
			f, keep = t, inT
		case same(t, inT, b, inB), same(o, inO, t, inT):
			f, keep = o, inO
		default:
			m.Conflicts = append(m.Conflicts, "field "+n)
			f, keep = o, inO
			if !oursNewer {
				f, keep = t, inT
			}
		}
		if keep {
			f.Value = bytes.Clone(f.Value)
			out = append(out, f)
		}
	}
	return out
}

// mergeHistory is the earlier secrets either has, less those base had and
// either forgot, the newest first.
func mergeHistory(base, ours, theirs []Earlier) []Earlier {
	key := func(e Earlier) string { return e.ReplacedAt.UTC().Format(time.RFC3339Nano) + "\x00" + string(e.Secret) }
	in := func(hs []Earlier, k string) bool {
		return slices.ContainsFunc(hs, func(e Earlier) bool { return key(e) == k })
	}
	var out []Earlier
	seen := map[string]bool{}
	for _, e := range slices.Concat(ours, theirs) {
		k := key(e)
		if seen[k] || (in(base, k) && (!in(ours, k) || !in(theirs, k))) {
			continue
		}
		seen[k] = true
		e.Secret = bytes.Clone(e.Secret)
		out = append(out, e)
	}
	slices.SortStableFunc(out, func(a, b Earlier) int {
		if c := b.ReplacedAt.Compare(a.ReplacedAt); c != 0 {
			return c
		}
		return cmp.Compare(string(a.Secret), string(b.Secret))
	})
	return out
}
