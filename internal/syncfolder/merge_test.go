package syncfolder

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// baseRecord is an entry as two computers last synced it.
func baseRecord() *Record {
	return &Record{
		Created: t0, Updated: t0, Changed: t0, Computer: "laptop", Version: 3,
		Kind: vault.KindPassword, Service: "github", Username: "alice",
		URL: "https://github.com", Folder: "work", Secret: []byte("pw-1"), Notes: []byte("notes"),
		Fields:  []Field{{Name: "pin", Value: []byte("1111"), Secret: true}, {Name: "team", Value: []byte("core")}},
		Tags:    []string{"code", "work"},
		History: []Earlier{{ReplacedAt: t0.Add(-time.Hour), Computer: "laptop", Secret: []byte("pw-0")}},
	}
}

// changed is base as a computer changed it at hour h after t0.
func changed(computer string, h int, edit func(r *Record)) *Record {
	r := copyOf(baseRecord()).Record
	r.Computer, r.Changed, r.Version = computer, t0.Add(time.Duration(h)*time.Hour), 4
	edit(r)
	return r
}

// merge merges ours and theirs against base both ways round, failing t
// unless both give the same entry.
func merge(t *testing.T, base, ours, theirs *Record) Merged {
	t.Helper()
	a, b := Merge(base, ours, theirs), Merge(base, theirs, ours)
	if !recordsEqual(a.Record, b.Record) || !bytes.Equal(a.Lost, b.Lost) || !slices.Equal(sorted(a.Conflicts), sorted(b.Conflicts)) {
		t.Fatalf("not the same both ways round:\n%+v %q\n%+v %q", a.Record, a.Conflicts, b.Record, b.Conflicts)
	}
	return a
}

func sorted(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }

// What only one changed is taken from it, whichever it was, with nothing
// noted; what neither changed stays.
func TestMerge_OneSided(t *testing.T) {
	for name, tc := range map[string]struct {
		edit  func(r *Record)
		check func(r *Record) bool
	}{
		"secret": {func(r *Record) { r.Secret, r.Updated = []byte("pw-2"), t0.Add(time.Hour) }, func(r *Record) bool {
			return string(r.Secret) == "pw-2" && r.Updated.Equal(t0.Add(time.Hour))
		}},
		"name":     {func(r *Record) { r.Service = "github-work" }, func(r *Record) bool { return r.Service == "github-work" }},
		"kind":     {func(r *Record) { r.Kind = vault.KindAPIKey }, func(r *Record) bool { return r.Kind == vault.KindAPIKey }},
		"URL":      {func(r *Record) { r.URL = "" }, func(r *Record) bool { return r.URL == "" }},
		"folder":   {func(r *Record) { r.Folder = "home" }, func(r *Record) bool { return r.Folder == "home" }},
		"notes":    {func(r *Record) { r.Notes = []byte("more") }, func(r *Record) bool { return string(r.Notes) == "more" }},
		"settings": {func(r *Record) { r.Settings.TOTP = totp.Params{Digits: 8} }, func(r *Record) bool { return r.Settings.TOTP.Digits == 8 }},
		"a tag added": {func(r *Record) { r.Tags = append(r.Tags, "new") }, func(r *Record) bool {
			return slices.Equal(r.Tags, []string{"code", "new", "work"})
		}},
		"a tag removed": {func(r *Record) { r.Tags = []string{"work"} }, func(r *Record) bool { return slices.Equal(r.Tags, []string{"work"}) }},
		"a field changed": {func(r *Record) { r.Fields[0].Value = []byte("2222") }, func(r *Record) bool {
			return len(r.Fields) == 2 && string(r.Fields[0].Value) == "2222"
		}},
		"a field removed":             {func(r *Record) { r.Fields = r.Fields[1:] }, func(r *Record) bool { return len(r.Fields) == 1 && r.Fields[0].Name == "team" }},
		"an earlier secret forgotten": {func(r *Record) { r.History = nil }, func(r *Record) bool { return len(r.History) == 0 }},
	} {
		one := changed("desktop", 1, tc.edit)
		m := merge(t, baseRecord(), baseRecord(), one)
		if !tc.check(m.Record) || len(m.Conflicts) != 0 || m.Lost != nil {
			t.Errorf("%s: merged %+v, conflicts %q", name, m.Record, m.Conflicts)
		}
		// Everything else as base has it.
		if name != "secret" && (string(m.Secret) != "pw-1" || !m.Updated.Equal(t0)) {
			t.Errorf("%s: secret %q updated %v", name, m.Secret, m.Updated)
		}
		if name != "an earlier secret forgotten" && len(m.History) != 1 {
			t.Errorf("%s: history %+v", name, m.History)
		}
	}
}

// Each computer's own changes all come through: one's new password, the
// other's note, tag and field.
func TestMerge_BothChangedDifferentThings(t *testing.T) {
	laptop := changed("laptop", 1, func(r *Record) { r.Secret, r.Updated = []byte("pw-2"), t0.Add(time.Hour) })
	desktop := changed("desktop", 2, func(r *Record) {
		r.Notes = []byte("note from desktop")
		r.Tags = append(r.Tags, "home")
		r.Fields = append(r.Fields, Field{Name: "recovery", Value: []byte("r"), Secret: true})
	})
	m := merge(t, baseRecord(), laptop, desktop)
	if string(m.Secret) != "pw-2" || string(m.Notes) != "note from desktop" || !slices.Equal(m.Tags, []string{"code", "home", "work"}) ||
		len(m.Fields) != 3 || len(m.Conflicts) != 0 || m.Lost != nil || len(m.History) != 1 {
		t.Errorf("merged %+v, conflicts %q", m.Record, m.Conflicts)
	}
}

// What both changed their own ways is the newer's, noted; the older's
// secret goes into the history, replaced when and where the newer was
// made.
func TestMerge_BothChangedTheSame(t *testing.T) {
	older := changed("laptop", 1, func(r *Record) {
		r.Secret, r.Updated, r.Notes, r.Folder = []byte("laptop-pw"), t0.Add(time.Hour), []byte("laptop"), "a"
		r.Fields[0].Value = []byte("l")
	})
	newer := changed("desktop", 2, func(r *Record) {
		r.Secret, r.Updated, r.Notes, r.Folder = []byte("desktop-pw"), t0.Add(2*time.Hour), []byte("desktop"), "b"
		r.Fields[0].Value = []byte("d")
	})
	m := merge(t, baseRecord(), older, newer)
	if string(m.Secret) != "desktop-pw" || !m.Updated.Equal(t0.Add(2*time.Hour)) || string(m.Notes) != "desktop" || m.Folder != "b" || string(m.Fields[0].Value) != "d" {
		t.Errorf("merged %+v", m.Record)
	}
	if !slices.Equal(sorted(m.Conflicts), []string{"field pin", "folder", "notes", "secret"}) || string(m.Lost) != "laptop-pw" {
		t.Errorf("conflicts %q, lost %q", m.Conflicts, m.Lost)
	}
	if len(m.History) != 2 || string(m.History[0].Secret) != "laptop-pw" || !m.History[0].ReplacedAt.Equal(newer.Changed) || m.History[0].Computer != "desktop" ||
		string(m.History[1].Secret) != "pw-0" {
		t.Errorf("history %+v", m.History)
	}
	// Changed at the same moment: still one the same both ways round.
	newer.Changed = older.Changed
	merge(t, baseRecord(), older, newer)
}

// Both making the same change isn't a conflict.
func TestMerge_BothMadeTheSameChange(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) {
		r.Secret, r.Notes, r.Updated, r.Created = []byte("pw-2"), []byte("n2"), t0.Add(time.Hour), t0.Add(-time.Hour)
	})
	b := changed("desktop", 2, func(r *Record) { r.Secret, r.Notes, r.Updated = []byte("pw-2"), []byte("n2"), t0.Add(2*time.Hour) })
	if m := merge(t, baseRecord(), a, b); len(m.Conflicts) != 0 || m.Lost != nil || string(m.Secret) != "pw-2" || len(m.History) != 1 {
		t.Errorf("merged %+v, conflicts %q", m.Record, m.Conflicts)
	} else if !m.Updated.Equal(t0.Add(2*time.Hour)) || !m.Created.Equal(t0.Add(-time.Hour)) {
		// Updated when the secret last changed; made when first made.
		t.Errorf("updated %v, created %v", m.Updated, m.Created)
	}
}

// Tags and fields merge one by one: one added here and one removed there
// both hold; fields are told apart by name in any case.
func TestMerge_TagsAndFields(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) {
		r.Tags = []string{"code", "work", "x"}
		r.Fields = []Field{{Name: "PIN", Value: []byte("1111"), Secret: true}, {Name: "team", Value: []byte("core")}, {Name: "a", Value: []byte("1")}}
	})
	b := changed("desktop", 2, func(r *Record) {
		r.Tags = []string{"code"}
		r.Fields = []Field{{Name: "pin", Value: []byte("1111"), Secret: true}}
	})
	m := merge(t, baseRecord(), a, b)
	if !slices.Equal(m.Tags, []string{"code", "x"}) {
		t.Errorf("tags %q", m.Tags)
	}
	// "PIN" (renamed by case on the laptop) and "pin" (left on the
	// desktop) are one field: the laptop's; team removed on the desktop; a
	// added on the laptop.
	names := func(fs []Field) (out []string) {
		for _, f := range fs {
			out = append(out, f.Name)
		}
		return out
	}
	if got := names(m.Fields); !slices.Equal(got, []string{"PIN", "a"}) || len(m.Conflicts) != 0 {
		t.Errorf("fields %q, conflicts %q", got, m.Conflicts)
	}
	// The desktop changing it too: both changed it, the newer's.
	b.Fields[0].Value = []byte("2222")
	m = merge(t, baseRecord(), a, b)
	if got := names(m.Fields); !slices.Equal(got, []string{"pin", "a"}) || string(m.Fields[0].Value) != "2222" || !slices.Equal(m.Conflicts, []string{"field pin"}) {
		t.Errorf("fields %q, conflicts %q", got, m.Conflicts)
	}
}

// Earlier secrets either has are kept, each once; those either forgot are
// gone, though the other still has them.
func TestMerge_History(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) {
		r.History = append([]Earlier{{ReplacedAt: t0.Add(time.Hour), Computer: "laptop", Secret: []byte("pw-1")}}, r.History...)
		r.Secret = []byte("pw-2")
	})
	b := changed("desktop", 2, func(r *Record) { r.History = nil })
	m := merge(t, baseRecord(), a, b)
	if len(m.History) != 1 || string(m.History[0].Secret) != "pw-1" {
		t.Errorf("history %+v", m.History)
	}
	// Both kept the same new one: once.
	c := changed("desktop", 2, func(r *Record) {
		r.History = append([]Earlier{{ReplacedAt: t0.Add(time.Hour), Computer: "laptop", Secret: []byte("pw-1")}}, r.History...)
		r.Secret = []byte("pw-2")
	})
	if m := merge(t, baseRecord(), a, c); len(m.History) != 2 {
		t.Errorf("history %+v", m.History)
	}
}

// An entry deleted on one computer and left on the other is deleted; edited
// on the other, it comes back with the edit; restored on one, it's back.
func TestMerge_Trash(t *testing.T) {
	deleted := changed("laptop", 1, func(r *Record) { r.Deleted = t0.Add(time.Hour) })
	if m := merge(t, baseRecord(), deleted, baseRecord()); !m.Deleted.Equal(t0.Add(time.Hour)) {
		t.Errorf("deleted, left: %+v", m.Record)
	}
	edited := changed("desktop", 2, func(r *Record) { r.Notes = []byte("edited") })
	if m := merge(t, baseRecord(), deleted, edited); !m.Deleted.IsZero() || string(m.Notes) != "edited" {
		t.Errorf("deleted, edited: %+v", m.Record)
	}
	both := changed("desktop", 2, func(r *Record) { r.Deleted = t0.Add(2 * time.Hour) })
	if m := merge(t, baseRecord(), deleted, both); !m.Deleted.Equal(t0.Add(time.Hour)) {
		t.Errorf("deleted on both: %v, want the earlier", m.Deleted)
	}
	inTrash := baseRecord()
	inTrash.Deleted = t0
	restored := changed("laptop", 1, func(r *Record) { r.Deleted = time.Time{} })
	still := changed("desktop", 2, func(r *Record) { r.Deleted = t0 })
	if m := merge(t, inTrash, restored, still); !m.Deleted.IsZero() {
		t.Errorf("restored, left in the trash: %v", m.Deleted)
	}
}

// An entry deleted for good on one computer is gone, unless the other
// edited or restored it: then it comes back as the other has it.
func TestMerge_Purged(t *testing.T) {
	purged := &Record{Purged: t0.Add(time.Hour), Computer: "laptop", Changed: t0.Add(time.Hour), Version: 4}
	if m := merge(t, baseRecord(), purged, baseRecord()); !m.Purged.Equal(purged.Purged) || m.Service != "" {
		t.Errorf("purged, left: %+v", m.Record)
	}
	edited := changed("desktop", 2, func(r *Record) { r.Notes = []byte("edited") })
	if m := merge(t, baseRecord(), purged, edited); !m.Purged.IsZero() || string(m.Notes) != "edited" || m.Service != "github" {
		t.Errorf("purged, edited: %+v", m.Record)
	}
	inTrash := baseRecord()
	inTrash.Deleted = t0
	restored := changed("desktop", 2, func(r *Record) {})
	if m := merge(t, inTrash, purged, restored); !m.Purged.IsZero() || m.Service != "github" || !m.Deleted.IsZero() {
		t.Errorf("purged, restored: %+v", m.Record)
	}
	later := &Record{Purged: t0.Add(3 * time.Hour), Computer: "desktop", Changed: t0.Add(3 * time.Hour), Version: 4}
	if m := merge(t, baseRecord(), purged, later); !m.Purged.Equal(purged.Purged) {
		t.Errorf("purged on both: %v, want the earlier", m.Purged)
	}
}

// With nothing synced before, what one has and the other doesn't is
// taken, and differing secrets are a conflict the newer wins.
func TestMerge_NoBase(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) { r.Notes = nil })
	b := changed("desktop", 2, func(r *Record) { r.Secret = []byte("other") })
	m := merge(t, nil, a, b)
	if string(m.Notes) != "notes" || string(m.Secret) != "other" || string(m.Lost) != "pw-1" {
		t.Errorf("merged %+v, lost %q", m.Record, m.Lost)
	}
}

// The merged entry shares nothing with the versions merged: wiping them
// leaves it whole.
func TestMerge_SharesNothing(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) { r.Secret = []byte("pw-2") })
	b := changed("desktop", 2, func(r *Record) { r.Notes = []byte("n") })
	base := baseRecord()
	m := Merge(base, a, b)
	for _, r := range []*Record{base, a, b} {
		r.Wipe()
	}
	if string(m.Secret) != "pw-2" || string(m.Notes) != "n" || string(m.Fields[0].Value) != "1111" || string(m.History[0].Secret) != "pw-0" {
		t.Errorf("after the versions were wiped: %+v", m.Record)
	}
	p := Merge(base, &Record{Purged: t0, Version: 9}, changed("desktop", 2, func(r *Record) { r.Secret = []byte("kept") }))
	b.Wipe()
	if string(p.Secret) != "kept" {
		t.Errorf("came back: %q", p.Secret)
	}
}
