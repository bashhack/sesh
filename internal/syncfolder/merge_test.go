package syncfolder

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// baseRecord is an entry as two computers last synced it.
func baseRecord() *Record {
	return &Record{
		Created: t0, Updated: t0, Changed: t0, Computer: "laptop", Versions: Versions{"x": 3},
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
	r.Computer, r.Changed, r.Versions = computer, t0.Add(time.Duration(h)*time.Hour), Versions{"x": 3, computer: 1}
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
		"a field removed": {func(r *Record) { r.Fields = r.Fields[1:] }, func(r *Record) bool { return len(r.Fields) == 1 && r.Fields[0].Name == "team" }},
		"an earlier secret forgotten": {func(r *Record) { r.History, r.Forgotten = nil, []Forgotten{{Hash: Forget([]byte("pw-0")), At: t0}} }, func(r *Record) bool {
			return len(r.History) == 0 && slices.Equal(r.Forgotten, []Forgotten{{Hash: Forget([]byte("pw-0")), At: t0}})
		}},
		// Trimmed to a shorter history.keep isn't forgotten: the other's
		// stays.
		"an earlier secret trimmed": {func(r *Record) { r.History = nil }, func(r *Record) bool { return len(r.History) == 1 }},
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
		// The secret replaced goes into the history too, whatever the other
		// computer's history kept.
		wantHistory := 1
		if name == "secret" {
			wantHistory = 2
		}
		if name != "an earlier secret forgotten" && len(m.History) != wantHistory {
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
		len(m.Fields) != 3 || len(m.Conflicts) != 0 || m.Lost != nil || len(m.History) != 2 {
		t.Errorf("merged %+v, conflicts %q", m.Record, m.Conflicts)
	}
}

// What both changed their own ways is the newer's, noted; nothing secret
// of the older's is lost: its secret goes into the history (replaced when
// and where the newer was made), its notes below the newer's, its secret
// field beside the newer's.
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
	if string(m.Secret) != "desktop-pw" || !m.Updated.Equal(t0.Add(2*time.Hour)) || m.Folder != "b" || string(m.Fields[0].Value) != "d" {
		t.Errorf("merged %+v", m.Record)
	}
	if want := "desktop\n\n— from laptop, 2026-10-01 01:00 UTC —\nlaptop"; string(m.Notes) != want {
		t.Errorf("notes %q, want %q", m.Notes, want)
	}
	if len(m.Fields) != 3 || m.Fields[2].Name != "pin-laptop" || string(m.Fields[2].Value) != "l" || !m.Fields[2].Secret {
		t.Errorf("fields %+v", m.Fields)
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

// Earlier secrets either has are kept, each use once; those either forgot
// are gone, though the other still has them.
func TestMerge_History(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) {
		r.History = append([]Earlier{{ReplacedAt: t0.Add(time.Hour), SetAt: t0, Computer: "laptop", Secret: []byte("pw-1")}}, r.History...)
		r.Secret = []byte("pw-2")
	})
	b := changed("desktop", 2, func(r *Record) { r.History, r.Forgotten = nil, []Forgotten{{Hash: Forget([]byte("pw-0")), At: t0}} })
	m := merge(t, baseRecord(), a, b)
	if len(m.History) != 1 || string(m.History[0].Secret) != "pw-1" {
		t.Errorf("history %+v", m.History)
	}
	// Both kept the same new one: once.
	c := changed("desktop", 2, func(r *Record) {
		r.History = append([]Earlier{{ReplacedAt: t0.Add(time.Hour), SetAt: t0, Computer: "laptop", Secret: []byte("pw-1")}}, r.History...)
		r.Secret = []byte("pw-2")
	})
	if m := merge(t, baseRecord(), a, c); len(m.History) != 2 {
		t.Errorf("history %+v", m.History)
	}
}

// stale is base as a computer not synced since pw-1 was forgotten changed
// it at hour h: pw-1, set at t0 as base has it, replaced by secret.
func stale(computer string, h int, secret string) *Record {
	return changed(computer, h, func(r *Record) {
		at := t0.Add(time.Duration(h) * time.Hour)
		r.Secret, r.Updated = []byte(secret), at
		r.History = append([]Earlier{{ReplacedAt: at, SetAt: t0, Computer: computer, Secret: []byte("pw-1")}}, r.History...)
	})
}

// forgot is base as the laptop changed it: pw-1 replaced by pw-2 at hour 1,
// then forgotten at hour 2.
func forgot() *Record {
	return changed("laptop", 1, func(r *Record) {
		r.Secret, r.Updated = []byte("pw-2"), t0.Add(time.Hour)
		r.Forgotten = []Forgotten{{Hash: Forget([]byte("pw-1")), At: t0.Add(2 * time.Hour)}}
	})
}

// The secret both had, forgotten on one, stays forgotten though the other
// replaced it after that, not having synced since: with base or without.
func TestMerge_ForgottenThenReplaced(t *testing.T) {
	for name, base := range map[string]*Record{"base": baseRecord(), "no base": nil} {
		m := merge(t, base, forgot(), stale("desktop", 3, "pw-3"))
		if string(m.Secret) != "pw-3" || hasEarlier(m.History, []byte("pw-1")) || !hasEarlier(m.History, []byte("pw-2")) {
			t.Errorf("%s: secret %s, history %+v", name, m.Secret, m.History)
		}
		// The desktop, synced at its own version, takes the merge: its pw-1
		// too is forgotten.
		replaced := stale("desktop", 3, "pw-3")
		if again := merge(t, replaced, replaced, m.Record); hasEarlier(again.History, []byte("pw-1")) {
			t.Errorf("%s: desktop's history %+v", name, again.History)
		}
	}
}

// Two computers replacing the forgotten secret, merged before the
// forgetting reaches either, still forget it, each its own copy.
func TestMerge_ForgottenThenReplacedTwice(t *testing.T) {
	desktop, third := stale("desktop", 3, "pw-3"), stale("third", 4, "pw-4")
	both := merge(t, baseRecord(), desktop, third)
	all := merge(t, baseRecord(), forgot(), both.Record)
	if hasEarlier(all.History, []byte("pw-1")) {
		t.Errorf("history %+v", all.History)
	}
	// The third computer, synced at its own version, still has its copy
	// replaced at hour 4.
	if again := merge(t, third, third, all.Record); hasEarlier(again.History, []byte("pw-1")) {
		t.Errorf("third's history %+v", again.History)
	}
}

// A forgotten secret used again, set after it was forgotten and replaced,
// is kept, beside a stale copy of its use before, forgotten.
func TestMerge_ForgottenUsedAgain(t *testing.T) {
	again := func(r *Record) {
		r.Secret, r.Updated = []byte("pw-new"), t0.Add(4*time.Hour)
		r.History = []Earlier{{ReplacedAt: t0.Add(4 * time.Hour), SetAt: t0.Add(3 * time.Hour), Computer: "laptop", Secret: []byte("pw-1")}}
		r.Forgotten = []Forgotten{{Hash: Forget([]byte("pw-1")), At: t0.Add(90 * time.Minute)}}
	}
	reused := changed("laptop", 4, again)
	tagged := changed("desktop", 5, func(r *Record) { r.Tags = append(r.Tags, "more") })
	for name, other := range map[string]*Record{"tag only": tagged, "stale copy": stale("desktop", 2, "pw-3")} {
		m := merge(t, baseRecord(), reused, other)
		i := slices.IndexFunc(m.History, func(e Earlier) bool { return string(e.Secret) == "pw-1" })
		if i < 0 || !m.History[i].SetAt.Equal(t0.Add(3*time.Hour)) || slices.IndexFunc(m.History[i+1:], func(e Earlier) bool { return string(e.Secret) == "pw-1" }) >= 0 {
			t.Errorf("%s: history %+v", name, m.History)
		}
	}
}

// A secret restored from a backup keeps when the backup had it set: with
// the same secret elsewhere, both ways round; replaced after it was
// forgotten elsewhere, forgotten.
func TestMerge_RestoredSetAt(t *testing.T) {
	restored := changed("desktop", 5, func(r *Record) { r.Updated, r.SetAt = t0.Add(5*time.Hour), t0 })
	if m := merge(t, baseRecord(), restored, baseRecord()); !m.Updated.Equal(t0.Add(5*time.Hour)) || !m.SetAt.Equal(t0) {
		t.Errorf("updated %s, set %s", m.Updated, m.SetAt)
	}
	replaced := changed("laptop", 6, func(r *Record) {
		r.Secret, r.Updated = []byte("pw-9"), t0.Add(6*time.Hour)
		r.Forgotten = []Forgotten{{Hash: Forget([]byte("pw-1")), At: t0.Add(2 * time.Hour)}}
	})
	if m := merge(t, nil, restored, replaced); string(m.Secret) != "pw-9" || hasEarlier(m.History, []byte("pw-1")) {
		t.Errorf("secret %s, history %+v", m.Secret, m.History)
	}
}

// Two uses of one secret are both kept, until one is forgotten: then only
// the use set after.
func TestMerge_HistoryTwoUses(t *testing.T) {
	first := Earlier{ReplacedAt: t0.Add(time.Hour), SetAt: t0, Computer: "desktop", Secret: []byte("pw-1")}
	again := Earlier{ReplacedAt: t0.Add(3 * time.Hour), SetAt: t0.Add(2 * time.Hour), Computer: "desktop", Secret: []byte("pw-1")}
	desktop := changed("desktop", 3, func(r *Record) {
		r.Secret, r.Updated = []byte("pw-3"), t0.Add(3*time.Hour)
		r.History = append([]Earlier{again, first}, r.History...)
	})
	tagged := changed("laptop", 4, func(r *Record) { r.Tags = append(r.Tags, "more") })
	uses := func(m Merged) (n int) {
		for _, e := range m.History {
			if string(e.Secret) == "pw-1" {
				n++
			}
		}
		return n
	}
	if m := merge(t, baseRecord(), desktop, tagged); uses(m) != 2 {
		t.Errorf("history %+v, want both uses of pw-1", m.History)
	}
	tagged.Forgotten = []Forgotten{{Hash: Forget([]byte("pw-1")), At: t0.Add(90 * time.Minute)}}
	if m := merge(t, baseRecord(), desktop, tagged); uses(m) != 1 || !hasEarlier(m.History, []byte("pw-1")) {
		t.Errorf("history %+v, want the use set after the forgetting", m.History)
	}
}

// A forgotten secret's copy with no set time is taken as set when
// replaced: used again later, it's kept.
func TestMerge_ForgottenUsedAgainNoSetTime(t *testing.T) {
	reused := changed("laptop", 4, func(r *Record) {
		r.Secret, r.Updated = []byte("pw-new"), t0.Add(4*time.Hour)
		r.History = []Earlier{{ReplacedAt: t0.Add(4 * time.Hour), Computer: "laptop", Secret: []byte("pw-1")}}
		r.Forgotten = []Forgotten{{Hash: Forget([]byte("pw-1")), At: t0.Add(90 * time.Minute)}}
	})
	tagged := changed("desktop", 5, func(r *Record) { r.Tags = append(r.Tags, "more") })
	if m := merge(t, baseRecord(), reused, tagged); !hasEarlier(m.History, []byte("pw-1")) {
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
	purged := &Record{Purged: t0.Add(time.Hour), Computer: "laptop", Changed: t0.Add(time.Hour), Versions: Versions{"x": 4}}
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
	later := &Record{Purged: t0.Add(3 * time.Hour), Computer: "desktop", Changed: t0.Add(3 * time.Hour), Versions: Versions{"x": 4}}
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
	if string(m.Secret) != "pw-2" || string(m.Notes) != "n" || string(m.Fields[0].Value) != "1111" || !slices.Contains(secrets(m.History), "pw-0") {
		t.Errorf("after the versions were wiped: %+v", m.Record)
	}
	p := Merge(base, &Record{Purged: t0, Versions: Versions{"x": 9}}, changed("desktop", 2, func(r *Record) { r.Secret = []byte("kept") }))
	b.Wipe()
	if string(p.Secret) != "kept" {
		t.Errorf("came back: %q", p.Secret)
	}
}

// sameContent says whether a and b hold the same entry, leaving out who
// made them, when, and their versions.
func sameContent(a, b *Record) bool {
	x, y := *a, *b
	x.Changed, y.Changed, x.Computer, y.Computer, x.Versions, y.Versions = time.Time{}, time.Time{}, "", "", nil, nil
	return recordsEqual(&x, &y) && slices.Equal(x.Forgotten, y.Forgotten)
}

// Once one computer has merged two versions, the other merging that result
// with its own version (as the next sync does) settles on the same entry:
// nothing is added to the history twice, no notes or fields again. Only
// the plain values its own change lost are noted again, to tell it so.
func TestMerge_SettlesOnce(t *testing.T) {
	for name, tc := range map[string]struct{ laptop, desktop func(r *Record) }{
		"secret": {
			func(r *Record) { r.Secret = []byte("laptop-pw") },
			func(r *Record) { r.Secret = []byte("desktop-pw") },
		},
		"notes and a secret field": {
			func(r *Record) { r.Notes, r.Fields[0].Value = []byte("laptop"), []byte("l") },
			func(r *Record) { r.Notes, r.Fields[0].Value = []byte("desktop"), []byte("d") },
		},
		"everything": {
			func(r *Record) {
				r.Secret, r.Notes, r.Folder, r.URL, r.Fields[0].Value = []byte("L"), []byte("ln"), "lf", "lu", []byte("l")
				r.Tags = []string{"x"}
			},
			func(r *Record) {
				r.Secret, r.Notes, r.Folder, r.URL, r.Fields[0].Value = []byte("D"), []byte("dn"), "df", "du", []byte("d")
				r.Tags = []string{"y"}
			},
		},
	} {
		laptop, desktop := changed("laptop", 1, tc.laptop), changed("desktop", 2, tc.desktop)
		m := merge(t, baseRecord(), laptop, desktop)
		// The desktop wrote it, later.
		m.Computer, m.Changed, m.Versions = "desktop", t0.Add(3*time.Hour), m.Versions.Next("desktop")
		for side, mine := range map[string]*Record{"laptop": laptop, "desktop": desktop} {
			again := merge(t, baseRecord(), mine, m.Record)
			if !sameContent(again.Record, m.Record) || slices.Contains(again.Conflicts, "secret") || slices.Contains(again.Conflicts, "notes") || again.Lost != nil {
				t.Errorf("%s, merged again on the %s: conflicts %q, lost %q\n%+v\nwant %+v", name, side, again.Conflicts, again.Lost, again.Record, m.Record)
			}
		}
		// And against itself, nothing changes.
		if again := merge(t, m.Record, m.Record, m.Record); !sameContent(again.Record, m.Record) || len(again.Conflicts) != 0 {
			t.Errorf("%s, merged with itself: %+v", name, again.Record)
		}
	}
}

// A file entry's name goes with its file: the newer's file comes with the
// newer's name, the older's name into the history with its file.
func TestMerge_FileNameGoesWithItsFile(t *testing.T) {
	base := baseRecord()
	base.Kind, base.Secret, base.Settings.FileName = vault.KindFile, []byte("A"), "a.pdf"
	laptop := copyOf(base).Record
	laptop.Computer, laptop.Changed, laptop.Secret, laptop.Settings.FileName = "laptop", t0.Add(time.Hour), []byte("B"), "b.pdf"
	desktop := copyOf(base).Record
	desktop.Computer, desktop.Changed, desktop.Secret = "desktop", t0.Add(2*time.Hour), []byte("A2")
	m := merge(t, base, laptop, desktop)
	if string(m.Secret) != "A2" || m.Settings.FileName != "a.pdf" {
		t.Errorf("file %q named %q, want A2 named a.pdf", m.Secret, m.Settings.FileName)
	}
	if !slices.ContainsFunc(m.History, func(e Earlier) bool { return string(e.Secret) == "B" && e.FileName == "b.pdf" }) {
		t.Errorf("history %+v: want B, named b.pdf", m.History)
	}
	// Only the name changed on one: that name.
	renamed := copyOf(base).Record
	renamed.Computer, renamed.Changed, renamed.Settings.FileName = "laptop", t0.Add(time.Hour), "c.pdf"
	if m := merge(t, base, renamed, copyOf(base).Record); m.Settings.FileName != "c.pdf" {
		t.Errorf("renamed: %q", m.Settings.FileName)
	}
}

// Code settings merge each on its own: an MFA device set on one and the
// codes' digits on the other both hold.
func TestMerge_SettingsEachOnItsOwn(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) { r.Settings.AWSMFADevice = "arn:aws:iam::1:mfa/x" })
	b := changed("desktop", 2, func(r *Record) { r.Settings.TOTP.Digits = 8 })
	if m := merge(t, baseRecord(), a, b); m.Settings.AWSMFADevice != "arn:aws:iam::1:mfa/x" || m.Settings.TOTP.Digits != 8 || len(m.Conflicts) != 0 {
		t.Errorf("settings %+v, conflicts %q", m.Settings, m.Conflicts)
	}
}

// An earlier secret both have, replaced at different times or on different
// computers, is kept once: the first time it was replaced.
func TestMerge_HistoryEachSecretOnce(t *testing.T) {
	a := changed("laptop", 1, func(r *Record) {
		r.Secret = []byte("pw-2")
		r.History = append([]Earlier{{ReplacedAt: t0.Add(time.Hour), Computer: "laptop", FileName: "a.txt", Secret: []byte("pw-1")}}, r.History...)
	})
	b := changed("desktop", 2, func(r *Record) {
		r.Secret = []byte("pw-2")
		r.History = append([]Earlier{{ReplacedAt: t0.Add(2 * time.Hour), Computer: "desktop", FileName: "b.txt", Secret: []byte("pw-1")}}, r.History...)
	})
	m := merge(t, baseRecord(), a, b)
	if len(m.History) != 2 || string(m.History[0].Secret) != "pw-1" || m.History[0].Computer != "laptop" || string(m.History[1].Secret) != "pw-0" {
		t.Errorf("history %+v", m.History)
	}
	// The same time and file name, other computers: one, the same either
	// way round.
	b.History[0].ReplacedAt, b.History[0].FileName = t0.Add(time.Hour), "a.txt"
	merge(t, baseRecord(), a, b)
}

// Two versions alike in time, computer and version, but not in what they
// hold, are still ordered the same either way round.
func TestMerge_FullTie(t *testing.T) {
	a := changed("mac", 1, func(r *Record) { r.Secret = []byte("one") })
	b := changed("mac", 1, func(r *Record) { r.Secret = []byte("two") })
	merge(t, baseRecord(), a, b)
}

// Deleted for good on one, edited then moved to the trash on the other: it
// comes back, in the trash, as the other has it.
func TestMerge_PurgedAgainstEditedInTheTrash(t *testing.T) {
	purged := &Record{Purged: t0.Add(time.Hour), Computer: "laptop", Changed: t0.Add(time.Hour), Versions: Versions{"x": 4}}
	trashed := changed("desktop", 2, func(r *Record) { r.Notes, r.Deleted = []byte("edited"), t0.Add(2*time.Hour) })
	if m := merge(t, baseRecord(), purged, trashed); !m.Purged.IsZero() || !m.Deleted.Equal(t0.Add(2*time.Hour)) || string(m.Notes) != "edited" {
		t.Errorf("merged %+v", m.Record)
	}
}

func secrets(hs []Earlier) (out []string) {
	for _, h := range hs {
		out = append(out, string(h.Secret))
	}
	return out
}

// A field kept beside another is named so fields can have it: the
// computer's name made fit, short enough, numbered when taken; with all
// the fields an entry can have, it goes into the notes.
func TestMerge_KeptBesideFits(t *testing.T) {
	for _, tc := range []struct{ name, computer, want string }{
		{"pin", "Marc's MacBook Pro", "pin-Marc-s-MacBook-Pro"},
		{"pin", "(())", "pin-other"},
		{strings.Repeat("p", 64), "laptop", strings.Repeat("p", 57) + "-laptop"},
	} {
		got := besideName(tc.name, tc.computer, nil)
		if got != tc.want || vault.CheckFieldName(got) != nil {
			t.Errorf("besideName(%q, %q) = %q (%v), want %q", tc.name, tc.computer, got, vault.CheckFieldName(got), tc.want)
		}
	}
	if got := besideName("pin", "laptop", []Field{{Name: "PIN-laptop"}}); got != "pin-laptop-2" {
		t.Errorf("taken: %q", got)
	}
	full := func(computer string, h int, v string) *Record {
		return changed(computer, h, func(r *Record) {
			r.Fields = nil
			for i := range vault.MaxFields {
				r.Fields = append(r.Fields, Field{Name: fmt.Sprintf("f%d", i), Value: []byte("x"), Secret: true})
			}
			r.Fields[0].Value = []byte(v)
		})
	}
	base := full("laptop", 0, "x")
	base.Notes = []byte("notes")
	m := merge(t, base, full("laptop", 1, "l"), full("desktop", 2, "d"))
	if len(m.Fields) != vault.MaxFields || string(m.Fields[0].Value) != "d" || !strings.Contains(string(m.Notes), "— f0-laptop —\nl") {
		t.Errorf("fields %d, notes %q", len(m.Fields), m.Notes)
	}
}

// One secret on both sides, updated at the same moment from different
// starts: the same record whichever side is ours, the later start kept.
func TestMerge_SameSecretSameUpdate(t *testing.T) {
	restored := changed("desktop", 5, func(r *Record) { r.Updated, r.SetAt = t0.Add(5*time.Hour), t0 })
	typed := changed("laptop", 6, func(r *Record) { r.Updated = t0.Add(5 * time.Hour) })
	if m := merge(t, baseRecord(), restored, typed); !m.Began().Equal(t0.Add(5 * time.Hour)) {
		t.Errorf("began %s", m.Began())
	}
}
