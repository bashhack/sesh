package syncfolder

import (
	"slices"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

func typedRecord() *Record {
	return &Record{Kind: vault.KindPassword, Service: "github", Username: "alice", Secret: []byte("pw-1"), Notes: []byte("n"),
		URL: "https://github.com", Tags: []string{"work"}, Fields: []Field{{Name: "pin", Value: []byte("1234"), Secret: true}},
		Changed: time.Unix(100, 0), Versions: Versions{"l": 1}}
}

// Diff keeps only what changed: the typed values, and hashes of what
// they replaced where that's secret.
func TestDiff(t *testing.T) {
	pre := typedRecord()
	post := typedRecord()
	post.Notes, post.Tags = []byte("typed notes"), []string{"home"}
	post.Fields = []Field{{Name: "PIN", Value: []byte("9999"), Secret: true}}
	post.Changed = time.Unix(200, 0)
	d := Diff(pre, post)
	want := []string{"notes", "field:pin", "tag:home", "tag:work"}
	if !slices.Equal(d.Keys, want) {
		t.Fatalf("keys %q, want %q", d.Keys, want)
	}
	if d.Post.Secret != nil || d.Post.URL != "" || string(d.Post.Notes) != "typed notes" || d.Hash["notes"] != Forget([]byte("n")) {
		t.Errorf("post %+v hash %v: want the notes typed only, the old notes hashed", d.Post, d.Hash)
	}
	if !slices.Equal(d.Post.Tags, []string{"home"}) || d.Created {
		t.Errorf("tags %q, created %v", d.Post.Tags, d.Created)
	}
	if made := Diff(nil, post); !made.Created || !made.Has("secret") || !made.Has("name") {
		t.Errorf("made here: %+v", made)
	}
	gone := Diff(pre, &Record{Purged: time.Unix(300, 0)})
	if !slices.Equal(gone.Keys, []string{"purged"}) || !slices.Equal(gone.Contents, []string{ContentHash(pre)}) || gone.Post.Secret != nil {
		t.Errorf("deleted for good: %+v", gone)
	}
}

// Rebase makes only what was typed again on another version: what the
// version had untyped, forged or not, is its own's, and a typed value
// replacing one it no longer holds settles as a conflict.
func TestRebase(t *testing.T) {
	forged := typedRecord()
	forged.Secret, forged.URL = []byte("evil"), "https://evil.example"
	typed := typedRecord()
	typed.Secret, typed.URL = []byte("evil"), "https://evil.example"
	typed.Notes = []byte("typed notes")
	typed.Changed = time.Unix(300, 0)
	tv := Diff(forged, typed)

	folder := typedRecord()
	folder.Notes = []byte("n")
	folder.Changed = time.Unix(200, 0)
	base, ours := tv.Rebase(folder)
	m := Merge(base, ours, folder)
	if string(m.Secret) != "pw-1" || m.URL != "https://github.com" || string(m.Notes) != "typed notes" {
		t.Errorf("merged %q %q %q: want the folder's secret and URL, the typed notes", m.Secret, m.URL, m.Notes)
	}
	if hasEarlier(m.History, []byte("evil")) {
		t.Errorf("history %v has the forged secret", m.History)
	}

	// The folder changed the notes since: both kept, the newer first.
	folder.Notes, folder.Computer = []byte("laptop notes"), "laptop"
	base, ours = tv.Rebase(folder)
	m = Merge(base, ours, folder)
	if want := "typed notes\n\n— from laptop, 1970-01-01 00:03 UTC —\nlaptop notes"; string(m.Notes) != want {
		t.Errorf("notes %q, want %q", m.Notes, want)
	}

	// A typed secret wins over the folder's, which goes into the history.
	typed.Secret = []byte("desk-2")
	tv = Diff(forged, typed)
	base, ours = tv.Rebase(folder)
	m = Merge(base, ours, folder)
	if string(m.Secret) != "desk-2" || !hasEarlier(m.History, []byte("pw-1")) || hasEarlier(m.History, []byte("evil")) {
		t.Errorf("secret %q history %v: want desk-2, pw-1 kept, nothing forged", m.Secret, m.History)
	}

	// The folder's secret changed later than the typed one: the folder's is
	// kept, the typed one in the history.
	folder.Secret, folder.Changed = []byte("pw-9"), time.Unix(400, 0)
	base, ours = tv.Rebase(folder)
	m = Merge(base, ours, folder)
	if string(m.Secret) != "pw-9" || !hasEarlier(m.History, []byte("desk-2")) {
		t.Errorf("secret %q history %v: want the later pw-9, desk-2 kept", m.Secret, m.History)
	}
}

// Fold keeps each typed value in the latest that typed it, drops what a
// deletion for good or a forget leaves nothing of.
func TestFold(t *testing.T) {
	a, b, c := typedRecord(), typedRecord(), typedRecord()
	b.Notes, b.Secret = []byte("one"), []byte("pw-2")
	c.Notes, c.Secret = []byte("two"), []byte("pw-2")
	t1, t2 := Diff(a, b), Diff(b, c)
	t1.N, t2.N = 1, 2
	all := Fold([]*Typed{t1}, t2)
	if len(all) != 2 || !slices.Equal(all[0].Keys, []string{"secret"}) || all[0].Post.Notes != nil {
		t.Fatalf("folded %+v: want the first keeping only its secret", all)
	}
	if all[1].Hash["notes"] != Forget([]byte("n")) {
		t.Errorf("the second's replaced notes %q: want the first's replaced, as nothing came between", all[1].Hash["notes"])
	}

	d := typedRecord()
	d.Secret, d.Notes = []byte("pw-2"), []byte("two")
	d.Forgotten = []Forgotten{{Hash: Forget([]byte("pw-2")), At: time.Unix(400, 0)}}
	t3 := Diff(c, d)
	all = Fold(all, t3)
	if len(all) != 2 || all[0].N != 2 {
		t.Errorf("after forgetting pw-2: %+v, want the first, which typed it, dropped", all)
	}

	gone := Diff(d, &Record{Purged: time.Unix(500, 0)})
	if all = Fold(all, gone); len(all) != 1 || !all[0].Has("purged") {
		t.Errorf("after a deletion for good: %+v, want it alone", all)
	}
}
