package vaultsync

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// lateWorld is two computers after the laptop changed the master password
// and sealed the folder's files again with the new key; the desktop hasn't
// taken the change. oldKey and oldID are the old key and its record's ID.
func lateWorld(t *testing.T) (laptop, desktop *computer, f syncfolder.Folder, gh vault.Key, rec database.UnlockMaterial, oldKey []byte, oldID string) {
	t.Helper()
	l, d, folder := twoComputers(t)
	gh = l.put("github", "pw-1")
	settle(t, folder, l, d)
	old, err := database.ReadUnlockMaterial(l.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	laptop, rec = changeKey(t, l, "correct horse battery", "the new password 1")
	syncOlder(t, laptop, folder)
	return laptop, d, folder, gh, rec, database.DeriveKey([]byte("correct horse battery"), old.Salt, old.Params), database.UnlockID(old.Verify)
}

// forge writes, as someone with the old password could, c's agreed
// version of the entry uid as change makes it, sealed with the old key, in
// place of the entry's file.
func forge(t *testing.T, c *computer, f syncfolder.Folder, uid string, oldKey []byte, oldID string, change func(*syncfolder.Record)) {
	t.Helper()
	rec, err := c.store.SyncBase(uid)
	if err != nil {
		t.Fatal(err)
	}
	change(rec)
	rec.Changed = time.Now()
	sealOld(t, f, uid+".sesh", uid, rec, oldKey, oldID)
}

// computerID is c's sync ID.
func computerID(t *testing.T, c *computer) string {
	t.Helper()
	id, err := c.store.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// noEvil fails t if "evil" is any computer's secret, current or earlier.
func noEvil(t *testing.T, cs ...*computer) {
	t.Helper()
	for _, c := range cs {
		if slices.Contains(allSecrets(t, c), "evil") {
			t.Errorf("%s has the forged secret: %q", c.name, allSecrets(t, c))
		}
	}
}

// switchDesktop has the desktop take the laptop's change, and syncs it.
func switchDesktop(t *testing.T, laptop, desktop *computer, f syncfolder.Folder, rec database.UnlockMaterial) (*computer, *Summary) {
	t.Helper()
	d := takeKey(t, desktop, laptop, rec, "the new password 1")
	return d, syncOlder(t, d, f)
}

// A change forged under the old key and taken before the change is set
// back to the folder's on taking it, whatever its counts, and goes nowhere.
func TestSync_LateSwitchSetsBackAForgery(t *testing.T) {
	t.Parallel()
	for _, as := range []string{"made up", "laptop", "desktop"} {
		t.Run(as, func(t *testing.T) {
			laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
			uid := liveUID(t, desktop, gh)
			id := map[string]string{"made up": "0123456789abcdef", "laptop": computerID(t, laptop), "desktop": computerID(t, desktop)}[as]
			forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
				r.Secret = []byte("evil")
				r.Versions = r.Versions.Join(syncfolder.Versions{id: r.Versions[id] + 1000})
			})
			desktop.sync(f)
			if got := desktop.secret(gh); got != "evil" {
				t.Fatalf("desktop on the old key: %q, want the forgery taken", got)
			}
			syncOlder(t, laptop, f)
			desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
			if !slices.Equal(s.SetBack, []string{gh.String()}) || len(s.Sent) != 0 {
				t.Errorf("desktop taking the change: %+v, want github set back", s)
			}
			settleOlder(t, f, laptop, desktopNew)
			for _, c := range []*computer{laptop, desktopNew} {
				if got := c.secret(gh); got != "pw-1" {
					t.Errorf("%s: %q, want pw-1", c.name, got)
				}
			}
			noEvil(t, laptop, desktopNew)
		})
	}
}

// A forgery with the very counts of a real change made under the new key
// is set back too: counts don't say whose a change is.
func TestSync_LateSwitchForgeryAtTheRealCount(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	laptop.put("github", "pw-2")
	syncOlder(t, laptop, f)
	real, _, err := laptop.store.SyncRecord(uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	base, err := laptop.store.SyncBase(uid)
	if err != nil {
		t.Fatal(err)
	}
	forged := real
	forged.Secret, forged.URL, forged.Versions = []byte("evil"), "https://evil.example", base.Versions
	sealOld(t, f, uid+".sesh", uid, forged, oldKey, oldID)
	desktop.sync(f)
	if got := desktop.secret(gh); got != "evil" {
		t.Fatalf("desktop on the old key: %q, want the forgery taken", got)
	}
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "pw-2" {
			t.Errorf("%s: %q, want pw-2", c.name, got)
		}
		d, err := c.store.Details(gh, "test")
		if err != nil {
			t.Fatal(err)
		}
		if d.URL != "" {
			t.Errorf("%s: URL %q, want none", c.name, d.URL)
		}
	}
	noEvil(t, laptop, desktopNew)
}

// A deletion for good forged under the old key is undone, whether the
// laptop writes the entry over before or after the desktop takes the change.
func TestSync_LateSwitchSetsBackADeletion(t *testing.T) {
	t.Parallel()
	for _, laptopFirst := range []bool{true, false} {
		laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
		uid := liveUID(t, desktop, gh)
		forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
			*r = syncfolder.Record{Purged: time.Now(), Versions: r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})}
		})
		desktop.sync(f)
		if slices.Contains(names(desktop), "github") {
			t.Fatal("desktop on the old key: the deletion not taken")
		}
		if laptopFirst {
			syncOlder(t, laptop, f)
		}
		desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
		if len(s.Sent) != 0 {
			t.Errorf("laptop first %v: desktop sent %q", laptopFirst, s.Sent)
		}
		settleOlder(t, f, laptop, desktopNew)
		for _, c := range []*computer{laptop, desktopNew} {
			if got := c.secret(gh); got != "pw-1" {
				t.Errorf("laptop first %v: %s: %q, want github back as pw-1", laptopFirst, c.name, got)
			}
		}
	}
}

// An edit typed over a forgery, and sent under the old key, is made again
// on the folder's version: the edit reaches the others, the forgery doesn't.
func TestSync_LateSwitchEditOverAForgery(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret, r.URL = []byte("evil"), "https://evil.example"
		r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	})
	desktop.sync(f)
	notes := "my notes"
	if _, err := desktop.store.Edit(gh, database.EntryEdit{Details: &vault.DetailsChange{SetNotes: true, Notes: []byte(notes)}}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
	if len(s.Sent) != 1 {
		t.Errorf("desktop taking the change: %+v, want its edit sent", s)
	}
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		d, err := c.store.Details(gh, "test")
		if err != nil {
			t.Fatal(err)
		}
		if got := c.secret(gh); got != "pw-1" || string(d.Notes) != notes || d.URL != "" {
			t.Errorf("%s: %q, notes %q, URL %q; want pw-1, the desktop's notes, no URL", c.name, got, d.Notes, d.URL)
		}
	}
	noEvil(t, laptop, desktopNew)
}

// Edits made on a computer before it takes the change, sent under the old
// key or not sent at all, reach the others once it does: the secret, notes
// and fields.
func TestSync_LateSwitchOwnEditsKept(t *testing.T) {
	t.Parallel()
	for _, sent := range []bool{true, false} {
		laptop, desktop, f, gh, rec, _, _ := lateWorld(t)
		desktop.put("github", "desk-2")
		change := vault.DetailsChange{SetNotes: true, Notes: []byte("my notes"), Set: []vault.Field{{Name: "recovery", Value: []byte("codes-123"), Secret: true}}}
		if _, err := desktop.store.Edit(gh, database.EntryEdit{Details: &change}); err != nil {
			t.Fatal(err)
		}
		if sent {
			desktop.sync(f)
		}
		desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
		if len(s.SetBack)+len(s.HeldBack) != 0 {
			t.Errorf("sent %v: desktop taking the change: %+v, want nothing set or held back", sent, s)
		}
		settleOlder(t, f, laptop, desktopNew)
		for _, c := range []*computer{laptop, desktopNew} {
			d, err := c.store.Details(gh, "reading")
			if err != nil {
				t.Fatal(err)
			}
			field := ""
			if len(d.Fields) == 1 {
				field = d.Fields[0].Name + "=" + string(d.Fields[0].Value)
			}
			if got := c.secret(gh); got != "desk-2" || string(d.Notes) != "my notes" || field != "recovery=codes-123" {
				t.Errorf("sent %v: %s: %q, notes %q, field %q; want the desktop's edits", sent, c.name, got, d.Notes, field)
			}
		}
	}
}

// A deletion for good typed under the old key stands once the computer
// takes the change.
func TestSync_LateSwitchOwnPurge(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, _, _ := lateWorld(t)
	if err := desktop.store.PurgeMany([]vault.Key{gh}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if slices.Contains(names(c), "github") {
			t.Errorf("%s has github, deleted for good on the desktop", c.name)
		}
	}
}

// A new secret then the old one forgotten, both under the old key: the
// new one reaches the others, and the old one is forgotten there.
func TestSync_LateSwitchEditThenForget(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, _, _ := lateWorld(t)
	desktop.put("github", "desk-2")
	desktop.sync(f)
	if err := desktop.store.ForgetVersions(gh, 2); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "desk-2" {
			t.Errorf("%s: %q, want desk-2", c.name, got)
		}
		if slices.Contains(allSecrets(t, c), "pw-1") {
			t.Errorf("%s still has pw-1, forgotten on the desktop: %q", c.name, allSecrets(t, c))
		}
	}
}

// Earlier secrets forgotten in a forgery are kept: the entry's forget
// marks are the folder's once the change is taken.
func TestSync_LateSwitchForgedForget(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	laptop.put("github", "pw-2")
	syncOlder(t, laptop, f)
	base, err := laptop.store.SyncBase(uid)
	if err != nil {
		t.Fatal(err)
	}
	h := syncfolder.Forget([]byte("pw-1"))
	base.Forgotten = []syncfolder.Forgotten{{Hash: h, At: time.Now().AddDate(100, 0, 0)}}
	base.Versions = base.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	sealOld(t, f, uid+".sesh", uid, base, oldKey, oldID)
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	desktopNew.put("github", "desk-3")
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if !slices.Contains(allSecrets(t, c), "pw-1") {
			t.Errorf("%s: pw-1 forgotten by the forgery: %q", c.name, allSecrets(t, c))
		}
	}
}

// Deleted for good under the new key after the change: that stands over a
// forgery and an edit typed on it.
func TestSync_LateSwitchDeletedElsewhere(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret = []byte("evil")
		r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	})
	desktop.sync(f)
	if _, err := desktop.store.Edit(gh, database.EntryEdit{Details: &vault.DetailsChange{SetNotes: true, Notes: []byte("typed")}}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	if err := laptop.store.PurgeMany([]vault.Key{gh}); err != nil {
		t.Fatal(err)
	}
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if slices.Contains(names(c), "github") {
			t.Errorf("%s has github, deleted for good on the laptop", c.name)
		}
	}
	noEvil(t, laptop, desktopNew)
}

// An entry made on a computer behind the change, taken by another behind
// it, reaches the others from the one that made it, not the one that took
// it; that one holds it back until then.
func TestSync_LateSwitchBetweenLateComputers(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs...)
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	syncOlder(t, laptop, f)
	bank := cs[2].put("bank", "third-2")
	cs[2].sync(f)
	cs[1].sync(f)
	if got := cs[1].secret(bank); got != "third-2" {
		t.Fatalf("desktop on the old key: %q, want the third's entry", got)
	}
	syncOlder(t, laptop, f)
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	if s := syncOlder(t, desktop, f); !slices.Equal(s.HeldBack, []string{bank.String()}) || len(s.Sent) != 0 {
		t.Errorf("desktop taking the change: %+v, want bank held back", s)
	}
	syncOlder(t, laptop, f)
	if slices.Contains(names(laptop), "bank") {
		t.Error("laptop has bank before the third takes the change")
	}
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	syncOlder(t, third, f)
	settleOlder(t, f, laptop, desktop, third)
	for _, c := range []*computer{laptop, desktop, third} {
		if got := c.secret(bank); got != "third-2" {
			t.Errorf("%s: %q, want the third's entry", c.name, got)
		}
	}
}

// The desktop takes the change before the laptop writes over a forged
// file: the entry is held back, then set back once the laptop has.
func TestSync_LateSwitchHeldUntilWrittenOver(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret = []byte("evil")
		r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	})
	desktop.sync(f)
	desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
	if !slices.Equal(s.HeldBack, []string{gh.String()}) || len(s.Sent) != 0 {
		t.Errorf("desktop before the laptop writes over it: %+v, want github held back", s)
	}
	syncOlder(t, laptop, f)
	if s := syncOlder(t, desktopNew, f); !slices.Equal(s.SetBack, []string{gh.String()}) {
		t.Errorf("desktop after: %+v, want github set back", s)
	}
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "pw-1" {
			t.Errorf("%s: %q, want pw-1", c.name, got)
		}
	}
	noEvil(t, laptop, desktopNew)
}

// An entry planted under the old key, which the folder has no version of
// under the new one, is held back, and nothing is sent for it, until it's
// deleted for good here; that sends nothing either.
func TestSync_LateSwitchHeldBack(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, _, rec, oldKey, oldID := lateWorld(t)
	uid := "0123456789abcdef0123456789abcdef"
	planted := &syncfolder.Record{Kind: vault.KindPassword, Service: "planted", Username: "alice", Secret: []byte("evil"), Versions: syncfolder.Versions{"0123456789abcdef": 1}, Changed: time.Now()}
	sealOld(t, f, uid+".sesh", uid, planted, oldKey, oldID)
	desktop.sync(f)
	if !slices.Contains(names(desktop), "planted") {
		t.Fatal("desktop on the old key: the planted entry not taken")
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "planted", Username: "alice"}
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	for range 2 {
		if s := syncOlder(t, desktopNew, f); !slices.Equal(s.HeldBack, []string{k.String()}) || len(s.Sent) != 0 || !s.Nothing() {
			t.Errorf("desktop: %+v, want planted held back, and nothing done", s)
		}
	}
	syncOlder(t, laptop, f)
	if err := desktopNew.store.PurgeMany([]vault.Key{k}); err != nil {
		t.Fatal(err)
	}
	if s := syncOlder(t, desktopNew, f); len(s.HeldBack)+len(s.Sent) != 0 {
		t.Errorf("desktop, deleted for good: %+v, want nothing held back or sent", s)
	}
	if after := scanFiles(t, f); slices.ContainsFunc(after, func(fl syncfolder.File) bool { return fl.UIDString() == uid }) {
		t.Error("a file was written for the planted entry")
	}
	settleOlder(t, f, laptop, desktopNew)
	if slices.Contains(names(laptop), "planted") {
		t.Error("laptop has the planted entry")
	}
}

// A forged rename beside a planted entry under the real one's name: the
// real one gets its name back, the planted one is renamed here and held
// back, whichever sorts first, and nothing of it is sent.
func TestSync_LateSwitchNameTaken(t *testing.T) {
	t.Parallel()
	for _, plantedUID := range []string{"00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff"} {
		laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
		uid := liveUID(t, desktop, gh)
		forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
			r.Service = "gh-old"
			r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
		})
		planted := &syncfolder.Record{Kind: vault.KindPassword, Service: "github", Username: "alice", Secret: []byte("evil"), Versions: syncfolder.Versions{"0123456789abcdef": 1}, Changed: time.Now()}
		sealOld(t, f, plantedUID+".sesh", plantedUID, planted, oldKey, oldID)
		desktop.sync(f)
		syncOlder(t, laptop, f)
		desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
		// The desktop keeps the planted one, held back: the vaults differ.
		for range 3 {
			syncOlder(t, laptop, f)
			syncOlder(t, desktopNew, f)
		}
		for _, c := range []*computer{laptop, desktopNew} {
			if got := c.secret(gh); got != "pw-1" || liveUID(t, c, gh) != uid {
				t.Errorf("planted %s: %s: github %q, want the real one", plantedUID[:2], c.name, got)
			}
		}
		if len(names(laptop)) != 1 {
			t.Errorf("planted %s: laptop has %q, want only github", plantedUID[:2], names(laptop))
		}
		noEvil(t, laptop)
	}
}

// A planted entry under the real one's name and secret, which the desktop's
// sync joined the real one into under the old key: the real one comes back,
// nothing of the planted one is sent.
func TestSync_LateSwitchJoinedIntoAPlant(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	plantedUID := "00000000000000000000000000000000"
	planted := &syncfolder.Record{Kind: vault.KindPassword, Service: "github", Username: "alice", Secret: []byte("pw-1"), URL: "https://evil.example", Versions: syncfolder.Versions{"0123456789abcdef": 1}, Changed: time.Now()}
	sealOld(t, f, plantedUID+".sesh", plantedUID, planted, oldKey, oldID)
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "pw-1" || liveUID(t, c, gh) != uid {
			t.Errorf("%s: github %q, want the real one", c.name, got)
		}
	}
	d, err := laptop.store.Details(gh, "test")
	if err != nil {
		t.Fatal(err)
	}
	if d.URL != "" || len(names(laptop)) != 1 {
		t.Errorf("laptop: URL %q, entries %q; want only the real github", d.URL, names(laptop))
	}
}

// What was set back never comes back through later changes.
func TestSync_LateSwitchLaterChanges(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret = []byte("evil")
		r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	})
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	laptop.put("github", "pw-9")
	settleOlder(t, f, laptop, desktopNew)
	desktopNew.put("github", "pw-10")
	settleOlder(t, f, laptop, desktopNew)
	if got := laptop.secret(gh); got != "pw-10" {
		t.Errorf("laptop: %q, want pw-10", got)
	}
	noEvil(t, laptop, desktopNew)
}

// An entry made under the old key and changed again before the switch is
// still this computer's own: sent once it takes the change.
func TestSync_LateSwitchMadeThenChanged(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, _, rec, _, _ := lateWorld(t)
	bank := desktop.put("bank", "b-1")
	desktop.sync(f)
	to := vault.Key{Kind: vault.KindPassword, Service: "bank2", Username: "alice"}
	if _, err := desktop.store.Edit(bank, database.EntryEdit{To: &to, Secret: []byte("b-2")}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
	if len(s.HeldBack) != 0 {
		t.Errorf("desktop taking the change: %+v, want nothing held back", s)
	}
	settleOlder(t, f, laptop, desktopNew)
	if got := laptop.secret(to); got != "b-2" {
		t.Errorf("laptop: bank2 %q, want the desktop's entry", got)
	}
}

// A deletion for good typed after an edit, both sent under the old key
// (an old-key file put back lets it write), stands once the computer takes
// the change.
func TestSync_LateSwitchPurgeAfterAnEdit(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	forge(t, desktop, f, liveUID(t, desktop, gh), oldKey, oldID, func(*syncfolder.Record) {})
	desktop.put("github", "desk-2")
	if s := desktop.sync(f); len(s.Sent) != 1 {
		t.Fatalf("desktop on the old key: %+v, want its edit sent", s)
	}
	if err := desktop.store.PurgeMany([]vault.Key{gh}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if slices.Contains(names(c), "github") {
			t.Errorf("%s has github, deleted for good on the desktop", c.name)
		}
	}
}

// A secret typed here that another computer's newer one replaced isn't

// An entry made and deleted for good under the old key, never anywhere
// else, leaves nothing to send once the computer takes the change.
func TestSync_LateSwitchMadeThenPurged(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, _, rec, _, _ := lateWorld(t)
	bank := desktop.put("bank", "b-1")
	desktop.sync(f)
	if err := desktop.store.PurgeMany([]vault.Key{bank}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	syncOlder(t, laptop, f)
	before := len(scanFiles(t, f))
	if _, s := switchDesktop(t, laptop, desktop, f, rec); len(s.Sent) != 0 {
		t.Errorf("desktop taking the change: %+v, want nothing sent", s)
	}
	if after := len(scanFiles(t, f)); after != before {
		t.Errorf("files %d, then %d: want nothing written", before, after)
	}
}

// A typed secret is kept only while the vault has it: replaced by
// another computer's newer one, it goes with history.keep 0, and stays
// with a history.
func TestSync_TypedKeptWhileTheVaultHasIt(t *testing.T) {
	t.Parallel()
	for _, keep := range []int{0, 10} {
		laptop, desktop, f := twoComputers(t)
		desktop.store.SetHistoryKeep(keep)
		gh := laptop.put("github", "pw-1")
		settle(t, f, laptop, desktop)
		desktop.put("github", "desk-2")
		laptop.put("github", "pw-3")
		laptop.sync(f)
		desktop.sync(f)
		settle(t, f, laptop, desktop)
		typed, err := desktop.store.SyncTyped(liveUID(t, desktop, gh))
		if err != nil {
			t.Fatal(err)
		}
		has := slices.ContainsFunc(typed, func(ty *syncfolder.Typed) bool { return string(ty.Post.Secret) == "desk-2" })
		if has != (keep > 0) {
			t.Errorf("history.keep %d: desk-2 kept %v, want %v", keep, has, keep > 0)
		}
	}
}

// An edit made on a computer behind the change, taken by another behind it
// and changed there in another way, reaches everyone once both take it.
func TestSync_LateSwitchEditTakenByAnotherLate(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	gh := cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs...)
	notes := vault.DetailsChange{SetNotes: true, Notes: []byte("desk notes")}
	if _, err := cs[1].store.Edit(gh, database.EntryEdit{Details: &notes}); err != nil {
		t.Fatal(err)
	}
	cs[1].sync(f)
	cs[2].sync(f)
	if _, err := cs[2].store.MoveToFolder([]vault.Key{gh}, "work"); err != nil {
		t.Fatal(err)
	}
	cs[2].sync(f)
	cs[1].sync(f)
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	syncOlder(t, laptop, f)
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	syncOlder(t, desktop, f)
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	syncOlder(t, third, f)
	settleOlder(t, f, laptop, desktop, third)
	for _, c := range []*computer{laptop, desktop, third} {
		d, err := c.store.Details(gh, "test")
		if err != nil {
			t.Fatal(err)
		}
		if string(d.Notes) != "desk notes" || folderOf(t, c, gh) != "work" {
			t.Errorf("%s: notes %q, folder %q; want the desktop's notes and the third's folder", c.name, d.Notes, folderOf(t, c, gh))
		}
	}
}

// folderOf is the folder c's entry k is in.
func folderOf(t *testing.T, c *computer, k vault.Key) string {
	t.Helper()
	es, err := c.store.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if e.Key == k {
			return e.Folder
		}
	}
	return ""
}

// A typed secret another computer behind the change replaced isn't made
// again: the newer one reaches everyone once that computer takes it.
func TestSync_LateSwitchTypedSecretReplaced(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	gh := cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs...)
	cs[1].put("github", "desk-2")
	cs[1].sync(f)
	cs[2].sync(f)
	cs[2].put("github", "third-3")
	cs[2].sync(f)
	cs[1].sync(f)
	if got := cs[1].secret(gh); got != "third-3" {
		t.Fatalf("desktop before the change: %q, want the third's newer", got)
	}
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	syncOlder(t, laptop, f)
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	syncOlder(t, desktop, f)
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	syncOlder(t, third, f)
	settleOlder(t, f, laptop, desktop, third)
	for _, c := range []*computer{laptop, desktop, third} {
		if got := c.secret(gh); got != "third-3" {
			t.Errorf("%s: %q, want third-3", c.name, got)
		}
	}
}

// A typed secret and URL a forgery under the old key replaced are made
// again, not the forgery, once the computer takes the change: the typed
// secret is still in the vault's history.
func TestSync_LateSwitchTypedThenForged(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(*syncfolder.Record) {})
	url := "https://github.com"
	if _, err := desktop.store.Edit(gh, database.EntryEdit{Secret: []byte("desk-2"), Details: &vault.DetailsChange{URL: &url}}); err != nil {
		t.Fatal(err)
	}
	if s := desktop.sync(f); len(s.Sent) != 1 {
		t.Fatalf("desktop on the old key: %+v, want its edit sent", s)
	}
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret, r.URL = []byte("evil"), "https://evil.example"
		r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	})
	desktop.sync(f)
	if got := desktop.secret(gh); got != "evil" {
		t.Fatalf("desktop on the old key: %q, want the forgery taken", got)
	}
	syncOlder(t, laptop, f)
	desktopNew, _ := switchDesktop(t, laptop, desktop, f, rec)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		d, err := c.store.Details(gh, "test")
		if err != nil {
			t.Fatal(err)
		}
		if got := c.secret(gh); got != "desk-2" || d.URL != url {
			t.Errorf("%s: %q, URL %q; want the typed desk-2 and %s", c.name, got, d.URL, url)
		}
	}
	noEvil(t, laptop, desktopNew)
}

// An entry made on one computer behind the change and renamed on another
// behind it reaches everyone, renamed, once both take it.
func TestSync_LateSwitchMadeHereChangedThere(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs...)
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	syncOlder(t, laptop, f)
	bank := cs[1].put("bank", "b-1")
	cs[1].sync(f)
	cs[2].sync(f)
	to := vault.Key{Kind: vault.KindPassword, Service: "bank-c", Username: "alice"}
	if _, err := cs[2].store.Edit(bank, database.EntryEdit{To: &to, Secret: []byte("c-2")}); err != nil {
		t.Fatal(err)
	}
	cs[2].sync(f)
	cs[1].sync(f)
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	syncOlder(t, desktop, f)
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	syncOlder(t, third, f)
	settleOlder(t, f, laptop, desktop, third)
	for _, c := range []*computer{laptop, desktop, third} {
		if got := c.secret(to); got != "c-2" {
			t.Errorf("%s: bank-c %q, want c-2", c.name, got)
		}
	}
}

// Notes typed at once on two computers behind the change, kept beside
// each other, reach everyone once both take it.
func TestSync_LateSwitchNotesOnBoth(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs...)
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	syncOlder(t, laptop, f)
	bank := cs[2].put("bank", "b-1")
	cs[2].sync(f)
	cs[1].sync(f)
	for i, c := range []*computer{cs[1], cs[2]} {
		n := vault.DetailsChange{SetNotes: true, Notes: []byte([]string{"from desk", "from third"}[i])}
		if _, err := c.store.Edit(bank, database.EntryEdit{Details: &n}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		cs[1].sync(f)
		cs[2].sync(f)
	}
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	syncOlder(t, desktop, f)
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	syncOlder(t, third, f)
	settleOlder(t, f, laptop, desktop, third)
	d, err := laptop.store.Details(bank, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(d.Notes, []byte("from desk")) || !bytes.Contains(d.Notes, []byte("from third")) {
		t.Errorf("laptop: notes %q, want both computers'", d.Notes)
	}
}

// A typed secret replaced, then forgotten or trimmed to history.keep, is
// no longer kept as typed, even beside something else typed with it.
func TestSync_TypedGoneWithTheVaults(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"forget", "prune"} {
		laptop, desktop, f := twoComputers(t)
		gh := laptop.put("github", "pw-1")
		settle(t, f, laptop, desktop)
		uid := liveUID(t, desktop, gh)
		if _, err := desktop.store.Edit(gh, database.EntryEdit{Secret: []byte("desk-2"), Details: &vault.DetailsChange{SetNotes: true, Notes: []byte("typed")}}); err != nil {
			t.Fatal(err)
		}
		laptop.put("github", "pw-3")
		laptop.sync(f)
		desktop.sync(f)
		settle(t, f, laptop, desktop)
		switch how {
		case "forget":
			h, err := desktop.store.History(gh)
			if err != nil {
				t.Fatal(err)
			}
			ns := make([]int, len(h))
			for i := range h {
				ns[i] = i + 2
			}
			if err := desktop.store.ForgetVersions(gh, ns...); err != nil {
				t.Fatal(err)
			}
		case "prune":
			if _, err := desktop.store.PruneHistory(0); err != nil {
				t.Fatal(err)
			}
		}
		typed, err := desktop.store.SyncTyped(uid)
		if err != nil {
			t.Fatal(err)
		}
		for _, ty := range typed {
			if ty.Post.Secret != nil {
				t.Errorf("%s: still kept as typed: %q", how, ty.Post.Secret)
			}
		}
	}
}

// A typed secret goes from what's kept as typed once the vault no longer
// has it, with no sync after, by the write that removed it: deleted for
// good, the trash emptied, or replaced with history.keep 0.
func TestSync_TypedGoneWithoutASync(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"purge", "empty the trash", "replace"} {
		laptop, desktop, f := twoComputers(t)
		desktop.store.SetHistoryKeep(0)
		gh := laptop.put("github", "pw-1")
		settle(t, f, laptop, desktop)
		uid := liveUID(t, desktop, gh)
		if _, err := desktop.store.Edit(gh, database.EntryEdit{Secret: []byte("desk-2"), Details: &vault.DetailsChange{SetNotes: true, Notes: []byte("typed")}}); err != nil {
			t.Fatal(err)
		}
		desktop.sync(f)
		var err error
		switch how {
		case "purge":
			err = desktop.store.PurgeMany([]vault.Key{gh})
		case "empty the trash":
			if err = desktop.store.Delete(gh); err == nil {
				_, err = desktop.store.EmptyTrash()
			}
		case "replace":
			desktop.put("github", "desk-3")
		}
		if err != nil {
			t.Fatal(err)
		}
		typed, err := desktop.store.SyncTyped(uid)
		if err != nil {
			t.Fatal(err)
		}
		for _, ty := range typed {
			if string(ty.Post.Secret) == "desk-2" {
				t.Errorf("%s: desk-2 still kept as typed", how)
			}
		}
	}
}

// An entry made on a computer behind the change, whose first secret it no
// longer has (history.keep 0) and changed on another behind it, is held
// back, not stuck, until its secret is typed again there.
func TestSync_LateSwitchMadeHereSecretGone(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs...)
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	syncOlder(t, laptop, f)
	cs[1].store.SetHistoryKeep(0)
	bank := cs[1].put("bank", "b-1")
	cs[1].sync(f)
	to := vault.Key{Kind: vault.KindPassword, Service: "bank2", Username: "alice"}
	if _, err := cs[1].store.Edit(bank, database.EntryEdit{To: &to}); err != nil {
		t.Fatal(err)
	}
	cs[1].sync(f)
	cs[2].sync(f)
	cs[2].put("bank2", "c-2")
	cs[2].sync(f)
	cs[1].sync(f)
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	if s := syncOlder(t, desktop, f); !slices.Equal(s.Retype, []string{to.String()}) || len(s.HeldBack)+len(s.Problems) != 0 {
		t.Errorf("desktop taking the change: %+v, want bank2 held back until its secret is typed again, no problem", s)
	}
	desktop.put("bank2", "desk-3")
	if s := syncOlder(t, desktop, f); len(s.HeldBack)+len(s.Retype) != 0 {
		t.Errorf("desktop, the secret typed again: %+v, want nothing held back", s)
	}
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	syncOlder(t, third, f)
	settleOlder(t, f, laptop, desktop, third)
	if !slices.Contains(names(laptop), "bank2") {
		t.Errorf("laptop: %q, want bank2", names(laptop))
	}
}

// A plain newer change from the other computers, made under the new key,
// is said as taken, not as set back.
func TestSync_LateSwitchNewerIsTaken(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, _, _ := lateWorld(t)
	laptop.put("github", "pw-2")
	syncOlder(t, laptop, f)
	desktopNew, s := switchDesktop(t, laptop, desktop, f, rec)
	if len(s.SetBack) != 0 || !slices.Equal(s.Received, []string{gh.String()}) {
		t.Errorf("desktop taking the change: %+v, want github taken, nothing set back", s)
	}
	if got := desktopNew.secret(gh); got != "pw-2" {
		t.Errorf("desktop: %q, want pw-2", got)
	}
}
