package vaultsync

import (
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

// A change forged under the old key, taken by a computer before it takes
// the new one, isn't sent on once it does, under any computer's count: the
// entry goes back to the folder's, the forged secret kept in its history.
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
			desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
			if s := syncOlder(t, desktopNew, f); !slices.Equal(s.SetBack, []string{gh.String()}) || len(s.Sent) != 0 {
				t.Errorf("desktop taking the change: %+v, want github set back", s)
			}
			settleOlder(t, f, laptop, desktopNew)
			for _, c := range []*computer{laptop, desktopNew} {
				if got := c.secret(gh); got != "pw-1" {
					t.Errorf("%s: %q, want pw-1", c.name, got)
				}
			}
			if !slices.Contains(allSecrets(t, desktopNew), "evil") {
				t.Error("desktop: the secret it had, gone from its history")
			}
			if slices.Contains(allSecrets(t, laptop), "evil") {
				t.Error("laptop: the forged secret reached it")
			}
		})
	}
}

// A deletion forged under the old key is undone the same way.
func TestSync_LateSwitchSetsBackADeletion(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		*r = syncfolder.Record{Purged: time.Now(), Versions: r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})}
	})
	desktop.sync(f)
	if slices.Contains(names(desktop), "github") {
		t.Fatal("desktop on the old key: the deletion not taken")
	}
	syncOlder(t, laptop, f)
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	syncOlder(t, desktopNew, f)
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "pw-1" {
			t.Errorf("%s: %q, want github back as pw-1", c.name, got)
		}
	}
}

// An edit typed over a version holding a count of this computer's it
// didn't give is held in doubt: the entry goes back to the folder's, the
// edit kept in history.
func TestSync_LateSwitchEditOverAForgery(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	id := computerID(t, desktop)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret = []byte("evil")
		r.Versions = r.Versions.Join(syncfolder.Versions{id: r.Versions[id] + 1000})
	})
	desktop.sync(f)
	desktop.put("github", "desk-2")
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	if s := syncOlder(t, desktopNew, f); !slices.Equal(s.SetBack, []string{gh.String()}) {
		t.Errorf("desktop taking the change: %+v, want github set back", s)
	}
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "pw-1" {
			t.Errorf("%s: %q, want pw-1", c.name, got)
		}
	}
	if !slices.Contains(allSecrets(t, desktopNew), "desk-2") {
		t.Error("desktop: its edit, gone from its history")
	}
}

// An edit of its own made under the old key is sent once the computer
// takes the change, as ever.
func TestSync_LateSwitchOwnEditSent(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, _, _ := lateWorld(t)
	desktop.put("github", "desk-2")
	desktop.sync(f)
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	if s := syncOlder(t, desktopNew, f); len(s.SetBack)+len(s.HeldBack) != 0 {
		t.Errorf("desktop taking the change: %+v, want nothing set or held back", s)
	}
	settleOlder(t, f, laptop, desktopNew)
	for _, c := range []*computer{laptop, desktopNew} {
		if got := c.secret(gh); got != "desk-2" {
			t.Errorf("%s: %q, want the desktop's edit", c.name, got)
		}
	}
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
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	if s := syncOlder(t, desktopNew, f); !slices.Equal(s.HeldBack, []string{gh.String()}) || len(s.Sent) != 0 {
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
}

// An entry planted under the old key, which the folder has no version of
// under the new one, is held back, and nothing is sent for it, until it's
// deleted for good here.
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
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	for range 2 {
		if s := syncOlder(t, desktopNew, f); !slices.Equal(s.HeldBack, []string{vault.Key{Kind: vault.KindPassword, Service: "planted", Username: "alice"}.String()}) || len(s.Sent) != 0 {
			t.Errorf("desktop: %+v, want planted held back", s)
		}
	}
	syncOlder(t, laptop, f)
	if slices.Contains(names(laptop), "planted") {
		t.Error("laptop took the planted entry")
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "planted", Username: "alice"}
	if err := desktopNew.store.PurgeMany([]vault.Key{k}); err != nil {
		t.Fatal(err)
	}
	if s := syncOlder(t, desktopNew, f); len(s.HeldBack) != 0 {
		t.Errorf("desktop, deleted for good: %+v, want nothing held back", s)
	}
	settleOlder(t, f, laptop, desktopNew)
	if slices.Contains(names(laptop), "planted") {
		t.Error("laptop has the planted entry")
	}
}

// What was set back stays in this computer's history through later
// changes, going with it as an earlier secret, never the current one.
func TestSync_LateSwitchSetBackKept(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, rec, oldKey, oldID := lateWorld(t)
	uid := liveUID(t, desktop, gh)
	forge(t, desktop, f, uid, oldKey, oldID, func(r *syncfolder.Record) {
		r.Secret = []byte("evil")
		r.Versions = r.Versions.Join(syncfolder.Versions{"0123456789abcdef": 1})
	})
	desktop.sync(f)
	syncOlder(t, laptop, f)
	desktopNew := takeKey(t, desktop, laptop, rec, "the new password 1")
	settleOlder(t, f, laptop, desktopNew)
	laptop.put("github", "pw-9")
	settleOlder(t, f, laptop, desktopNew)
	desktopNew.put("github", "pw-10")
	settleOlder(t, f, laptop, desktopNew)
	if got := laptop.secret(gh); got != "pw-10" {
		t.Errorf("laptop: %q, want pw-10", got)
	}
	if !slices.Contains(allSecrets(t, desktopNew), "evil") {
		t.Errorf("desktop: what it set back, gone from its history: %q", allSecrets(t, desktopNew))
	}
	if laptop.secret(gh) == "evil" || desktopNew.secret(gh) == "evil" {
		t.Error("what was set back is the secret again")
	}
}
