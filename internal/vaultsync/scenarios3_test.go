package vaultsync

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

// An entry edited after a restore beats the folder's deletion of it.
func TestSync_EditAfterRestoreBeatsDeletion(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"purge", "trash"} {
		t.Run(how, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if how == "purge" {
				if err := desktop.store.PurgeMany([]vault.Key{x}); err != nil {
					t.Fatal(err)
				}
			} else if err := desktop.store.Delete(x); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 6, laptop, desktop)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			// The user keeps using the restored entry: a new password.
			laptop.put("x", "set-after-restore")
			if err := laptop.store.SetDetails(x, &vault.Details{Notes: []byte("note-after-restore")}); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				tr, _ := c.store.Trash() //nolint:errcheck // test
				var trashed []string
				for _, e := range tr {
					trashed = append(trashed, e.Key.Service)
				}
				t.Logf("%s: live %q secrets %q trash %q", c.name, names(c), allSecrets(t, c), trashed)
				if !slices.Contains(allSecrets(t, c), "set-after-restore") {
					t.Errorf("%s: the password set after the restore is gone", c.name)
				}
			}
		})
	}
}

// A restore doesn't undo this computer's own deletion since: deletions made
// since stay deleted.
func TestSync_RestoreKeepsOwnDeletion(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	x := laptop.put("x", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	if err := laptop.store.PurgeMany([]vault.Key{x}); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	// Deletions since stay deleted, this computer's too: the trash, not a
	// restore, undoes a deletion while syncing.
	for _, c := range cs {
		if slices.Contains(names(c), "x") {
			t.Errorf("%s: x is back", c.name)
		}
	}
}

// A password forgotten on one computer is forgotten on another whose clock
// is ahead.
func TestSync_ForgetClockAhead(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	desktop.put("github", "pw-2")
	// The desktop's clock is 10 minutes ahead.
	rawExec(t, paths[1], `UPDATE history SET replaced_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '+10 minutes')`)
	rawExec(t, paths[1], `UPDATE entries SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '+10 minutes')`)
	for _, c := range cs {
		r, _, _ := c.store.SyncRecord(uidOfKey(t, c, gh), "x") //nolint:errcheck // test
		for _, h := range r.History {
			t.Logf("before sync %s: %s replaced %s (now %s)", c.name, h.Secret, h.ReplacedAt, time.Now().UTC())
		}
	}
	settleN(t, f, 6, laptop, desktop)
	for _, c := range cs {
		r, _, _ := c.store.SyncRecord(uidOfKey(t, c, gh), "x") //nolint:errcheck // test
		for _, h := range r.History {
			t.Logf("%s: %s replaced %s (now %s)", c.name, h.Secret, h.ReplacedAt, time.Now().UTC())
		}
	}
	if err := laptop.store.ForgetVersions(gh, 2); err != nil { // pw-1
		t.Fatal(err)
	}
	t.Logf("laptop right after forget: %q", allSecrets(t, laptop))
	for range 3 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s", c.name, s)
		}
	}
	for _, c := range cs {
		t.Logf("%s: %q", c.name, allSecrets(t, c))
		if slices.Contains(allSecrets(t, c), "pw-1") {
			t.Errorf("%s: pw-1, forgotten on purpose, is back", c.name)
		}
	}
}

// Two entries made under one name, one waiting for its file: neither is
// settled until both can be, so nothing of either is lost.
func TestSync_JoinWaits(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	o := laptop.put("netflix", "same-pw")
	rawExec(t, paths[0], `UPDATE entries SET uid = '00000000000000000000000000000001' WHERE service = 'netflix'`)
	syncLoose(laptop, f)
	dir := filepath.Join(f.Dir(), "entries")
	ownO := filepath.Join(dir, "00000000000000000000000000000001.sesh")
	saved, err := os.ReadFile(ownO)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ownO, filepath.Join(t.TempDir(), "o")); err != nil {
		t.Fatal(err)
	}
	// The desktop makes its own netflix, with notes and an earlier secret.
	desktop.put("netflix", "older-desktop-pw")
	desktop.put("netflix", "same-pw")
	if err := desktop.store.SetDetails(o, &vault.Details{Notes: []byte("desktop-notes")}); err != nil {
		t.Fatal(err)
	}
	syncLoose(desktop, f)
	t.Logf("folder: %q", entryFiles(f))
	// O's file is back, but not readable yet (being written, say).
	if err := os.WriteFile(ownO, []byte("not readable yet"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := syncLoose(laptop, f)
	t.Logf("laptop: %s %q joined=%q", s, s.Problems, s.Joined)
	t.Logf("laptop: live %q secrets %q", names(laptop), allSecrets(t, laptop))
	// Later, O's file is readable again.
	if err := os.WriteFile(ownO, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s %q", c.name, s, s.Problems)
		}
	}
	for _, c := range cs {
		d, _ := c.store.Details(o, "") //nolint:errcheck // test
		t.Logf("%s: live %q secrets %q notes %q", c.name, names(c), allSecrets(t, c), d.Notes)
		all := strings.Join(allSecrets(t, c), ",") + string(d.Notes)
		if !strings.Contains(all, "desktop-notes") || !strings.Contains(all, "older-desktop-pw") {
			t.Errorf("%s: the desktop's netflix notes/earlier password are gone", c.name)
		}
	}
}

func bigFile(i int) []byte {
	b := make([]byte, 1<<20)
	for j := range b {
		b[j] = byte('a' + (i+j)%26)
	}
	copy(b, fmt.Sprintf("v%05d", i))
	return b
}

// A file entry with more history than fits a sync file keeps it all here,
// and syncs whichever computer changes it.
func TestSync_BigHistory(t *testing.T) {
	t.Parallel()
	if raceDetector {
		t.Skip("too slow with -race; run without it")
	}
	for _, how := range []string{"both changed", "other changed"} {
		t.Run(how, func(t *testing.T) {
			cs, _, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			laptop.store.SetHistoryKeep(60)
			k := vault.Key{Kind: vault.KindFile, Service: "kube", Username: "alice"}
			for i := range 60 {
				if err := laptop.store.Save(&vault.Entry{Key: k, Settings: vault.Settings{FileName: "config"}}, bigFile(i)); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			h, _ := laptop.store.History(k) //nolint:errcheck // test
			t.Logf("laptop history before: %d", len(h))
			if err := desktop.store.SetDetails(k, &vault.Details{Notes: []byte("desk")}); err != nil {
				t.Fatal(err)
			}
			if how == "both changed" {
				if err := laptop.store.SetDetails(k, &vault.Details{URL: "https://x"}); err != nil {
					t.Fatal(err)
				}
			}
			syncLoose(desktop, f)
			for i := range 3 {
				s := syncLoose(laptop, f)
				hist, _ := laptop.store.History(k)  //nolint:errcheck // test
				d, _ := laptop.store.Details(k, "") //nolint:errcheck // test
				t.Logf("laptop sync %d: %s %q; history %d notes %q", i, s, s.Problems, len(hist), d.Notes)
			}
			h, _ = laptop.store.History(k) //nolint:errcheck // test
			if len(h) < 59 {
				t.Errorf("laptop history %d, was 59", len(h))
			}
			if d, _ := laptop.store.Details(k, ""); string(d.Notes) != "desk" { //nolint:errcheck // test
				t.Errorf("the desktop's notes never reached the laptop: %q", d.Notes)
			}
		})
	}
}

// A restored entry's values win over the folder's, both ways of restoring,
// the folder's password kept in history.
func TestSync_RestoredValuesWin(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"in place", "replace"} {
		t.Run(how, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := laptop.put("github", "restored-pw")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if err := laptop.store.SetDetails(gh, &vault.Details{Notes: []byte("restored-notes")}); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 6, laptop, desktop)
			if err := database.CopyTo(paths[0], backup+"2"); err != nil {
				t.Fatal(err)
			}
			backup += "2"
			time.Sleep(20 * time.Millisecond)
			desktop.put("github", "folder-pw")
			if err := desktop.store.SetDetails(gh, &vault.Details{Notes: []byte("folder-notes")}); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 6, laptop, desktop)
			if how == "in place" {
				if err := database.RestoreInPlace(paths[0], backup); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := laptop.store.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := database.ReplaceVault(paths[0], backup, time.Now()); err != nil {
					t.Fatal(err)
				}
				laptop.store = openVault(t, paths[0])
			}
			// The folder's password kept here at once, not only once the
			// other computer syncs.
			laptop.sync(f)
			if !slices.Contains(allSecrets(t, laptop), "folder-pw") {
				t.Errorf("%s: the folder's password isn't kept in the laptop's history", how)
			}
			settleN(t, f, 6, laptop, desktop)
			d, _ := laptop.store.Details(gh, "") //nolint:errcheck // test
			t.Logf("%s: laptop %q desktop %q; notes %q", how, laptop.secret(gh), desktop.secret(gh), d.Notes)
			// The restored notes win, the folder's kept below them.
			if !strings.HasPrefix(string(d.Notes), "restored-notes") || !strings.Contains(string(d.Notes), "folder-notes") {
				t.Errorf("%s: notes %q", how, d.Notes)
			}
			if laptop.secret(gh) != "restored-pw" || desktop.secret(gh) != "restored-pw" {
				t.Errorf("%s: the restored value didn't win (laptop %q, desktop %q)", how, laptop.secret(gh), desktop.secret(gh))
			}
			if !slices.Contains(allSecrets(t, desktop), "folder-pw") {
				t.Errorf("%s: the folder's password isn't kept in history", how)
			}
		})
	}
}

// An entry deleted after a restore, before syncing, stays deleted.
func TestSync_DeleteAfterRestore(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"purge", "trash"} {
		t.Run(how, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if how == "purge" {
				if err := laptop.store.PurgeMany([]vault.Key{x}); err != nil {
					t.Fatal(err)
				}
			} else if err := laptop.store.Delete(x); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 6, laptop, desktop)
			t.Logf("%s: laptop live %q, desktop live %q", how, names(laptop), names(desktop))
			if slices.Contains(names(laptop), "x") {
				t.Errorf("%s: deleted on the laptop after its restore, x is live again", how)
			}
		})
	}
}

// Saving a new secret keeps an entry's creation time, in the vault and the
// in-memory store alike.
func TestSync_SaveKeepsCreated(t *testing.T) {
	t.Parallel()
	cs, _, _ := computers(t, 1)
	k := vault.Key{Kind: vault.KindPassword, Service: "c", Username: "alice"}
	m := vault.NewMemStore()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return t0 }
	for _, s := range []vault.Store{cs[0].store, m} {
		if err := s.Save(&vault.Entry{Key: k}, []byte("one")); err != nil {
			t.Fatal(err)
		}
		e1, _ := s.Lookup(k) //nolint:errcheck // test
		time.Sleep(20 * time.Millisecond)
		t0 = t0.Add(time.Hour)
		if err := s.Save(&vault.Entry{Key: k}, []byte("two")); err != nil {
			t.Fatal(err)
		}
		e2, _ := s.Lookup(k) //nolint:errcheck // test
		if !e2.CreatedAt.Equal(e1.CreatedAt) {
			t.Errorf("%T: created %s, then %s", s, e1.CreatedAt, e2.CreatedAt)
		}
	}
}
