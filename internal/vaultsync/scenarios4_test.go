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
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

func restoreHow(t *testing.T, c *computer, path, backup, how string) {
	t.Helper()
	if how == "in place" {
		if err := database.RestoreInPlace(path, backup); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := c.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReplaceVault(path, backup, time.Now()); err != nil {
		t.Fatal(err)
	}
	c.store = openVault(t, path)
}

func detailsText(t *testing.T, c *computer, k vault.Key) string {
	t.Helper()
	d, err := c.store.Details(k, "test")
	if err != nil {
		return "ERR " + err.Error()
	}
	var b strings.Builder
	b.WriteString("notes=" + string(d.Notes))
	for _, f := range d.Fields {
		b.WriteString(" " + f.Name + "=" + string(f.Value))
	}
	return b.String()
}

// A restore keeps a secret field and notes made elsewhere since the backup.
func TestSync_RestoreKeepsFolderFields(t *testing.T) {
	for _, how := range []string{"in place", "replace"} {
		for _, variant := range []string{"laptop agreed it", "fresh on restore"} {
			t.Run(how+"/"+variant, func(t *testing.T) {
				cs, paths, f := computers(t, 2)
				laptop, desktop := cs[0], cs[1]
				x := laptop.put("x", "pw-1")
				settleN(t, f, 6, laptop, desktop)
				backup := filepath.Join(t.TempDir(), "backup.db")
				if err := database.CopyTo(paths[0], backup); err != nil {
					t.Fatal(err)
				}
				if err := desktop.store.SetDetails(x, &vault.Details{Notes: []byte("desk-notes"), Fields: []vault.Field{{Name: "recovery", Value: []byte("RC-SECRET"), Secret: true}}}); err != nil {
					t.Fatal(err)
				}
				if variant == "laptop agreed it" {
					settleN(t, f, 6, laptop, desktop)
				} else {
					syncLoose(desktop, f)
				}
				restoreHow(t, laptop, paths[0], backup, how)
				for range 4 {
					for _, c := range cs {
						s := syncLoose(c, f)
						t.Logf("%s: %s %q", c.name, s, s.Problems)
					}
				}
				for _, c := range cs {
					txt := detailsText(t, c, x)
					t.Logf("%s: %s secrets %q", c.name, txt, allSecrets(t, c))
					if !strings.Contains(txt, "RC-SECRET") && !slices.Contains(allSecrets(t, c), "RC-SECRET") {
						t.Errorf("%s: secret field RC-SECRET set on the desktop is gone", c.name)
					}
					if !strings.Contains(txt, "desk-notes") {
						t.Errorf("%s: desktop notes gone", c.name)
					}
				}
			})
		}
	}
}

// A restore keeps the earlier secrets the folder's file has.
func TestSync_RestoreKeepsFolderHistory(t *testing.T) {
	for _, variant := range []string{"agreed (base)", "fresh"} {
		t.Run(variant, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			desktop.store.SetHistoryKeep(0)
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			laptop.put("x", "pw-2")
			time.Sleep(10 * time.Millisecond)
			laptop.put("x", "pw-3")
			settleN(t, f, 6, laptop, desktop)
			if variant == "fresh" {
				if err := desktop.store.SetDetails(x, &vault.Details{URL: "https://x"}); err != nil {
					t.Fatal(err)
				}
				syncLoose(desktop, f)
			}
			for _, c := range cs {
				t.Logf("before restore %s: %q", c.name, allSecrets(t, c))
			}
			folderSecrets(t, laptop, f)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			for range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: %q", c.name, allSecrets(t, c))
			}
			// When the folder's file has pw-2 in its history, the restore
			// keeps it. ("fresh": the desktop, keeping none, wrote a newer
			// file without it, so the laptop's own history was its only
			// copy, which restoring the older backup replaces.)
			if variant != "fresh" && !slices.Contains(allSecrets(t, laptop), "pw-2") {
				t.Errorf("laptop (keep 10) lacks pw-2, which the folder's file had in its history")
			}
		})
	}
}

// Forgetting works with clocks a little apart; with them together, the
// same password used again later is kept.
func TestSync_ForgetAndReuse(t *testing.T) {
	for _, skew := range []string{"none", "+1 hours", "+4 years"} {
		t.Run(skew, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := laptop.put("github", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			desktop.put("github", "pw-2")
			if skew != "none" {
				rawExec(t, paths[1], `UPDATE history SET replaced_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '`+skew+`')`)
				rawExec(t, paths[1], `UPDATE entries SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '`+skew+`')`)
			}
			dumpForget(t, desktop)
			settleN(t, f, 6, laptop, desktop)
			if err := laptop.store.ForgetVersions(gh, 2); err != nil { // pw-1
				t.Fatal(err)
			}
			dumpForget(t, laptop)
			settleN(t, f, 6, laptop, desktop)
			// Forgotten everywhere, with clocks within a day of each other;
			// one years ahead may keep it (a mark that far ahead would keep
			// the same password, used again later, forgotten for years).
			for _, c := range cs {
				if skew != "+4 years" && slices.Contains(allSecrets(t, c), "pw-1") {
					t.Fatalf("%s: forget didn't take", c.name)
				}
			}
			// With the clocks apart, a mark is as late as the other's clock
			// said, so the same password used again within that is
			// forgotten too: only checked with the clocks together.
			if skew != "none" {
				return
			}
			// Later, pw-1 is used again, then replaced.
			laptop.put("github", "pw-1")
			time.Sleep(10 * time.Millisecond)
			laptop.put("github", "pw-3")
			t.Logf("laptop right after reuse: %q", allSecrets(t, laptop))
			for range 3 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: %q", c.name, allSecrets(t, c))
				if !slices.Contains(allSecrets(t, c), "pw-1") {
					t.Errorf("%s: pw-1, used again after the forget and then replaced, is gone from history", c.name)
				}
			}
		})
	}
}

// Restoring a backup the folder already has writes nothing back.
func TestSync_RestoreSameWritesNothing(t *testing.T) {
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	for i := range 20 {
		laptop.put("svc"+string(rune('a'+i)), "pw")
	}
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	s := syncLoose(laptop, f)
	t.Logf("laptop: %s merged=%d sent=%d", s, len(s.Merged), len(s.Sent))
	s2 := syncLoose(desktop, f)
	t.Logf("desktop: %s received=%d", s2, len(s2.Received))
	if len(s.Merged)+len(s.Sent) > 0 {
		t.Errorf("restore of an identical backup wrote %d entries to the folder", len(s.Merged)+len(s.Sent))
	}
}

func dumpForget(t *testing.T, c *computer) {
	t.Helper()
	items, _ := c.store.SyncItems() //nolint:errcheck // test
	for _, it := range items {
		if it.Place == database.SyncGone {
			continue
		}
		r, _, _ := c.store.SyncRecord(it.UID, "x") //nolint:errcheck // test
		for _, h := range r.History {
			t.Logf("%s hist %s replaced %s", c.name, h.Secret, h.ReplacedAt)
		}
		for _, m := range r.Forgotten {
			t.Logf("%s forgot %s.. at %s", c.name, m.Hash[:8], m.At)
		}
	}
}

// The password a restore replaces goes into history as replaced then, so
// a short history.keep keeps it.
func TestSync_RestoreReplacedNow(t *testing.T) {
	for _, keep := range []int{10, 1} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			laptop.store.SetHistoryKeep(keep)
			desktop.store.SetHistoryKeep(keep)
			laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
			laptop.put("x", "pw-2")
			time.Sleep(20 * time.Millisecond)
			laptop.put("x", "pw-3")
			settleN(t, f, 6, laptop, desktop)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			for range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				dumpForget(t, c)
				t.Logf("%s: %q", c.name, allSecrets(t, c))
				if !slices.Contains(allSecrets(t, c), "pw-3") {
					t.Errorf("%s: pw-3, the password in use until the restore, is gone (history.keep %d)", c.name, keep)
				}
			}
		})
	}
}

func folderSecrets(t *testing.T, c *computer, f syncfolder.Folder) {
	t.Helper()
	contents, err := f.Scan()
	if err != nil {
		t.Fatal(err)
	}
	for _, fl := range contents.Files {
		b, err := f.Read(&fl)
		if err != nil {
			t.Fatal(err)
		}
		_, rec, err := syncfolder.Open(c.store.SyncSealer(), b)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("folder file %s: %s %q", filepath.Base(fl.Path), rec.Secret, secrets(rec.History))
	}
}

// An edit after a restore merges with the folder's version, keeping its
// password, even where the other computer keeps none.
func TestSync_EditAfterRestoreMerges(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(fmt.Sprint("edit=", edit), func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			desktop.store.SetHistoryKeep(0)
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			laptop.put("x", "pw-3")
			settleN(t, f, 6, laptop, desktop)
			folderSecrets(t, laptop, f)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if edit {
				if err := laptop.store.SetDetails(x, &vault.Details{URL: "https://after-restore"}); err != nil {
					t.Fatal(err)
				}
			}
			for range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: %q", c.name, allSecrets(t, c))
			}
			if !slices.Contains(allSecrets(t, laptop), "pw-3") && !slices.Contains(allSecrets(t, desktop), "pw-3") {
				t.Errorf("pw-3, the password everywhere until the restore, is gone everywhere")
			}
		})
	}
}

// An edit after a restore, the other computer off: the folder's password
// is kept.
func TestSync_EditAfterRestoreOtherOffline(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(fmt.Sprint("edit=", edit), func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			laptop.put("x", "pw-3")
			syncLoose(laptop, f) // the desktop is off
			folderSecrets(t, laptop, f)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if edit {
				if err := laptop.store.SetDetails(x, &vault.Details{URL: "https://after-restore"}); err != nil {
					t.Fatal(err)
				}
			}
			syncLoose(laptop, f)
			for range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: %q", c.name, allSecrets(t, c))
			}
			if !slices.Contains(allSecrets(t, laptop), "pw-3") && !slices.Contains(allSecrets(t, desktop), "pw-3") {
				t.Errorf("pw-3, the password until the restore, is gone everywhere")
			}
		})
	}
}

// The same, after replacing the vault from a backup.
func TestSync_EditAfterReplaceOtherOffline(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(fmt.Sprint("edit=", edit), func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			laptop.put("x", "pw-3")
			syncLoose(laptop, f) // the desktop is off
			folderSecrets(t, laptop, f)
			restoreHow(t, laptop, paths[0], backup, "replace")
			if edit {
				if err := laptop.store.SetDetails(x, &vault.Details{URL: "https://after-restore"}); err != nil {
					t.Fatal(err)
				}
			}
			syncLoose(laptop, f)
			for range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: %q", c.name, allSecrets(t, c))
			}
			if !slices.Contains(allSecrets(t, laptop), "pw-3") && !slices.Contains(allSecrets(t, desktop), "pw-3") {
				t.Errorf("pw-3, the password until the restore, is gone everywhere")
			}
		})
	}
}

// A restored entry whose folder version two computers changed at once
// keeps all three passwords.
func TestSync_RestoreConcurrentCopies(t *testing.T) {
	for _, how := range []string{"in place", "replace"} {
		t.Run(how, func(t *testing.T) {
			cs, paths, f := computers(t, 3)
			laptop, desktop, third := cs[0], cs[1], cs[2]
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, cs...)
			uid := uidOfKey(t, laptop, x)
			own := filepath.Join(f.Dir(), "entries", uid+".sesh")
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			old, _ := os.ReadFile(own) //nolint:errcheck // test
			desktop.put("x", "pw-D")
			syncLoose(desktop, f)
			ds, _ := os.ReadFile(own) //nolint:errcheck // test
			if err := os.WriteFile(own, old, 0o600); err != nil {
				t.Fatal(err)
			}
			third.put("x", "pw-T")
			syncLoose(third, f)
			if err := os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (desktop's conflicted copy).sesh"), ds, 0o600); err != nil {
				t.Fatal(err)
			}
			restoreHow(t, laptop, paths[0], backup, how)
			for range 5 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("%s: %s %q", c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: %q", c.name, allSecrets(t, c))
				for _, want := range []string{"pw-1", "pw-D", "pw-T"} {
					if !slices.Contains(allSecrets(t, c), want) {
						t.Errorf("%s: %s gone", c.name, want)
					}
				}
			}
			sameVaults(t, laptop, desktop)
			sameVaults(t, laptop, third)
			if laptop.secret(x) != "pw-1" {
				t.Errorf("restored value didn't win: %s", laptop.secret(x))
			}
		})
	}
}

// A restored entry in the trash goes back to the trash, the folder's
// password kept.
func TestSync_RestoredTrashedHere(t *testing.T) {
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	x := laptop.put("x", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	if err := laptop.store.Delete(x); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	tr, _ := desktop.store.Trash() //nolint:errcheck // test
	if _, err := desktop.store.RestoreFromTrash(tr[0].ID, vault.Key{}); err != nil {
		t.Fatal(err)
	}
	desktop.put("x", "pw-D")
	settleN(t, f, 6, laptop, desktop)
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	for _, c := range cs {
		tr, _ := c.store.Trash() //nolint:errcheck // test
		t.Logf("%s: live %q trash %d secrets %q", c.name, names(c), len(tr), allSecrets(t, c))
	}
}

// Two restores before syncing, either order, lose nothing.
func TestSync_TwoRestores(t *testing.T) {
	for _, order := range []string{"old then new", "new then old"} {
		t.Run(order, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			x := laptop.put("x", "pw-1")
			settleN(t, f, 6, laptop, desktop)
			b1 := filepath.Join(t.TempDir(), "b1.db")
			if err := database.CopyTo(paths[0], b1); err != nil {
				t.Fatal(err)
			}
			laptop.put("y", "y-1")
			laptop.put("x", "pw-2")
			settleN(t, f, 6, laptop, desktop)
			b2 := filepath.Join(t.TempDir(), "b2.db")
			if err := database.CopyTo(paths[0], b2); err != nil {
				t.Fatal(err)
			}
			desktop.put("x", "pw-D")
			desktop.put("y", "y-D")
			desktop.put("z", "z-D")
			settleN(t, f, 6, laptop, desktop)
			first, second := b1, b2
			if order != "old then new" {
				first, second = b2, b1
			}
			if err := database.RestoreInPlace(paths[0], first); err != nil {
				t.Fatal(err)
			}
			if err := database.RestoreInPlace(paths[0], second); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 6, laptop, desktop)
			for _, c := range cs {
				t.Logf("%s: live %q secrets %q", c.name, names(c), allSecrets(t, c))
				for _, want := range []string{"pw-1", "pw-2", "pw-D", "y-1", "y-D", "z-D"} {
					if !slices.Contains(allSecrets(t, c), want) {
						t.Errorf("%s: %s gone", c.name, want)
					}
				}
			}
			t.Logf("x now %s", laptop.secret(x))
		})
	}
}
