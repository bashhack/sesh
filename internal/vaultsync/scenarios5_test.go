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

func allOf(t *testing.T, cs []*computer) map[string][]string {
	out := map[string][]string{}
	for _, c := range cs {
		out[c.name] = allSecrets(t, c)
	}
	return out
}

func trashOf(c *computer) string {
	tr, _ := c.store.Trash() //nolint:errcheck // test
	var b []string
	for _, e := range tr {
		b = append(b, fmt.Sprintf("%s@%s", e.Service, e.DeletedAt.Format(time.DateOnly)))
	}
	return strings.Join(b, ",")
}

// An entry restored into the trash counts its trash days from the restore,
// so it isn't deleted for good at once.
func TestSync_RestoredTrashDays(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"expire on laptop before sync", "no expire on laptop; desktop expires after"} {
		t.Run(variant, func(t *testing.T) {
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
			// Weeks later: the backup's trash date is now over 30 days ago.
			rawExec(t, backup, `UPDATE trash SET deleted_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '-40 days')`)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			cutoff := time.Now().AddDate(0, 0, -30)
			if strings.HasPrefix(variant, "expire on laptop") {
				n, err := laptop.store.ExpireTrash(cutoff)
				t.Logf("laptop expired %d (%v)", n, err)
			}
			for i := range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("round %d %s: %s %q; live %q trash %q", i, c.name, s, s.Problems, names(c), trashOf(c))
					n, _ := c.store.ExpireTrash(cutoff) //nolint:errcheck // test
					if n > 0 {
						t.Logf("  %s expired %d from the trash", c.name, n)
					}
				}
			}
			all := allOf(t, cs)
			t.Logf("secrets: %q", all)
			if !slices.Contains(all["laptop"], "pw-D") && !slices.Contains(all["desktop"], "pw-D") {
				t.Errorf("pw-D, x's password in use on the desktop until the laptop's restore, is gone everywhere")
			}
		})
	}
}

// Two computers restoring at once lose nothing.
func TestSync_TwoRestoresAtOnce(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"in place", "replace"} {
		for _, race := range []bool{false, true} {
			t.Run(fmt.Sprint(how, " race=", race), func(t *testing.T) {
				cs, paths, f := computers(t, 2)
				laptop, desktop := cs[0], cs[1]
				x := laptop.put("x", "pw-1")
				settleN(t, f, 6, laptop, desktop)
				laptop.put("x", "pw-L")
				bl := filepath.Join(t.TempDir(), "bl.db")
				if err := database.CopyTo(paths[0], bl); err != nil {
					t.Fatal(err)
				}
				settleN(t, f, 6, laptop, desktop)
				time.Sleep(5 * time.Millisecond)
				desktop.put("x", "pw-Dk")
				if err := desktop.store.SetDetails(x, &vault.Details{Notes: []byte("desk-notes")}); err != nil {
					t.Fatal(err)
				}
				bd := filepath.Join(t.TempDir(), "bd.db")
				if err := database.CopyTo(paths[1], bd); err != nil {
					t.Fatal(err)
				}
				settleN(t, f, 6, laptop, desktop)
				time.Sleep(5 * time.Millisecond)
				laptop.put("x", "pw-3")
				settleN(t, f, 6, laptop, desktop)
				uid := uidOfKey(t, laptop, x)
				own := filepath.Join(f.Dir(), "entries", uid+".sesh")
				restoreHow(t, laptop, paths[0], bl, how)
				restoreHow(t, desktop, paths[1], bd, how)
				old, _ := os.ReadFile(own) //nolint:errcheck // test
				s := syncLoose(laptop, f)
				t.Logf("laptop: %s %q", s, s.Problems)
				if race {
					m1, _ := os.ReadFile(own) //nolint:errcheck // test
					if err := os.WriteFile(own, old, 0o600); err != nil {
						t.Fatal(err)
					}
					s = syncLoose(desktop, f)
					t.Logf("desktop: %s %q", s, s.Problems)
					if err := os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (laptop's conflicted copy).sesh"), m1, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				for i := range 5 {
					for _, c := range cs {
						s := syncLoose(c, f)
						t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
					}
				}
				for _, c := range cs {
					t.Logf("%s: x=%s %s %q", c.name, c.secret(x), detailsText(t, c, x), allSecrets(t, c))
					for _, want := range []string{"pw-1", "pw-L", "pw-Dk", "pw-3"} {
						if !slices.Contains(allSecrets(t, c), want) {
							t.Errorf("%s: %s gone", c.name, want)
						}
					}
				}
				sameVaults(t, laptop, desktop)
			})
		}
	}
}

// A restore, then a rename into a name taken since: both kept.
func TestSync_RestoreThenRenameIntoTaken(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"in place", "replace"} {
		for _, laterOwn := range []bool{false, true} {
			t.Run(fmt.Sprint(how, " laptop-made-y=", laterOwn), func(t *testing.T) {
				cs, paths, f := computers(t, 2)
				laptop, desktop := cs[0], cs[1]
				x := laptop.put("x", "pw-1")
				settleN(t, f, 6, laptop, desktop)
				backup := filepath.Join(t.TempDir(), "backup.db")
				if err := database.CopyTo(paths[0], backup); err != nil {
					t.Fatal(err)
				}
				if laterOwn {
					laptop.put("y", "pw-y")
				} else {
					desktop.put("y", "pw-y")
				}
				desktop.put("x", "pw-x2")
				settleN(t, f, 6, laptop, desktop)
				restoreHow(t, laptop, paths[0], backup, how)
				to := vault.Key{Kind: x.Kind, Service: "y", Username: x.Username}
				if _, err := laptop.store.Edit(x, database.EntryEdit{To: &to}); err != nil {
					t.Fatal(err)
				}
				for i := range 5 {
					for _, c := range cs {
						s := syncLoose(c, f)
						t.Logf("round %d %s: %s %q renamed %q", i, c.name, s, s.Problems, s.Renamed)
					}
				}
				for _, c := range cs {
					t.Logf("%s: live %q secrets %q", c.name, names(c), allSecrets(t, c))
					for _, want := range []string{"pw-1", "pw-y", "pw-x2"} {
						if !slices.Contains(allSecrets(t, c), want) {
							t.Errorf("%s: %s gone", c.name, want)
						}
					}
				}
				sameVaults(t, laptop, desktop)
			})
		}
	}
}

// A restored entry whose folder has only sync tools' copies keeps all.
func TestSync_RestoredOnlyCopies(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	x := laptop.put("x", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	uid := uidOfKey(t, laptop, x)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	v1, _ := os.ReadFile(own) //nolint:errcheck // test
	desktop.put("x", "pw-2")
	syncLoose(desktop, f)
	v2, _ := os.ReadFile(own) //nolint:errcheck // test
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (old copy).sesh"), v1, 0o600)        //nolint:errcheck // test
	_ = os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (conflicted copy).sesh"), v2, 0o600) //nolint:errcheck // test
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
		}
	}
	t.Logf("files %q", entryFiles(f))
	for _, c := range cs {
		t.Logf("%s: x=%s %q", c.name, c.secret(x), allSecrets(t, c))
		if !slices.Contains(allSecrets(t, c), "pw-2") {
			t.Errorf("%s: pw-2 gone", c.name)
		}
	}
	sameVaults(t, laptop, desktop)
}

// A restored entry with a damaged agreed version keeps the folder's password.
func TestSync_RestoredDamagedBase(t *testing.T) {
	t.Parallel()
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
			desktop.put("x", "pw-2")
			settleN(t, f, 6, laptop, desktop)
			if err := database.RestoreInPlace(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			rawExec(t, paths[0], `UPDATE sync_state SET base = x'00'`)
			if edit {
				if err := laptop.store.SetDetails(x, &vault.Details{URL: "https://after"}); err != nil {
					t.Fatal(err)
				}
			}
			for i := range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
				}
			}
			for _, c := range cs {
				t.Logf("%s: x=%s %q", c.name, c.secret(x), allSecrets(t, c))
				if !slices.Contains(allSecrets(t, c), "pw-2") {
					t.Errorf("%s: pw-2 gone", c.name)
				}
			}
			sameVaults(t, laptop, desktop)
		})
	}
}

// A restore on a computer keeping no history loses nothing elsewhere.
func TestSync_RestoreKeepZero(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 3)
	laptop, desktop, third := cs[0], cs[1], cs[2]
	laptop.store.SetHistoryKeep(0)
	third.store.SetHistoryKeep(1000)
	x := laptop.put("x", "pw-1")
	settleN(t, f, 6, cs...)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	desktop.put("x", "pw-2")
	syncLoose(desktop, f)
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
		}
	}
	for _, c := range cs {
		t.Logf("%s: x=%s %q", c.name, c.secret(x), allSecrets(t, c))
	}
	if !slices.Contains(allSecrets(t, third), "pw-2") {
		t.Errorf("third (keeps all): pw-2 gone")
	}
}

// A restore over a folder file a sync tool rolled back keeps the newer
// password the computer had agreed.
func TestSync_RestoreOverRolledBackFile(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	desktop.store.SetHistoryKeep(0)
	x := laptop.put("x", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	uid := uidOfKey(t, laptop, x)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	v1, _ := os.ReadFile(own) //nolint:errcheck // test
	time.Sleep(5 * time.Millisecond)
	laptop.put("x", "pw-3")
	syncLoose(laptop, f)
	// The sync tool puts the old file back before the desktop saw pw-3.
	if err := os.WriteFile(own, v1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
		}
	}
	for _, c := range cs {
		t.Logf("%s: x=%s %q", c.name, c.secret(x), allSecrets(t, c))
	}
	if !slices.Contains(allSecrets(t, laptop), "pw-3") {
		t.Errorf("laptop (keeps 10): pw-3, its password until the restore, gone")
	}
}

// A restored file entry with more history than fits a sync file keeps it.
func TestSync_RestoredBigHistory(t *testing.T) {
	t.Parallel()
	if raceDetector {
		t.Skip("too slow with -race; run without it")
	}
	for _, how := range []string{"in place", "replace"} {
		t.Run(how, func(t *testing.T) {
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			laptop.store.SetHistoryKeep(60)
			desktop.store.SetHistoryKeep(60)
			k := vault.Key{Kind: vault.KindFile, Service: "kube", Username: "alice"}
			for i := range 60 {
				if err := laptop.store.Save(&vault.Entry{Key: k, Settings: vault.Settings{FileName: "config"}}, bigFile(i)); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				for _, c := range cs {
					syncLoose(c, f)
				}
			}
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[0], backup); err != nil {
				t.Fatal(err)
			}
			if err := desktop.store.Save(&vault.Entry{Key: k, Settings: vault.Settings{FileName: "config2"}}, bigFile(1000)); err != nil {
				t.Fatal(err)
			}
			syncLoose(desktop, f)
			syncLoose(laptop, f)
			restoreHow(t, laptop, paths[0], backup, how)
			for i := range 4 {
				for _, c := range cs {
					s := syncLoose(c, f)
					h, _ := c.store.History(k) //nolint:errcheck // test
					t.Logf("round %d %s: %s %q history %d", i, c.name, s, s.Problems, len(h))
				}
			}
			for _, c := range cs {
				sec := allSecrets(t, c)
				has := false
				for _, s := range sec {
					if strings.HasPrefix(s, "v01000") {
						has = true
					}
				}
				h, _ := c.store.History(k) //nolint:errcheck // test
				t.Logf("%s: history %d has-desktop-version %v current %.6s", c.name, len(h), has, c.secret(k))
				if !has {
					t.Errorf("%s: the desktop's version (v01000) is gone", c.name)
				}
			}
		})
	}
}

// An edit in a restored backup, never synced, beats the folder's deletion,
// as it would without the restore.
func TestSync_RestoredUnsyncedEdit(t *testing.T) {
	t.Parallel()
	for _, del := range []string{"purge", "trash"} {
		for _, how := range []string{"none", "in place", "replace"} {
			t.Run(del+"/"+how, func(t *testing.T) {
				cs, paths, f := computers(t, 2)
				laptop, desktop := cs[0], cs[1]
				x := laptop.put("x", "pw-1")
				settleN(t, f, 6, laptop, desktop)
				time.Sleep(5 * time.Millisecond)
				laptop.put("x", "pw-L") // not synced
				if del == "purge" {
					if err := desktop.store.PurgeMany([]vault.Key{x}); err != nil {
						t.Fatal(err)
					}
				} else if err := desktop.store.Delete(x); err != nil {
					t.Fatal(err)
				}
				syncLoose(desktop, f)
				backup := filepath.Join(t.TempDir(), "backup.db")
				if err := database.CopyTo(paths[0], backup); err != nil {
					t.Fatal(err)
				}
				if how != "none" {
					restoreHow(t, laptop, paths[0], backup, how)
				}
				for i := range 4 {
					for _, c := range cs {
						s := syncLoose(c, f)
						t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
					}
				}
				for _, c := range cs {
					t.Logf("%s: live %q trash %q secrets %q", c.name, names(c), trashOf(c), allSecrets(t, c))
				}
				if !slices.Contains(allSecrets(t, laptop), "pw-L") && !slices.Contains(allSecrets(t, desktop), "pw-L") {
					t.Errorf("pw-L, set on the laptop and in its backup, is gone everywhere")
				}
				if !slices.Contains(names(laptop), "x") {
					t.Logf("NOTE: x not live on the laptop")
				}
			})
		}
	}
}

// A password forgotten while another computer, offline, still had it as
// its own stays forgotten.
func TestSync_ForgetWhileHeldOffline(t *testing.T) {
	t.Parallel()
	for _, change := range []bool{false, true} {
		for _, deskEdit := range []bool{false, true} {
			t.Run(fmt.Sprint("change-after-forget=", change, " desktop-edit=", deskEdit), func(t *testing.T) {
				cs, _, f := computers(t, 2)
				laptop, desktop := cs[0], cs[1]
				x := laptop.put("x", "pw-A")
				settleN(t, f, 6, laptop, desktop)
				// The desktop is off from here.
				time.Sleep(5 * time.Millisecond)
				laptop.put("x", "pw-B")
				time.Sleep(5 * time.Millisecond)
				if err := laptop.store.ForgetVersions(x, 2); err != nil { // pw-A
					t.Fatal(err)
				}
				if slices.Contains(allSecrets(t, laptop), "pw-A") {
					t.Fatal("forget didn't take locally")
				}
				if change {
					time.Sleep(5 * time.Millisecond)
					laptop.put("x", "pw-C")
				}
				syncLoose(laptop, f)
				if deskEdit {
					if err := desktop.store.SetDetails(x, &vault.Details{Notes: []byte("desk")}); err != nil {
						t.Fatal(err)
					}
				}
				for i := range 4 {
					for _, c := range cs {
						s := syncLoose(c, f)
						t.Logf("round %d %s: %s %q", i, c.name, s, s.Problems)
					}
				}
				for _, c := range cs {
					t.Logf("%s: %q", c.name, allSecrets(t, c))
					if slices.Contains(allSecrets(t, c), "pw-A") {
						t.Errorf("%s: pw-A, forgotten on purpose, is back", c.name)
					}
				}
			})
		}
	}
}

// A computer first syncing after an entry was deleted for good has nothing
// to say of it: it never had it.
func TestSync_DeletedBeforeJoining(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	gh := cs[0].put("github", "pw-1")
	cs[0].put("bank", "pw-2")
	settleN(t, f, 4, cs[0], cs[1])
	if err := cs[0].store.PurgeMany([]vault.Key{gh}); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 4, cs[0], cs[1])
	s := cs[2].sync(f)
	if len(s.Received) != 1 || s.Received[0] != "password/bank/alice" {
		t.Errorf("first sync: %+v, want only bank taken", s)
	}
}
