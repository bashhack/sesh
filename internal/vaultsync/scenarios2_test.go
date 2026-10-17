package vaultsync

import (
	"bytes"
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

func names(c *computer) []string {
	items, _ := c.store.SyncItems() //nolint:errcheck // test
	var out []string
	for _, it := range items {
		if it.Place == database.SyncLive {
			out = append(out, it.Key.Service)
		}
	}
	slices.Sort(out)
	return out
}

func entryFiles(f syncfolder.Folder) []string {
	des, _ := os.ReadDir(filepath.Join(f.Dir(), "entries")) //nolint:errcheck // test
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}

// Fields added on both computers, more together than an entry can have:
// nothing is written that can't be kept, and each keeps its own.
func TestSync_FieldsUnionTooMany(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	mk := func(prefix string) *vault.Details {
		d := &vault.Details{}
		for i := range 30 {
			d.Fields = append(d.Fields, vault.Field{Name: fmt.Sprintf("%s%d", prefix, i), Value: []byte(prefix + "-v"), Secret: i == 0})
		}
		return d
	}
	if err := laptop.store.SetDetails(gh, mk("l")); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.SetDetails(gh, mk("d")); err != nil {
		t.Fatal(err)
	}
	uid := uidOfKey(t, laptop, gh)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	// The laptop's own fields fit: sent.
	syncLoose(laptop, f)
	before, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}
	var said []string
	for range 4 {
		for _, c := range cs {
			said = append(said, syncLoose(c, f).Problems...)
		}
	}
	// Nothing written that can't be kept: the folder's file is as it was,
	// each computer keeps its own fields, and it says why.
	if after, _ := os.ReadFile(own); string(after) != string(before) { //nolint:errcheck // compared
		t.Error("an entry that can't be kept was written")
	}
	for _, c := range cs {
		if d, err := c.store.Details(gh, ""); err != nil || len(d.Fields) != 30 {
			t.Errorf("%s: %d fields, %v", c.name, len(d.Fields), err)
		}
	}
	if !strings.Contains(strings.Join(said, "\n"), "can't be merged into an entry sesh can keep") {
		t.Errorf("not said: %q", said)
	}
}

// Entries deleted for good, or to the trash, on another computer after this
// one's backup stay deleted when it's restored.
func TestSync_RestoreKeepsDeletionsSince(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	laptop.put("keep", "k-1")
	gone := laptop.put("gone", "leaked-secret")
	trashed := laptop.put("trashed", "t-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.PurgeMany([]vault.Key{gone}); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.Delete(trashed); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	t.Logf("before restore: laptop %q desktop %q", names(laptop), names(desktop))
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	t.Logf("after restore+sync: laptop %q desktop %q", names(laptop), names(desktop))
	if slices.Contains(names(desktop), "gone") {
		t.Errorf("desktop: the entry it deleted for good is back: %q", allSecrets(t, desktop))
	}
	if slices.Contains(names(desktop), "trashed") {
		t.Errorf("desktop: the entry it moved to the trash is live again")
	}
}

// Names swapped on one computer (a->tmp, b->a, tmp->b) settle alike on
// both, with both passwords.
func TestSync_NameSwap(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	ka := laptop.put("a", "sa")
	kb := laptop.put("b", "sb")
	settleN(t, f, 6, laptop, desktop)
	tmp := vault.Key{Kind: vault.KindPassword, Service: "tmp", Username: "alice"}
	for _, e := range [][2]vault.Key{{ka, tmp}, {kb, ka}, {tmp, kb}} {
		to := e[1]
		if _, err := desktop.store.Edit(e[0], database.EntryEdit{To: &to}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("desktop after swap: a=%s b=%s", desktop.secret(ka), desktop.secret(kb))
	for range 4 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s %q renamed %q", c.name, s, s.Problems, s.Renamed)
		}
	}
	// A swap is two names each taken by the other: settled as one name
	// made twice, so one ends "a (2)" (a known limit); both passwords
	// are kept, the same on both computers.
	sameVaults(t, laptop, desktop)
	for _, c := range cs {
		secrets := allSecrets(t, c)
		if !slices.Contains(secrets, "sa") || !slices.Contains(secrets, "sb") {
			t.Errorf("%s: names %q, secrets %q", c.name, names(c), secrets)
		}
	}
}

// An entry freeing a name whose file isn't downloaded yet waits: nothing is
// written over it.
func TestSync_FreedNameWaits(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	ka := laptop.put("a", "secret-1")
	kb := laptop.put("b", "secret-2")
	settleN(t, f, 6, laptop, desktop)
	low, high := ka, kb
	if uidOfKey(t, laptop, ka) > uidOfKey(t, laptop, kb) {
		low, high = kb, ka
	}
	highUID := uidOfKey(t, laptop, high)
	kc := vault.Key{Kind: vault.KindPassword, Service: "c", Username: "alice"}
	// laptop: high moves off its name to c, low takes high's name.
	if _, err := laptop.store.Edit(high, database.EntryEdit{To: &kc}); err != nil {
		t.Fatal(err)
	}
	to := high
	if _, err := laptop.store.Edit(low, database.EntryEdit{To: &to}); err != nil {
		t.Fatal(err)
	}
	syncLoose(laptop, f)
	// On the desktop, the high entry's own file is still to download (a
	// placeholder), but a sync tool's copy of the laptop's file is there.
	dir := filepath.Join(f.Dir(), "entries")
	own := filepath.Join(dir, highUID+".sesh")
	b, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, highUID+" (laptop's conflicted copy).sesh"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(own, filepath.Join(dir, "."+highUID+".sesh.icloud")); err != nil {
		t.Fatal(err)
	}
	s := syncLoose(desktop, f)
	t.Logf("desktop: %s; problems %q; files %q", s, s.Problems, entryFiles(f))
	if _, err := os.Stat(own); err == nil {
		t.Errorf("desktop wrote %s over a file not downloaded yet (NotDownloaded=%d)", filepath.Base(own), s.NotDownloaded)
	}
}

// A password changed on one computer is written once: the other writes
// nothing back for history it keeps more of.
func TestSync_OneWritePerChange(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	for _, c := range cs {
		c.store.SetHistoryKeep(3)
	}
	laptop.put("github", "pw-0")
	settleN(t, f, 6, laptop, desktop)
	for i := 1; i <= 6; i++ {
		laptop.put("github", fmt.Sprintf("pw-%d", i))
		var log []string
		for round := range 4 {
			quiet := true
			for _, c := range cs {
				s := syncLoose(c, f)
				if !s.Nothing() {
					quiet = false
					log = append(log, fmt.Sprintf("r%d %s: %s", round, c.name, s))
				}
			}
			if quiet {
				break
			}
		}
		// The laptop sends it, the desktop takes it: nothing more.
		if len(log) > 2 {
			t.Errorf("change %d: %s", i, strings.Join(log, " | "))
		}
	}
}

// A password both computers replaced, forgotten on one, is forgotten on
// both.
func TestSync_ForgetAfterConcurrentChange(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-old")
	settleN(t, f, 6, laptop, desktop)
	laptop.put("github", "pw-laptop")
	desktop.put("github", "pw-desktop")
	// laptop forgets pw-old (its version 2).
	if err := laptop.store.ForgetVersions(gh, 2); err != nil {
		t.Fatal(err)
	}
	t.Logf("laptop before sync: %q", allSecrets(t, laptop))
	settleN(t, f, 6, laptop, desktop)
	for _, c := range cs {
		t.Logf("%s: %q", c.name, allSecrets(t, c))
		if slices.Contains(allSecrets(t, c), "pw-old") {
			t.Errorf("%s: pw-old, forgotten on the laptop, is back", c.name)
		}
	}
}

// A password forgotten on one computer stays forgotten though the other,
// not having synced since, replaces it afterwards; whichever syncs first.
func TestSync_ForgetBeforeConcurrentChange(t *testing.T) {
	t.Parallel()
	for _, first := range []string{"laptop", "desktop"} {
		t.Run(first+" first", func(t *testing.T) {
			cs, _, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, laptop, desktop)
			laptop.put("github", "pw-laptop")
			// laptop forgets pw-old (its version 2), then the desktop replaces it.
			if err := laptop.store.ForgetVersions(gh, 2); err != nil {
				t.Fatal(err)
			}
			desktop.put("github", "pw-desktop")
			order := []*computer{laptop, desktop}
			if first == "desktop" {
				order = []*computer{desktop, laptop}
			}
			settleN(t, f, 6, order...)
			for _, c := range cs {
				if slices.Contains(allSecrets(t, c), "pw-old") {
					t.Errorf("%s: pw-old, forgotten on the laptop, is back (all %q)", c.name, allSecrets(t, c))
				}
			}
		})
	}
}

// A large file entry with a long history still syncs: the oldest earlier
// files aren't sent once it would be over MaxFileSize.
func TestSync_FileHistorySize(t *testing.T) {
	t.Parallel()
	if raceDetector {
		t.Skip("too slow with -race; run without it")
	}
	for _, keep := range []int{10, 50} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			cs, _, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			laptop.store.SetHistoryKeep(keep)
			k := vault.Key{Kind: vault.KindFile, Service: "kube", Username: "alice"}
			for i := range keep + 3 {
				b := make([]byte, 1<<20)
				for j := range b {
					b[j] = byte('a' + (i+j)%26)
				}
				copy(b, fmt.Sprintf("v%05d", i))
				for range 0 {
				}
				if err := laptop.store.Save(&vault.Entry{Key: k, Settings: vault.Settings{FileName: "config"}}, b); err != nil {
					t.Fatal(err)
				}
				if i%10 != 9 && i != keep+2 {
					continue
				}
				s := syncLoose(laptop, f)
				d := syncLoose(desktop, f)
				var size int64
				for _, n := range entryFiles(f) {
					if fi, err := os.Stat(filepath.Join(f.Dir(), "entries", n)); err == nil && fi.Size() > size {
						size = fi.Size()
					}
				}
				if len(s.Problems)+len(d.Problems) > 0 || size > syncfolder.MaxFileSize {
					t.Errorf("after %d versions: laptop %q; desktop %q; biggest file %d MiB", i+1, s.Problems, d.Problems, size>>20)
				}
				if got, err := desktop.store.Get(k); err != nil || !bytes.Equal(got, b) {
					t.Errorf("after %d versions: the desktop doesn't have the latest file (%v)", i+1, err)
				}
			}
		})
	}
}

// A secret field changed on both computers, the entry's details full: the
// newer's is kept on both, said in the summary.
func TestSync_SecretFieldDroppedWhenFull(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	notes := []byte(strings.Repeat("n", vault.MaxDetailsSize-4))
	set := func(c *computer, pin string) {
		if err := c.store.SetDetails(gh, &vault.Details{Notes: notes, Fields: []vault.Field{{Name: "pin", Value: []byte(pin), Secret: true}}}); err != nil {
			t.Fatal(err)
		}
	}
	set(laptop, "0000")
	settleN(t, f, 6, laptop, desktop)
	set(laptop, "1111")
	set(desktop, "2222")
	var said []string
	for range 3 {
		for _, c := range cs {
			said = append(said, syncLoose(c, f).Problems...)
		}
	}
	// The entry can't hold the older's beside the newer's: the newer's
	// kept, the same on both, and the summary says so.
	sameVaults(t, laptop, desktop)
	if !strings.Contains(strings.Join(said, "\n"), "secret fields don't fit beside the newer's") {
		t.Errorf("not said: %q", said)
	}
}

// A damaged agreed version, nothing changed: mended from the folder, and
// the syncs settle.
func TestSync_DamagedBaseQuiet(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	laptop.put("github", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	rawExec(t, paths[1], `UPDATE sync_state SET base = x'00'`)
	syncLoose(desktop, f)
	// Mended from the folder's file: the next syncs are quiet.
	for i := range 3 {
		if s := syncLoose(desktop, f); !s.Nothing() {
			t.Errorf("desktop sync %d after: %s %q", i+1, s, s.Problems)
		}
	}
}

// A vault replaced from its own older backup syncs its next changes: it
// gets a new sync ID, not its old counts.
func TestSync_ReplaceVaultCounter(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{"pw-2", "pw-3", "pw-4"} {
		laptop.put("github", pw)
		settleN(t, f, 6, laptop, desktop)
	}
	if err := laptop.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReplaceVault(paths[0], backup, time.Now()); err != nil {
		t.Fatal(err)
	}
	laptop.store = openVault(t, paths[0])
	for range 3 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s %q", c.name, s, s.Problems)
		}
	}
	t.Logf("after replace+sync: laptop %q desktop %q", laptop.secret(gh), desktop.secret(gh))
	laptop.put("github", "pw-5")
	for range 3 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s %q ignored=%d", c.name, s, s.Problems, s.Ignored)
		}
	}
	t.Logf("laptop %q (%q), desktop %q (%q)", laptop.secret(gh), allSecrets(t, laptop), desktop.secret(gh), allSecrets(t, desktop))
	if desktop.secret(gh) != "pw-5" || laptop.secret(gh) != "pw-5" {
		t.Errorf("pw-5, the laptop's change after the restore, isn't the password on both")
	}
}

// A computer set up from another's backup doesn't share its sync ID.
func TestSync_ReplaceVaultSharedID(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	other := laptop.put("other", "o-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReplaceVault(paths[1], backup, time.Now()); err != nil {
		t.Fatal(err)
	}
	desktop.store = openVault(t, paths[1])
	a, _ := laptop.store.SyncComputerID()  //nolint:errcheck // compared
	b, _ := desktop.store.SyncComputerID() //nolint:errcheck // compared
	if a == b {
		t.Errorf("both have the sync ID %s", a)
	}
	settleN(t, f, 6, laptop, desktop)
	for _, pw := range []string{"o-2", "o-3", "o-4"} {
		laptop.put("other", pw)
		laptop.sync(f)
	}
	laptop.put("github", "pw-1b")
	settleN(t, f, 6, laptop, desktop)
	desktop.put("github", "pw-2")
	for range 3 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s ignored=%d", c.name, s, s.Ignored)
		}
	}
	t.Logf("github: laptop %q desktop %q; other: laptop %q desktop %q", laptop.secret(gh), desktop.secret(gh), laptop.secret(other), desktop.secret(other))
	if laptop.secret(gh) != "pw-2" {
		t.Errorf("the desktop's pw-2 never reached the laptop (laptop secrets %q)", allSecrets(t, laptop))
	}
}

// A file entry changed on one computer is written once, not back again.
func TestSync_FileOneWritePerChange(t *testing.T) {
	t.Parallel()
	if raceDetector {
		t.Skip("too slow with -race; run without it")
	}
	cs, _, f := computers(t, 2)
	laptop := cs[0]
	k := vault.Key{Kind: vault.KindFile, Service: "kube", Username: "alice"}
	put := func(i int) {
		b := make([]byte, 1<<20)
		for j := range b {
			b[j] = byte('a' + (i+j)%26)
		}
		copy(b, fmt.Sprintf("v%05d", i))
		if err := laptop.store.Save(&vault.Entry{Key: k, Settings: vault.Settings{FileName: "config"}}, b); err != nil {
			t.Fatal(err)
		}
	}
	put(0)
	settleN(t, f, 6, cs...)
	uid := uidOfKey(t, laptop, k)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	for i := 1; i <= 14; i++ {
		put(i)
		var log []string
		writes := 0
		for round := range 4 {
			quiet := true
			for _, c := range cs {
				before, _ := os.ReadFile(own) //nolint:errcheck // test
				s := syncLoose(c, f)
				after, _ := os.ReadFile(own) //nolint:errcheck // test
				if string(before) != string(after) {
					log = append(log, fmt.Sprintf("r%d %s wrote %d MiB (%s)", round, c.name, len(after)>>20, s))
					writes++
				}
				if !s.Nothing() {
					quiet = false
				}
			}
			if quiet {
				break
			}
		}
		// Written once, by the laptop.
		if writes != 1 {
			t.Errorf("change %d: %s", i, strings.Join(log, " | "))
		}
	}
}
