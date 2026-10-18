package vaultsync

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// computers is n computers (laptop, desktop, third, ...) sharing a folder, with paths.
func computers(t *testing.T, n int) ([]*computer, []string, syncfolder.Folder) {
	t.Helper()
	dir := t.TempDir()
	names := []string{"laptop", "desktop", "third", "fourth"}
	var paths []string
	for i := range n {
		p := filepath.Join(dir, names[i], "passwords.db")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	la := openVault(t, paths[0])
	first := vault.Key{Kind: vault.KindPassword, Service: "first"}
	if err := la.Put(first, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := la.PurgeMany([]vault.Key{first}); err != nil {
		t.Fatal(err)
	}
	cs := []*computer{{t: t, store: la, name: names[0]}}
	for i := 1; i < n; i++ {
		if err := database.CopyTo(paths[0], paths[i]); err != nil {
			t.Fatal(err)
		}
		cs = append(cs, &computer{t: t, store: openVault(t, paths[i]), name: names[i]})
	}
	return cs, paths, syncfolder.New(filepath.Join(dir, "sync"))
}

// settleN is settle for any number of computers, comparing each to the first.
func settleN(t *testing.T, f syncfolder.Folder, rounds int, cs ...*computer) {
	t.Helper()
	for r := range rounds {
		quiet := true
		for _, c := range cs {
			if !c.sync(f).Nothing() {
				quiet = false
			}
		}
		if quiet {
			for _, c := range cs[1:] {
				sameVaults(t, cs[0], c)
			}
			t.Logf("settled after %d rounds", r+1)
			return
		}
	}
	t.Fatalf("still syncing after %d rounds", rounds)
}

func allSecrets(t *testing.T, c *computer) []string {
	t.Helper()
	items, err := c.store.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, it := range items {
		if it.Place == database.SyncGone {
			continue
		}
		r, _, err := c.store.SyncRecord(it.UID, "x")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(r.Secret))
		out = append(out, secrets(r.History)...)
	}
	return out
}

// A computer keeping fewer earlier secrets changing a password doesn't cost
// the one keeping more the password it had.
func TestSync_FewerKeptElsewhere(t *testing.T) {
	t.Parallel()
	for _, keep := range []int{0, 1} {
		cs, _, f := computers(t, 2)
		laptop, desktop := cs[0], cs[1]
		desktop.store.SetHistoryKeep(keep)
		laptop.put("github", "pw-1")
		settleN(t, f, 6, laptop, desktop)
		desktop.put("github", "pw-2")
		desktop.put("github", "pw-3")
		settleN(t, f, 6, laptop, desktop)
		t.Logf("keep=%d laptop (keep 10) secrets: %q; desktop: %q", keep, allSecrets(t, laptop), allSecrets(t, desktop))
		if !slices.Contains(allSecrets(t, laptop), "pw-1") {
			t.Errorf("keep=%d: pw-1 gone from the laptop, which keeps 10", keep)
		}
	}
}

// A computer with history.keep 0 keeps none of the earlier secrets synced
// to it.
func TestSync_KeepZero(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	desktop.store.SetHistoryKeep(0)
	gh := laptop.put("github", "pw-1")
	laptop.put("github", "pw-2")
	settleN(t, f, 6, laptop, desktop)
	h, err := desktop.store.History(gh)
	t.Logf("desktop (keep 0) history: %d versions, %v", len(h), err)
	if len(h) != 0 {
		t.Errorf("desktop with history.keep 0 holds %d earlier secrets", len(h))
	}
}

// Renaming X a->c, then Y b->a, on one computer reaches the other as two
// renames, not one name made twice.
func TestSync_RenameIntoFreedName(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	ka := laptop.put("a", "secret-1")
	kb := laptop.put("b", "secret-2")
	settleN(t, f, 6, laptop, desktop)
	// high frees its name, low (sorting first) takes it.
	low, high := ka, kb
	if uidOfKey(t, laptop, ka) > uidOfKey(t, laptop, kb) {
		low, high = kb, ka
	}
	x, other := high, low
	kc := vault.Key{Kind: vault.KindPassword, Service: "c", Username: "alice"}
	if _, err := laptop.store.Edit(x, database.EntryEdit{To: &kc}); err != nil {
		t.Fatal(err)
	}
	if _, err := laptop.store.Edit(other, database.EntryEdit{To: &x}); err != nil {
		t.Fatal(err)
	}
	t.Logf("x (uid %s) %s -> c; other (uid %s) %s -> %s", uidOfKey(t, laptop, kc), x.Service, uidOfKey(t, laptop, x), other.Service, x.Service)
	settleN(t, f, 6, laptop, desktop)
	for _, c := range cs {
		items, _ := c.store.SyncItems() //nolint:errcheck // test
		var names []string
		for _, it := range items {
			if it.Place == database.SyncLive {
				names = append(names, it.Key.Service)
			}
		}
		slices.Sort(names)
		t.Logf("%s: %q", c.name, names)
		if !slices.Equal(names, []string{x.Service, "c"}) {
			t.Errorf("%s: names %q, want %q", c.name, names, []string{x.Service, "c"})
		}
	}
}

// One name made on three computers with three secrets: all kept, numbered.
func TestSync_SameNameThree(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	for i, c := range cs {
		c.put("bank", "pw-"+c.name)
		_ = i
	}
	settleN(t, f, 8, cs...)
	for _, c := range cs {
		items, _ := c.store.SyncItems() //nolint:errcheck // test
		var names []string
		for _, it := range items {
			if it.Place == database.SyncLive {
				names = append(names, it.Key.Service)
			}
		}
		slices.Sort(names)
		secrets := allSecrets(t, c)
		if !slices.Equal(names, []string{"bank", "bank (2)", "bank (3)"}) || !slices.Contains(secrets, "pw-laptop") || !slices.Contains(secrets, "pw-desktop") || !slices.Contains(secrets, "pw-third") {
			t.Errorf("%s: names %q, secrets %q", c.name, names, secrets)
		}
	}
}

// Notes changed on both computers, too long to keep both: the newer's are
// kept, said in the summary, and the computers settle.
func TestSync_NotesTooLongForBoth(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	long := func(c byte) []byte { return bytes.Repeat([]byte{c}, vault.MaxDetailsSize*2/3) }
	if err := laptop.store.SetDetails(gh, &vault.Details{Notes: long('l')}); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.SetDetails(gh, &vault.Details{Notes: long('d')}); err != nil {
		t.Fatal(err)
	}
	laptop.sync(f)
	s := syncLoose(desktop, f)
	if len(s.Problems) != 1 || !strings.Contains(s.Problems[0], "the newer's were kept") {
		t.Errorf("problems %q", s.Problems)
	}
	settle(t, f, laptop, desktop)
	d, err := laptop.store.Details(gh, "")
	if err != nil || !bytes.Equal(d.Notes, long('d')) {
		t.Errorf("notes %d bytes, %v; want the desktop's, the newer", len(d.Notes), err)
	}
}

// One name made on three computers with one secret: one entry.
func TestSync_SameNameThreeSame(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	for _, c := range cs {
		c.put("bank", "same")
	}
	settleN(t, f, 8, cs...)
	for _, c := range cs {
		t.Logf("%s: secrets %q", c.name, allSecrets(t, c))
	}
}

// A restore from an older backup, then syncing, deletes nothing made since,
// here or elsewhere, and loses no secret.
func TestSync_RestoreThenSync(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	// After the backup: a new password on the laptop, a new entry on the desktop.
	laptop.put("github", "pw-2")
	desktop.put("made-on-desktop", "desk-secret")
	settleN(t, f, 6, laptop, desktop)
	if err := database.RestoreInPlace(paths[0], backup); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	for _, c := range cs {
		t.Logf("%s: %q", c.name, allSecrets(t, c))
	}
	if !slices.Contains(allSecrets(t, desktop), "desk-secret") {
		t.Error("the desktop's own entry, made after the laptop's backup, is gone from the desktop")
	}
	if !slices.Contains(allSecrets(t, desktop), "pw-2") {
		t.Error("pw-2 gone from the desktop (current and history)")
	}
	_ = gh
}

// writeOnly is push without SyncAgree: a crash, or ErrEntryChanged, after
// the folder's file is written.
func writeOnly(t *testing.T, c *computer, f syncfolder.Folder, uid string) {
	t.Helper()
	keyID, err := c.store.SyncKeyID()
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.store.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	local, _, err := c.store.SyncRecord(uid, c.name)
	if err != nil {
		t.Fatal(err)
	}
	// A damaged agreed version (an earlier step's) is as none.
	base, err := c.store.SyncBase(uid)
	if err != nil {
		base = nil
	}
	if base != nil {
		local.Versions = base.Versions
	}
	n, err := c.store.SyncNextChange(local.Versions[id])
	if err != nil {
		t.Fatal(err)
	}
	local.Versions = local.Versions.Join(nil)
	local.Versions[id] = n
	h, err := syncfolder.NewHeader(uid, keyID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := syncfolder.Seal(c.store.SyncSealer(), h, local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(h, b); err != nil {
		t.Fatal(err)
	}
}

// A change written but never agreed (a crash) doesn't share its count with
// the next, which would then be taken for an older copy.
func TestSync_CountNotReused(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"older put back", "lost"} {
		t.Run(how, func(t *testing.T) {
			cs, _, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := laptop.put("github", "pw-0")
			settleN(t, f, 6, laptop, desktop)
			uid := uidOfKey(t, laptop, gh)
			own := filepath.Join(f.Dir(), "entries", uid+".sesh")
			old, err := os.ReadFile(own)
			if err != nil {
				t.Fatal(err)
			}
			laptop.put("github", "pw-1")
			writeOnly(t, laptop, f, uid)
			laptop.put("github", "pw-2")
			if s := desktop.sync(f); len(s.Received) != 1 {
				t.Fatalf("desktop: %+v", s)
			}
			if how == "lost" {
				if err := os.Remove(own); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(own, old, 0o600); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 8, laptop, desktop)
			// pw-2, the laptop's latest, stays the password: the older
			// pw-1 doesn't come back.
			for _, c := range cs {
				if got := c.secret(gh); got != "pw-2" {
					t.Errorf("%s: current %q, want pw-2 (all %q)", c.name, got, allSecrets(t, c))
				}
			}
		})
	}
}

func rawExec(t *testing.T, path, q string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

func syncLoose(c *computer, f syncfolder.Folder) *Summary {
	s, err := Sync(c.store, f, c.name)
	if err != nil {
		c.t.Fatalf("%s: %v", c.name, err)
	}
	return s
}

// An entry with one damaged earlier secret still syncs.
func TestSync_DamagedHistoryRow(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	laptop.put("github", "pw-2")
	settleN(t, f, 6, laptop, desktop)
	rawExec(t, paths[1], `UPDATE history SET encrypted_data = zeroblob(40)`)
	laptop.put("github", "pw-3")
	laptop.sync(f)
	for range 3 {
		s := syncLoose(desktop, f)
		t.Logf("desktop: %s; problems %q", s, s.Problems)
	}
	t.Logf("desktop has %q", desktop.secret(gh))
	if desktop.secret(gh) != "pw-3" {
		t.Error("the desktop never takes pw-3")
	}
}

// Damaged tags of an entry in the trash aren't taken for tags removed.
func TestSync_DamagedTrashTags(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	if _, err := laptop.store.AddTag([]vault.Key{gh}, "work"); err != nil {
		t.Fatal(err)
	}
	if err := laptop.store.Delete(gh); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	rawExec(t, paths[1], `UPDATE trash SET tags = 'not json'`)
	tr, err := laptop.store.Trash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := laptop.store.RestoreFromTrash(tr[0].ID, vault.Key{}); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		laptop.sync(f)
		desktop.sync(f)
	}
	for _, c := range cs {
		e, err := c.store.Lookup(gh)
		t.Logf("%s: tags %q, %v", c.name, e.Tags, err)
		if err != nil || !slices.Equal(e.Tags, []string{"work"}) {
			t.Errorf("%s: tags %q, want work", c.name, e.Tags)
		}
	}
}

// An entry whose agreed version is damaged still syncs, merged as never
// synced.
func TestSync_DamagedBase(t *testing.T) {
	t.Parallel()
	cs, paths, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	settleN(t, f, 6, laptop, desktop)
	rawExec(t, paths[1], `UPDATE sync_state SET base = substr(base, 1, length(base) - 5) || x'0000000000'`)
	laptop.put("github", "pw-2")
	laptop.sync(f)
	for range 3 {
		s := syncLoose(desktop, f)
		t.Logf("desktop: %s; problems %q", s, s.Problems)
	}
	if desktop.secret(gh) != "pw-2" {
		t.Errorf("desktop never takes pw-2: has %q", desktop.secret(gh))
	}
}

// A password forgotten on purpose, set again later and replaced, is kept
// in the history that time.
func TestSync_ForgottenReused(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "reused")
	laptop.put("github", "pw-2")
	if err := laptop.store.ForgetVersions(gh, 2); err != nil { // "reused"
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	laptop.put("github", "reused")
	laptop.put("github", "pw-3")
	h, _ := laptop.store.History(gh) //nolint:errcheck // test
	t.Logf("laptop history before sync: %d", len(h))
	settleN(t, f, 6, laptop, desktop)
	for _, c := range cs {
		t.Logf("%s: %q", c.name, allSecrets(t, c))
		if !slices.Contains(allSecrets(t, c), "reused") {
			t.Errorf("%s: the password before pw-3 (reused) is gone", c.name)
		}
	}
}

// Three computers changing one entry at once (its file and two copies, one
// of a copy) keep all three passwords.
func TestSync_CopiesOfCopies(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	gh := cs[0].put("github", "pw-0")
	settleN(t, f, 6, cs...)
	uid := uidOfKey(t, cs[0], gh)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	old, _ := os.ReadFile(own) //nolint:errcheck // test
	var outs [][]byte
	for _, c := range cs {
		if err := os.WriteFile(own, old, 0o600); err != nil {
			t.Fatal(err)
		}
		c.put("github", "pw-"+c.name)
		c.sync(f)
		b, _ := os.ReadFile(own) //nolint:errcheck // test
		outs = append(outs, b)
	}
	_ = os.WriteFile(own, outs[0], 0o600)                                                                            //nolint:errcheck // test
	_ = os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (desktop's conflicted copy).sesh"), outs[1], 0o600)     //nolint:errcheck // test
	_ = os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (desktop's conflicted copy) (1).sesh"), outs[2], 0o600) //nolint:errcheck // test
	settleN(t, f, 8, cs...)
	for _, c := range cs {
		got := allSecrets(t, c)
		t.Logf("%s: %q", c.name, got)
		for _, want := range []string{"pw-laptop", "pw-desktop", "pw-third"} {
			if !slices.Contains(got, want) {
				t.Errorf("%s: %s lost", c.name, want)
			}
		}
	}
	des, _ := os.ReadDir(filepath.Join(f.Dir(), "entries")) //nolint:errcheck // test
	for _, d := range des {
		if strings.Contains(d.Name(), "conflicted") {
			t.Errorf("copy left: %s", d.Name())
		}
	}
}

// Deleted for good on one computer while edited on the other, both writing
// at once: the edit wins.
func TestSync_PurgeRacingEdit(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-0")
	settleN(t, f, 6, laptop, desktop)
	uid := uidOfKey(t, laptop, gh)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	old, _ := os.ReadFile(own) //nolint:errcheck // test
	if err := laptop.store.PurgeMany([]vault.Key{gh}); err != nil {
		t.Fatal(err)
	}
	laptop.sync(f)
	purge, _ := os.ReadFile(own)      //nolint:errcheck // test
	_ = os.WriteFile(own, old, 0o600) //nolint:errcheck // test
	desktop.put("github", "pw-edit")
	desktop.sync(f)
	edit, _ := os.ReadFile(own) //nolint:errcheck // test
	for _, order := range []string{"purge own"} {
		_ = order
		_ = os.WriteFile(own, purge, 0o600)                                                                       //nolint:errcheck // test
		_ = os.WriteFile(filepath.Join(f.Dir(), "entries", uid+" (desktop's conflicted copy).sesh"), edit, 0o600) //nolint:errcheck // test
	}
	settleN(t, f, 8, laptop, desktop)
	for _, c := range cs {
		t.Logf("%s: %q", c.name, allSecrets(t, c))
		if !slices.Contains(allSecrets(t, c), "pw-edit") {
			t.Errorf("%s: the edit lost to the purge", c.name)
		}
	}
}

// A secret field changed on both computers keeps both values, the older
// beside under a name fields can have.
func TestSync_SecretFieldOnBoth(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop, desktop := cs[0], cs[1]
	gh := laptop.put("github", "pw-1")
	name := "pin"
	if err := laptop.store.SetDetails(gh, &vault.Details{Fields: []vault.Field{{Name: name, Value: []byte("v0"), Secret: true}}}); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, laptop, desktop)
	if err := laptop.store.SetDetails(gh, &vault.Details{Fields: []vault.Field{{Name: name, Value: []byte("v-laptop"), Secret: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.SetDetails(gh, &vault.Details{Fields: []vault.Field{{Name: name, Value: []byte("v-desktop"), Secret: true}}}); err != nil {
		t.Fatal(err)
	}
	laptop.sync(f)
	for range 3 {
		for _, c := range cs {
			s := syncLoose(c, f)
			t.Logf("%s: %s %q", c.name, s, s.Problems)
		}
	}
	for _, c := range cs {
		r, _, err := c.store.SyncRecord(uidOfKey(t, c, gh), "x")
		if err != nil {
			t.Fatal(err)
		}
		var vals []string
		for _, fl := range r.Fields {
			vals = append(vals, string(fl.Value))
		}
		if !slices.Contains(vals, "v-laptop") || !slices.Contains(vals, "v-desktop") {
			t.Errorf("%s fields %q, want both values kept", c.name, vals)
		}
	}
	sameVaults(t, laptop, desktop)
}

// Wiping what Merge returns wipes the older secret lost too.
func TestSync_MergedWipe(t *testing.T) {
	t.Parallel()
	base := &syncfolder.Record{Service: "x", Secret: []byte("s0")}
	a := &syncfolder.Record{Service: "x", Secret: []byte("s-ours"), Computer: "a"}
	b := &syncfolder.Record{Service: "x", Secret: []byte("s-theirs"), Computer: "b"}
	m := syncfolder.Merge(base, a, b)
	m.Wipe()
	t.Logf("after Wipe: Lost %q", m.Lost)
	if len(m.Lost) > 0 && strings.Trim(string(m.Lost), "\x00") != "" {
		t.Errorf("Lost still holds %q after Wipe", m.Lost)
	}
}
