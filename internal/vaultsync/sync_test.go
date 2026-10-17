package vaultsync

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// computer is one computer syncing: its own vault, by name.
type computer struct {
	t     *testing.T
	store *database.Store
	name  string
}

func openVault(t *testing.T, path string) *database.Store {
	t.Helper()
	prompt := func(string) ([]byte, error) { return []byte("correct horse battery"), nil }
	s, err := database.Open(path, database.NewKeySourceOracle(database.NewMasterPasswordSource(path, prompt, database.WithKDFParams(kdf.Minimum()))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test cleanup
	s.SetTrashDays(30)
	s.SetHistoryKeep(10)
	return s
}

// twoComputers are a laptop and a desktop, each with its own vault under
// one master password, and the sync folder they share.
func twoComputers(t *testing.T) (laptop, desktop *computer, folder syncfolder.Folder) {
	t.Helper()
	dir := t.TempDir()
	a := filepath.Join(dir, "laptop", "passwords.db")
	b := filepath.Join(dir, "desktop", "passwords.db")
	for _, p := range []string{a, b} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	la := openVault(t, a)
	// The key record is made with the first entry sealed.
	first := vault.Key{Kind: vault.KindPassword, Service: "first"}
	if err := la.Put(first, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := la.PurgeMany([]vault.Key{first}); err != nil {
		t.Fatal(err)
	}
	// The desktop's vault has the laptop's key record, as joining gives it.
	if err := database.CopyTo(a, b); err != nil {
		t.Fatal(err)
	}
	return &computer{t: t, store: la, name: "laptop"}, &computer{t: t, store: openVault(t, b), name: "desktop"}, syncfolder.New(filepath.Join(dir, "sync"))
}

func (c *computer) sync(f syncfolder.Folder) *Summary {
	c.t.Helper()
	s, err := Sync(c.store, f, c.name)
	if err != nil {
		c.t.Fatalf("%s: sync: %v", c.name, err)
	}
	for _, p := range s.Problems {
		c.t.Errorf("%s: sync problem: %s", c.name, p)
	}
	return s
}

func (c *computer) put(service, secret string) vault.Key {
	c.t.Helper()
	k := vault.Key{Kind: vault.KindPassword, Service: service, Username: "alice"}
	if err := c.store.Put(k, []byte(secret)); err != nil {
		c.t.Fatal(err)
	}
	return k
}

func (c *computer) secret(k vault.Key) string {
	c.t.Helper()
	b, err := c.store.Get(k)
	if err != nil {
		c.t.Fatalf("%s: %s: %v", c.name, k, err)
	}
	return string(b)
}

// settle syncs both computers until neither has anything more to do, and
// fails t unless they then hold the same entries.
func settle(t *testing.T, f syncfolder.Folder, cs ...*computer) {
	t.Helper()
	for range 4 {
		quiet := true
		for _, c := range cs {
			if !c.sync(f).Nothing() {
				quiet = false
			}
		}
		if quiet {
			sameVaults(t, cs[0], cs[1])
			return
		}
	}
	t.Fatal("still syncing after 4 rounds")
}

// sameVaults fails t unless a and b hold the same entries: names, secrets,
// details, folders, tags, the trash and earlier secrets.
func sameVaults(t *testing.T, a, b *computer) {
	t.Helper()
	ia, err := a.store.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	ib, err := b.store.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	live := func(items []database.SyncItem) (out []string) {
		for _, it := range items {
			if it.Place != database.SyncGone {
				out = append(out, it.UID)
			}
		}
		return out
	}
	if !slices.Equal(live(ia), live(ib)) {
		t.Fatalf("entries differ: %s has %q, %s %q", a.name, live(ia), b.name, live(ib))
	}
	for _, uid := range live(ia) {
		ra, _, err := a.store.SyncRecord(uid, "x")
		if err != nil {
			t.Fatal(err)
		}
		rb, _, err := b.store.SyncRecord(uid, "x")
		if err != nil {
			t.Fatal(err)
		}
		if ra.Service != rb.Service || ra.Username != rb.Username || ra.Kind != rb.Kind || !bytes.Equal(ra.Secret, rb.Secret) ||
			ra.URL != rb.URL || ra.Folder != rb.Folder || !bytes.Equal(ra.Notes, rb.Notes) || !slices.Equal(ra.Tags, rb.Tags) ||
			ra.Deleted.IsZero() != rb.Deleted.IsZero() || len(ra.Fields) != len(rb.Fields) || !sameHistory(secrets(ra.History), secrets(rb.History)) {
			t.Errorf("%s differs:\n%s %+v\n%s %+v", uid, a.name, ra, b.name, rb)
		}
	}
}

// sameHistory says whether a and b, earlier secrets, agree: each computer
// keeps its own number, so the shorter's are among the longer's (when
// each was replaced can differ, one having trimmed its first record of
// it).
func sameHistory(a, b []string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func secrets(hs []syncfolder.Earlier) (out []string) {
	for _, h := range hs {
		out = append(out, string(h.Secret))
	}
	return out
}

// An entry made on one computer reaches the other with everything it
// holds; a change there comes back; a rename is the same entry renamed.
func TestSync_BothWays(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	d := &vault.Details{URL: "https://github.com", Notes: []byte("notes"), Fields: []vault.Field{{Name: "pin", Value: []byte("1234"), Secret: true}}}
	if err := laptop.store.SaveWithDetails(&vault.Entry{Key: gh, Folder: "work", Tags: []string{"code"}}, []byte("pw-2"), d); err != nil {
		t.Fatal(err)
	}
	if s := laptop.sync(f); len(s.Sent) != 1 {
		t.Fatalf("laptop sent %q", s.Sent)
	}
	if s := desktop.sync(f); len(s.Received) != 1 || desktop.secret(gh) != "pw-2" {
		t.Fatalf("desktop received %q", s.Received)
	}
	sameVaults(t, laptop, desktop)
	if h, err := desktop.store.History(gh); err != nil || len(h) != 1 {
		t.Errorf("desktop history: %d, %v", len(h), err)
	}
	// Nothing new: nothing to do, either side.
	for _, c := range []*computer{laptop, desktop} {
		if s := c.sync(f); !s.Nothing() {
			t.Errorf("%s: %+v, want nothing", c.name, s)
		}
	}
	desktop.put("github", "pw-3")
	settle(t, f, laptop, desktop)
	if laptop.secret(gh) != "pw-3" {
		t.Errorf("laptop has %q", laptop.secret(gh))
	}
	to := vault.Key{Kind: vault.KindPassword, Service: "github-work", Username: "alice"}
	if _, err := laptop.store.Edit(gh, database.EntryEdit{To: &to}); err != nil {
		t.Fatal(err)
	}
	settle(t, f, laptop, desktop)
	if desktop.secret(to) != "pw-3" {
		t.Error("the rename didn't reach the desktop")
	}
	if err := desktop.store.Exists(gh); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("the old name on the desktop: %v", err)
	}
}

// One entry changed on both computers before they sync is merged: each
// one's changes, the newer password kept, the older in the history.
func TestSync_ChangedOnBoth(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	laptop.put("github", "laptop-pw")
	if err := laptop.store.SetDetails(gh, &vault.Details{Notes: []byte("from the laptop")}); err != nil {
		t.Fatal(err)
	}
	desktop.put("github", "desktop-pw")
	if _, err := desktop.store.AddTag([]vault.Key{gh}, "home"); err != nil {
		t.Fatal(err)
	}
	laptop.sync(f)
	s := desktop.sync(f)
	if len(s.Merged) != 1 || !slices.Contains(s.Merged[0].Conflicts, "secret") {
		t.Fatalf("merged %+v", s.Merged)
	}
	settle(t, f, laptop, desktop)
	if got := desktop.secret(gh); got != "desktop-pw" {
		t.Errorf("secret %q, want the newer, desktop-pw", got)
	}
	e, err := laptop.store.Lookup(gh)
	if err != nil || !slices.Equal(e.Tags, []string{"home"}) || !e.HasNotes {
		t.Errorf("laptop: %+v, %v", e, err)
	}
	r, _, err := laptop.store.SyncRecord(uidOfKey(t, laptop, gh), "x")
	if err != nil || !slices.Contains(secrets(r.History), "laptop-pw") || !slices.Contains(secrets(r.History), "pw-1") {
		t.Errorf("history %q, %v; want laptop-pw and pw-1 kept", secrets(r.History), err)
	}
}

func uidOfKey(t *testing.T, c *computer, k vault.Key) string {
	t.Helper()
	items, err := c.store.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Key == k {
			return it.UID
		}
	}
	t.Fatalf("%s: no %s", c.name, k)
	return ""
}

// Moving to the trash, restoring and deleting for good each reach the
// other computer; an entry edited on one and deleted on the other comes
// back.
func TestSync_TrashAndDeletion(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	if err := laptop.store.Delete(gh); err != nil {
		t.Fatal(err)
	}
	settle(t, f, laptop, desktop)
	if tr, err := desktop.store.Trash(); err != nil || len(tr) != 1 {
		t.Fatalf("desktop trash: %v, %v", tr, err)
	}
	tr, _ := desktop.store.Trash() //nolint:errcheck // read above
	if _, err := desktop.store.RestoreFromTrash(tr[0].ID, vault.Key{}); err != nil {
		t.Fatal(err)
	}
	settle(t, f, laptop, desktop)
	if laptop.secret(gh) != "pw-1" {
		t.Error("the restore didn't reach the laptop")
	}
	// Deleted on the laptop, edited on the desktop: back, with the edit.
	if err := laptop.store.Delete(gh); err != nil {
		t.Fatal(err)
	}
	desktop.put("github", "pw-2")
	settle(t, f, laptop, desktop)
	if laptop.secret(gh) != "pw-2" {
		t.Error("the edit didn't bring it back")
	}
	// Deleted for good: gone on both, and its file says so.
	if err := laptop.store.PurgeMany([]vault.Key{gh}); err != nil {
		t.Fatal(err)
	}
	settle(t, f, laptop, desktop)
	if err := desktop.store.Exists(gh); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("desktop still has it: %v", err)
	}
	if tr, _ := desktop.store.Trash(); len(tr) != 0 { //nolint:errcheck // a count
		t.Errorf("desktop trash: %v", tr)
	}
}

// Entries made on both computers under one name: with the same secret
// they become one; with others, both are kept, the same one renamed on
// both.
func TestSync_SameName(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	same := laptop.put("netflix", "same-pw")
	desktop.put("netflix", "same-pw")
	laptop.put("bank", "laptop-pw")
	desktop.put("bank", "desktop-pw")
	laptop.sync(f)
	s := desktop.sync(f)
	if len(s.Joined) != 1 || len(s.Renamed) != 1 || s.Renamed[0] != "password/bank (2)/alice" {
		t.Fatalf("joined %q, renamed %q", s.Joined, s.Renamed)
	}
	settle(t, f, laptop, desktop)
	if laptop.secret(same) != "same-pw" {
		t.Error("netflix lost")
	}
	b2 := vault.Key{Kind: vault.KindPassword, Service: "bank (2)", Username: "alice"}
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank", Username: "alice"}
	got := map[string]bool{laptop.secret(bank): true, laptop.secret(b2): true}
	if !got["laptop-pw"] || !got["desktop-pw"] {
		t.Errorf("bank and bank (2) on the laptop: %v", got)
	}
	// The one with the lower uid keeps the name.
	if uidOfKey(t, laptop, bank) > uidOfKey(t, laptop, b2) {
		t.Error("the higher uid kept the name")
	}
}

// A sync tool's copy of an entry's file (two computers writing it at
// once) is merged, then removed; a file lost from the folder is written
// again, not taken for a deletion; an older copy put back is ignored.
func TestSync_WhatSyncToolsDo(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	uid := uidOfKey(t, laptop, gh)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	old, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}

	// Both write at once: the laptop's lands as the file, the desktop's as
	// Dropbox's copy.
	laptop.put("github", "laptop-pw")
	laptop.sync(f)
	laptops, _ := os.ReadFile(own) //nolint:errcheck // read just after
	if err := os.WriteFile(own, old, 0o600); err != nil {
		t.Fatal(err)
	}
	desktop.put("github", "desktop-pw")
	desktop.sync(f)
	conflicted := filepath.Join(f.Dir(), "entries", uid+" (desktop's conflicted copy).sesh")
	desktops, _ := os.ReadFile(own) //nolint:errcheck // read just after
	if err := os.WriteFile(conflicted, desktops, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, laptops, 0o600); err != nil {
		t.Fatal(err)
	}
	// Merged by the first sync that reads it, which removes it.
	laptop.sync(f)
	if _, err := os.Stat(conflicted); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the copy is still there: %v", err)
	}
	settle(t, f, laptop, desktop)
	r, _, _ := laptop.store.SyncRecord(uid, "x") //nolint:errcheck // checked by the merge below
	got := append([]string{string(r.Secret)}, secrets(r.History)...)
	if !slices.Contains(got, "laptop-pw") || !slices.Contains(got, "desktop-pw") {
		t.Errorf("after the copy: %q, want both passwords kept", got)
	}

	// Lost: written again, the entry kept; said as written again, not
	// sent, and the other computer, taking it, has nothing to say.
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	if s := laptop.sync(f); s.Rewritten != 1 || len(s.Sent) != 0 {
		t.Errorf("a lost file: %+v, want written again, not sent", s)
	}
	if s := desktop.sync(f); !s.Nothing() {
		t.Errorf("the file written again, as it was: %+v, want nothing said", s)
	}
	settle(t, f, laptop, desktop)
	if _, err := os.Stat(own); err != nil {
		t.Errorf("not written again: %v", err)
	}
	if desktop.secret(gh) == "" {
		t.Error("lost on the desktop")
	}

	// An older copy put back: ignored, and the file written again.
	now := desktop.secret(gh)
	if err := os.WriteFile(own, old, 0o600); err != nil {
		t.Fatal(err)
	}
	s := desktop.sync(f)
	if s.Ignored != 1 || desktop.secret(gh) != now {
		t.Errorf("an older copy: %+v, secret %q, want %q kept", s, desktop.secret(gh), now)
	}
	settle(t, f, laptop, desktop)
	if laptop.secret(gh) != now {
		t.Errorf("laptop: %q, want %q", laptop.secret(gh), now)
	}
}

// A file the sync tool hasn't downloaded yet is waited for: nothing is
// written over it.
func TestSync_NotDownloaded(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	uid := uidOfKey(t, laptop, gh)
	own := filepath.Join(f.Dir(), "entries", uid+".sesh")
	placeholder := filepath.Join(f.Dir(), "entries", "."+uid+".sesh.icloud")
	if err := os.Rename(own, placeholder); err != nil {
		t.Fatal(err)
	}
	desktop.put("github", "pw-2")
	s := desktop.sync(f)
	if s.NotDownloaded != 1 || len(s.Sent) != 0 {
		t.Errorf("summary %+v", s)
	}
	if _, err := os.Stat(own); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("written over a file not downloaded: %v", err)
	}
}

// Forgetting an earlier secret on purpose forgets it on every computer;
// a computer keeping fewer doesn't take them from the others.
func TestSync_History(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	for _, pw := range []string{"pw-2", "pw-3", "pw-4"} {
		laptop.put("github", pw)
	}
	settle(t, f, laptop, desktop)
	desktop.store.SetHistoryKeep(1)
	if _, err := desktop.store.PruneHistory(1); err != nil {
		t.Fatal(err)
	}
	if err := desktop.store.SetDetails(gh, &vault.Details{Notes: []byte("n")}); err != nil {
		t.Fatal(err)
	}
	desktop.sync(f)
	laptop.sync(f)
	if h, err := laptop.store.History(gh); err != nil || len(h) != 3 {
		t.Errorf("laptop history after the desktop trimmed its own: %d, %v; want 3", len(h), err)
	}
	// Forgotten on the laptop: version 2 (pw-3), on both.
	if err := laptop.store.ForgetVersions(gh, 2); err != nil {
		t.Fatal(err)
	}
	desktop.store.SetHistoryKeep(10)
	for range 3 {
		laptop.sync(f)
		desktop.sync(f)
	}
	for _, c := range []*computer{laptop, desktop} {
		r, _, err := c.store.SyncRecord(uidOfKey(t, c, gh), "x")
		if err != nil || slices.Contains(secrets(r.History), "pw-3") {
			t.Errorf("%s history %q, %v; want pw-3 forgotten", c.name, secrets(r.History), err)
		}
	}
}

// Names in the summary say what happened, in a line for the audit log.
func TestSummary_String(t *testing.T) {
	t.Parallel()
	s := &Summary{Received: []string{"a"}, Sent: []string{"b", "c"}, Ignored: 1}
	if got := s.String(); got != "Sync: 1 received, 2 sent, 1 older copies ignored" {
		t.Errorf("%q", got)
	}
	if got := (&Summary{}).String(); !strings.Contains(got, "nothing") {
		t.Errorf("%q", got)
	}
}

// otherKey seals with a key that isn't the vault's.
type otherKey struct{}

func (otherKey) EncryptEntry(p, aad []byte) ([]byte, []byte, error) {
	return database.EncryptEntry(bytes.Repeat([]byte{9}, 32), p, aad)
}

func (otherKey) DecryptEntry(d, s, aad []byte) ([]byte, error) {
	return database.DecryptEntry(bytes.Repeat([]byte{9}, 32), d, s, aad)
}

// An entry whose file was sealed with another master password's key (from
// a computer that changed it), or can't be read, waits: nothing here is
// written over it.
func TestSync_FilesNotForThisKey(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	bank := laptop.put("bank", "b-1")
	settle(t, f, laptop, desktop)
	ghFile := filepath.Join(f.Dir(), "entries", uidOfKey(t, laptop, gh)+".sesh")
	h, err := syncfolder.NewHeader(uidOfKey(t, laptop, gh), strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := syncfolder.Seal(otherKey{}, h, &syncfolder.Record{Service: "github", Secret: []byte("theirs")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ghFile, other, 0o600); err != nil {
		t.Fatal(err)
	}
	bankFile := filepath.Join(f.Dir(), "entries", uidOfKey(t, laptop, bank)+".sesh")
	if err := os.WriteFile(bankFile, []byte("not readable yet"), 0o600); err != nil {
		t.Fatal(err)
	}
	laptop.put("github", "pw-2")
	laptop.put("bank", "b-2")
	s, err := Sync(laptop.store, f, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if s.OtherKey != 1 || len(s.Sent) != 0 || len(s.Problems) != 1 {
		t.Errorf("summary %+v", s)
	}
	if b, _ := os.ReadFile(ghFile); !bytes.Equal(b, other) { //nolint:errcheck // compared
		t.Error("written over the other key's file")
	}
	if b, _ := os.ReadFile(bankFile); string(b) != "not readable yet" { //nolint:errcheck // compared
		t.Error("written over a file that couldn't be read")
	}
}
