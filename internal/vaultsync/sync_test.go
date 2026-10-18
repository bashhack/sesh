package vaultsync

import (
	"bytes"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

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

// A computer that only takes still makes the folder's entries readable
// only by its user, as a sync tool may make it for anyone.
func TestSync_TakingTightensTheFolder(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	laptop.put("github", "pw-1")
	laptop.sync(f)
	dir := filepath.Join(f.Dir(), "entries")
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // a folder anyone can read, as a sync tool may leave it
		t.Fatal(err)
	}
	info := filepath.Join(f.Dir(), syncfolder.InfoFile)
	if err := os.WriteFile(info, []byte("{}"), 0o644); err != nil { //nolint:gosec // readable by anyone, as a sync tool may leave it
		t.Fatal(err)
	}
	if err := os.Chmod(info, 0o644); err != nil { //nolint:gosec // as above
		t.Fatal(err)
	}
	desktop.sync(f)
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("entries/ after a sync that only took: %v, %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(info); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s after a sync that only took: %v, %v", syncfolder.InfoFile, fi.Mode(), err)
	}
}

// Tightening takes away only what others had, so a file kept read-only
// stays so; and a folder whose permissions can't be changed still syncs,
// the trouble said.
func TestSync_TightenKeepsAndSays(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	laptop.put("github", "pw-1")
	laptop.sync(f)
	info := filepath.Join(f.Dir(), syncfolder.InfoFile)
	if err := os.WriteFile(info, []byte("{}"), 0o444); err != nil { //nolint:gosec // read-only for all, as a user may keep it
		t.Fatal(err)
	}
	if err := os.Chmod(info, 0o444); err != nil { //nolint:gosec // as above
		t.Fatal(err)
	}
	desktop.sync(f)
	if fi, err := os.Stat(info); err != nil || fi.Mode().Perm() != 0o400 {
		t.Errorf("a read-only %s: %v, %v; want 0400", syncfolder.InfoFile, fi.Mode(), err)
	}
	if runtime.GOOS != "darwin" {
		return
	}
	// Locked (chflags uchg), so chmod fails.
	if err := os.Chmod(info, 0o644); err != nil { //nolint:gosec // readable by others again
		t.Fatal(err)
	}
	if err := exec.Command("chflags", "uchg", info).Run(); err != nil {
		t.Skip("chflags:", err)
	}
	t.Cleanup(func() { _ = exec.Command("chflags", "nouchg", info).Run() }) //nolint:errcheck // test cleanup
	laptop.put("gitlab", "pw-2")
	s, err := Sync(laptop.store, f, laptop.name)
	if err != nil || len(s.Problems) != 0 || len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "readable only by you") || len(s.Sent) != 1 {
		t.Errorf("a locked %s: %+v, %v; want it said and the rest synced", syncfolder.InfoFile, s, err)
	}
}

func openVaultPw(t *testing.T, path, pw string) *database.Store {
	t.Helper()
	prompt := func(string) ([]byte, error) { return []byte(pw), nil }
	s, err := database.Open(path, database.NewKeySourceOracle(database.NewMasterPasswordSource(path, prompt, database.WithKDFParams(kdf.Minimum()))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test cleanup
	s.SetTrashDays(30)
	s.SetHistoryKeep(10)
	return s
}

// changeKey changes c's master password to pw, as passwd does while the
// vault syncs (the change kept as a key link), and returns its vault opened
// with the new one and the key record.
func changeKey(t *testing.T, c *computer, oldPW, pw string) (*computer, database.UnlockMaterial) {
	t.Helper()
	path := c.store.Path()
	old, err := database.ReadUnlockMaterial(path)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := database.DeriveKey([]byte(oldPW), old.Salt, old.Params)
	newKey, rec, err := database.NewMasterPasswordSource(path, func(string) ([]byte, error) { return []byte(pw), nil }, database.WithKDFParams(kdf.Minimum())).NewKey()
	if err != nil {
		t.Fatal(err)
	}
	oldID, newID := database.UnlockID(old.Verify), database.UnlockID(rec.Verify)
	link, err := database.NewKeyLink(oldKey, newKey, oldID, newID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.Rekey(newKey, rec, nil, database.RekeyOptions{Sync: database.RekeySend, Link: link}); err != nil {
		t.Fatal(err)
	}
	return &computer{t: t, store: openVaultPw(t, path, pw), name: c.name}, rec
}

// takeKey switches c to the master password pw, the key record rec, with
// the links of from (the computer that changed it), as taking a change
// does, and returns its vault opened with it.
func takeKey(t *testing.T, c *computer, from *computer, rec database.UnlockMaterial, pw string) *computer {
	t.Helper()
	links, err := from.store.SyncKeyLinks()
	if err != nil {
		t.Fatal(err)
	}
	key := database.DeriveKey([]byte(pw), rec.Salt, rec.Params)
	if _, err := c.store.Rekey(key, rec, nil, database.RekeyOptions{Sync: database.RekeyAdopt, Links: links}); err != nil {
		t.Fatal(err)
	}
	return &computer{t: t, store: openVaultPw(t, c.store.Path(), pw), name: c.name}
}

// syncOlder syncs c, opening files sealed with its older keys.
func syncOlder(t *testing.T, c *computer, f syncfolder.Folder) *Summary {
	t.Helper()
	older, err := c.store.SyncOlderKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer older.Close()
	s, err := SyncWith(c.store, f, c.name, Options{Older: older})
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	for _, p := range s.Problems {
		t.Errorf("%s: sync problem: %s", c.name, p)
	}
	return s
}

// A master password changed on the laptop: it seals the folder's files
// again with the new key; the desktop, until it takes the new password,
// reads none of them; an entry it writes meanwhile with the old key the
// laptop opens, through its key link, and seals again.
func TestSync_PasswordChange(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	laptop.put("github", "pw-1")
	laptop.put("gitlab", "pw-2")
	settle(t, f, laptop, desktop)
	before := scanFiles(t, f)[0]
	oldCopy, err := os.ReadFile(before.Path)
	if err != nil {
		t.Fatal(err)
	}

	laptopNew, rec := changeKey(t, laptop, "correct horse battery", "the new password 1")
	if s := syncOlder(t, laptopNew, f); s.Resealed != 2 {
		t.Fatalf("laptop, sealing again: %+v", s)
	}
	newID := database.UnlockID(rec.Verify)
	for _, file := range scanFiles(t, f) {
		if file.KeyIDString() != newID {
			t.Errorf("%s still sealed with the old key", file.Path)
		}
	}

	// The desktop, on the old password, reads nothing, and writes an entry
	// with the old key, which the laptop doesn't take (anyone with the old
	// password could have written it); the desktop sends it again under
	// the new key once it takes it.
	if before := desktop.sync(f); before.OtherKey != 2 {
		t.Errorf("desktop before taking the new password: %+v", before)
	}
	desktop.put("bank", "pw-3")
	desktop.sync(f)
	if s := syncOlder(t, laptopNew, f); s.EarlierKey != 1 || len(s.Received) != 0 {
		t.Errorf("laptop, the desktop's old-key entry: %+v", s)
	}

	desktopNew := takeKey(t, desktop, laptopNew, rec, "the new password 1")
	syncOlder(t, desktopNew, f)
	settle(t, f, laptopNew, desktopNew)
	for _, c := range []*computer{laptopNew, desktopNew} {
		if c.secret(vault.Key{Kind: vault.KindPassword, Service: "bank", Username: "alice"}) != "pw-3" {
			t.Errorf("%s hasn't the desktop's entry", c.name)
		}
	}

	// A file from before the change put back: not read, and written over
	// with the new key.
	if err := os.WriteFile(before.Path, oldCopy, 0o600); err != nil {
		t.Fatal(err)
	}
	if s := syncOlder(t, desktopNew, f); s.EarlierKey != 1 {
		t.Errorf("an old-key copy put back: %+v", s)
	}
	for _, file := range scanFiles(t, f) {
		if file.KeyIDString() != newID {
			t.Errorf("%s left sealed with the old key", file.Path)
		}
	}
}

// An entry written with the old key by a computer that hasn't taken the
// change isn't taken by those that have; it reaches them, under the new
// key, once that computer takes it, and no file stays on an old key.
func TestSync_PasswordChangeTakesUnseen(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 3)
	cs[0].put("github", "pw-1")
	settleN(t, f, 4, cs[0], cs[1], cs[2])
	// The desktop writes an entry with the old key; the third computer
	// hasn't seen it when it takes the new password.
	cs[1].put("bank", "pw-2")
	cs[1].sync(f)
	laptop, rec := changeKey(t, cs[0], "correct horse battery", "the new password 1")
	third := takeKey(t, cs[2], laptop, rec, "the new password 1")
	if s := syncOlder(t, third, f); len(s.Merged) != 0 || s.Resealed == 0 || s.EarlierKey != 1 || len(s.Received) != 0 {
		t.Fatalf("the third computer takes the new password: %+v; want files sealed again, the desktop's not taken", s)
	}
	desktop := takeKey(t, cs[1], laptop, rec, "the new password 1")
	syncOlder(t, desktop, f)
	settle(t, f, laptop, desktop, third)
	if third.secret(vault.Key{Kind: vault.KindPassword, Service: "bank", Username: "alice"}) != "pw-2" {
		t.Error("the third computer hasn't the desktop's entry")
	}
	newID := database.UnlockID(rec.Verify)
	for _, file := range scanFiles(t, f) {
		if file.KeyIDString() != newID {
			t.Errorf("%s still sealed with the old key", file.Path)
		}
	}
}

// Two master password changes, one after the other: a computer two
// changes behind is opened through both links.
func TestSync_PasswordChangeTwice(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	desktop.put("bank", "pw-2")
	desktop.sync(f)
	l1, _ := changeKey(t, laptop, "correct horse battery", "the new password 1")
	l2, rec := changeKey(t, l1, "the new password 1", "the new password 2")
	if s := syncOlder(t, l2, f); s.EarlierKey != 1 {
		t.Errorf("the laptop, two changes on, and the desktop's old-key entry: %+v", s)
	}
	d2 := takeKey(t, desktop, l2, rec, "the new password 2")
	syncOlder(t, d2, f)
	settle(t, f, l2, d2)
	if l2.secret(vault.Key{Kind: vault.KindPassword, Service: "bank", Username: "alice"}) != "pw-2" {
		t.Error("the laptop hasn't the desktop's entry once it took both changes")
	}
}

func scanFiles(t *testing.T, f syncfolder.Folder) []syncfolder.File {
	t.Helper()
	c, err := f.Scan()
	if err != nil {
		t.Fatal(err)
	}
	return c.Files
}

// An entry changed on one computer while the other only sealed its file
// again (a password change) or wrote it back (lost) is sent from the first,
// not said to be changed on both: nothing in it changed there.
func TestSync_EditOverSealedAgain(t *testing.T) {
	t.Parallel()
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}

	laptop, desktop, f := twoComputers(t)
	laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	desktop.put("github", "desktop-pw")
	laptopNew, rec := changeKey(t, laptop, "correct horse battery", "the new password 1")
	syncOlder(t, laptopNew, f)
	desktopNew := takeKey(t, desktop, laptopNew, rec, "the new password 1")
	s := syncOlder(t, desktopNew, f)
	if len(s.Merged) != 0 || len(s.Sent) != 1 || s.Sent[0] != "password/github/alice" {
		t.Errorf("the desktop's edit over a file sealed again: %+v; want it sent, nothing merged", s)
	}
	settle(t, f, laptopNew, desktopNew)
	if got := laptopNew.secret(gh); got != "desktop-pw" {
		t.Errorf("the laptop has %q", got)
	}

	// The same with a file lost and written back by the laptop.
	laptop, desktop, f = twoComputers(t)
	laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	own := filepath.Join(f.Dir(), "entries", uidOfKey(t, laptop, gh)+".sesh")
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	laptop.sync(f)
	desktop.put("github", "desktop-pw")
	s = desktop.sync(f)
	if len(s.Merged) != 0 || len(s.Sent) != 1 {
		t.Errorf("the desktop's edit over a file written back: %+v; want it sent, nothing merged", s)
	}
	settle(t, f, laptop, desktop)
	if got := laptop.secret(gh); got != "desktop-pw" {
		t.Errorf("the laptop has %q", got)
	}
}

// After a master password change both computers took, a file sealed with
// the old key and holding a new secret (someone with the old password and
// an older sesh-sync.json) is taken by neither, and written over.
func TestSync_EarlierKeyChangeNotTaken(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	gh := laptop.put("github", "pw-1")
	settle(t, f, laptop, desktop)
	old, err := database.ReadUnlockMaterial(laptop.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	laptopNew, rec := changeKey(t, laptop, "correct horse battery", "the new password 1")
	syncOlder(t, laptopNew, f)
	desktopNew := takeKey(t, desktop, laptopNew, rec, "the new password 1")
	syncOlder(t, desktopNew, f)
	settle(t, f, laptopNew, desktopNew)

	uid := liveUID(t, laptopNew, gh)
	forged, _, err := laptopNew.store.SyncRecord(uid, "attacker")
	if err != nil {
		t.Fatal(err)
	}
	forged.Secret = []byte("evil")
	forged.Versions = syncfolder.Versions{"0123456789abcdef": 1}
	forged.Changed = time.Now().Add(time.Hour)
	h, err := syncfolder.NewHeader(uid, database.UnlockID(old.Verify))
	if err != nil {
		t.Fatal(err)
	}
	b, err := syncfolder.Seal(database.KeySealer(database.DeriveKey([]byte("correct horse battery"), old.Salt, old.Params)), h, forged)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, file := range scanFiles(t, f) {
		if file.UIDString() == uid {
			path = file.Path
		}
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// The first to sync writes it over; the other then finds nothing.
	if s := syncOlder(t, desktopNew, f); s.EarlierKey != 1 || len(s.Received)+len(s.Merged) != 0 {
		t.Errorf("desktop: %+v", s)
	}
	if s := syncOlder(t, laptopNew, f); !s.Nothing() {
		t.Errorf("laptop: %+v", s)
	}
	for _, c := range []*computer{desktopNew, laptopNew} {
		if got := c.secret(gh); got != "pw-1" {
			t.Errorf("%s took the old-key file: %q", c.name, got)
		}
	}
	newID := database.UnlockID(rec.Verify)
	for _, file := range scanFiles(t, f) {
		if file.KeyIDString() != newID {
			t.Errorf("%s left sealed with the old key", file.Path)
		}
	}
}

// settleOlder is settle with each computer's older keys, as the commands
// sync.
func settleOlder(t *testing.T, f syncfolder.Folder, cs ...*computer) {
	t.Helper()
	for range 4 {
		quiet := true
		for _, c := range cs {
			if !syncOlder(t, c, f).Nothing() {
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

// oldKeyWorld is two computers, both on a new master password, and what
// someone with the old one would seal with: its key and key record ID.
func oldKeyWorld(t *testing.T) (laptop, desktop *computer, f syncfolder.Folder, gh vault.Key, oldKey []byte, oldID string) {
	t.Helper()
	l, d, folder := twoComputers(t)
	gh = l.put("github", "pw-1")
	settle(t, folder, l, d)
	old, err := database.ReadUnlockMaterial(l.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	laptop, rec := changeKey(t, l, "correct horse battery", "the new password 1")
	syncOlder(t, laptop, folder)
	desktop = takeKey(t, d, laptop, rec, "the new password 1")
	syncOlder(t, desktop, folder)
	settle(t, folder, laptop, desktop)
	return laptop, desktop, folder, gh, database.DeriveKey([]byte("correct horse battery"), old.Salt, old.Params), database.UnlockID(old.Verify)
}

// sealOld writes rec, for the entry uid, sealed with key (the record
// keyID's) as path in the folder f.
func sealOld(t *testing.T, f syncfolder.Folder, path, uid string, rec *syncfolder.Record, key []byte, keyID string) {
	t.Helper()
	h, err := syncfolder.NewHeader(uid, keyID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := syncfolder.Seal(database.KeySealer(key), h, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.Dir(), "entries", path), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A copy under the old key holding what was agreed, with counts made up,
// doesn't stand in for a real change made since: that's taken.
func TestSync_EarlierKeyCopyDoesntSwallowAnEdit(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, oldKey, oldID := oldKeyWorld(t)
	uid := liveUID(t, laptop, gh)
	desktop.put("github", "desk-2")
	desktop.sync(f)
	forged, _, err := laptop.store.SyncRecord(uid, "attacker")
	if err != nil {
		t.Fatal(err)
	}
	forged.Versions = syncfolder.Versions{}
	for _, c := range []*computer{laptop, desktop} {
		id, err := c.store.SyncComputerID()
		if err != nil {
			t.Fatal(err)
		}
		forged.Versions[id] = 1_000_000
	}
	sealOld(t, f, uid+" (conflicted copy).sesh", uid, forged, oldKey, oldID)
	settleOlder(t, f, laptop, desktop)
	for _, c := range []*computer{laptop, desktop} {
		if got := c.secret(gh); got != "desk-2" {
			t.Errorf("%s: %q, want the desktop's edit", c.name, got)
		}
	}
}

// A file under the old key with a count as high as it goes jams nothing:
// it isn't read, and a later edit syncs.
func TestSync_EarlierKeyHighCount(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, oldKey, oldID := oldKeyWorld(t)
	uid := liveUID(t, laptop, gh)
	forged, _, err := laptop.store.SyncRecord(uid, "attacker")
	if err != nil {
		t.Fatal(err)
	}
	id, err := desktop.store.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	forged.Versions = syncfolder.Versions{id: math.MaxInt64}
	sealOld(t, f, uid+".sesh", uid, forged, oldKey, oldID)
	settleOlder(t, f, laptop, desktop)
	desktop.put("github", "desk-2")
	settleOlder(t, f, laptop, desktop)
	if got := laptop.secret(gh); got != "desk-2" {
		t.Errorf("laptop: %q, want the desktop's edit", got)
	}
}

// A deletion made on a computer that hadn't taken the new password yet
// stands once it does: the file written over isn't taken for an edit.
func TestSync_DeletionBehindTheChange(t *testing.T) {
	t.Parallel()
	for _, purge := range []bool{false, true} {
		laptop, desktop, f := twoComputers(t)
		gh := laptop.put("github", "pw-1")
		settleOlder(t, f, laptop, desktop)
		laptopNew, rec := changeKey(t, laptop, "correct horse battery", "the new password 1")
		var err error
		if purge {
			err = desktop.store.PurgeMany([]vault.Key{gh})
		} else {
			err = desktop.store.Delete(gh)
		}
		if err != nil {
			t.Fatal(err)
		}
		desktop.sync(f)
		syncOlder(t, laptopNew, f)
		desktopNew := takeKey(t, desktop, laptopNew, rec, "the new password 1")
		syncOlder(t, desktopNew, f)
		settleOlder(t, f, laptopNew, desktopNew)
		for _, c := range []*computer{laptopNew, desktopNew} {
			if slices.Contains(names(c), "github") {
				t.Errorf("purge %v: %s has github live again", purge, c.name)
			}
		}
	}
}

// A new entry under the old key, never agreed here, isn't taken, and
// nothing is written for it.
func TestSync_EarlierKeyNewEntry(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, _, oldKey, oldID := oldKeyWorld(t)
	uid := "0123456789abcdef0123456789abcdef"
	forged := &syncfolder.Record{Kind: vault.KindPassword, Service: "planted", Secret: []byte("evil"), Versions: syncfolder.Versions{"0123456789abcdef": 1}, Changed: time.Now()}
	sealOld(t, f, uid+".sesh", uid, forged, oldKey, oldID)
	before := scanFiles(t, f)
	for _, c := range []*computer{laptop, desktop} {
		if s := syncOlder(t, c, f); s.EarlierKey != 1 || s.Resealed+s.Rewritten+len(s.Received) != 0 {
			t.Errorf("%s: %+v", c.name, s)
		}
		if slices.Contains(names(c), "planted") {
			t.Errorf("%s took the planted entry", c.name)
		}
	}
	if after := scanFiles(t, f); len(after) != len(before) {
		t.Errorf("files %d, then %d: something was written for it", len(before), len(after))
	}
}

// An edit made here while the entry's own file was under the old key is
// sent as a change, not written over as what was agreed.
func TestSync_EarlierKeyOwnFileUnderAnEdit(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, oldKey, oldID := oldKeyWorld(t)
	uid := liveUID(t, laptop, gh)
	forged, _, err := laptop.store.SyncRecord(uid, "attacker")
	if err != nil {
		t.Fatal(err)
	}
	forged.Secret = []byte("evil")
	sealOld(t, f, uid+".sesh", uid, forged, oldKey, oldID)
	desktop.put("github", "desk-2")
	// The desktop first, so it meets the old-key file with its edit.
	if s := syncOlder(t, desktop, f); s.EarlierKey != 1 {
		t.Errorf("desktop: %+v, want the old-key file counted", s)
	}
	settleOlder(t, f, laptop, desktop)
	for _, c := range []*computer{laptop, desktop} {
		if got := c.secret(gh); got != "desk-2" {
			t.Errorf("%s: %q, want the desktop's edit", c.name, got)
		}
	}
}

// An entry restored from a backup isn't deleted by a file under the old
// key saying it was.
func TestSync_EarlierKeyRestored(t *testing.T) {
	t.Parallel()
	laptop, desktop, f, gh, oldKey, oldID := oldKeyWorld(t)
	uid := liveUID(t, laptop, gh)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CopyTo(laptop.store.Path(), backup); err != nil {
		t.Fatal(err)
	}
	if err := database.RestoreInPlace(laptop.store.Path(), backup); err != nil {
		t.Fatal(err)
	}
	id, err := desktop.store.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	gone := &syncfolder.Record{Purged: time.Now(), Changed: time.Now(), Versions: syncfolder.Versions{id: 1_000_000}}
	sealOld(t, f, uid+" (conflicted copy).sesh", uid, gone, oldKey, oldID)
	if s := syncOlder(t, laptop, f); s.EarlierKey != 1 {
		t.Errorf("laptop: %+v, want the old-key file counted", s)
	}
	settleOlder(t, f, laptop, desktop)
	for _, c := range []*computer{laptop, desktop} {
		if got := c.secret(gh); got != "pw-1" {
			t.Errorf("%s: %q, want pw-1 kept", c.name, got)
		}
	}
}
