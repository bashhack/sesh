package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/tui"
)

// The app's backups are sesh backup's and sesh restore's: listed newest first with another vault's marked, made in
// the folder or to a file (asking before replacing one), deleted one at a time, and restored from in place.
func TestUI_Backups(t *testing.T) {
	healthVault(t)
	clock := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	orig := now
	now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	t.Cleanup(func() { now = orig })
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	db := cfg.DBPath.Value
	if b, err := uiBackups(db); err != nil || len(b.List) != 0 {
		t.Fatalf("none yet: %+v, %v", b, err)
	}
	if said, err := uiBackUp(db, "", false); err != nil || !strings.HasPrefix(said, "Backed up the vault to ") {
		t.Fatalf("back up now: %q, %v", said, err)
	}
	b, err := uiBackups(db)
	if err != nil || len(b.List) != 1 || b.List[0].Other || b.List[0].Size == "" {
		t.Fatalf("one: %+v, %v", b, err)
	}
	first := b.List[0].Path
	// Another vault's, with the same file name, is listed and marked.
	other := filepath.Join(filepath.Dir(first), strings.TrimSuffix(filepath.Base(db), ".db")+"-77aa0000-2026-01-01T000000Z.db")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := uiBackups(db); err != nil || len(b.List) != 2 || !b.List[1].Other {
		t.Errorf("another vault's: %+v, %v", b, err)
	}
	// Backing up now prunes this vault's to backup.keep: the oldest goes, the first stays.
	name := filepath.Base(first)
	older := filepath.Join(filepath.Dir(first), name[:len(name)-len("2026-10-14T181242Z.db")]+"2026-01-01T000000Z.db")
	if err := os.WriteFile(older, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	useConfigFile(t, "[backup]\nkeep = 2\n")
	if _, err := uiBackUp(db, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(older); !os.IsNotExist(err) {
		t.Errorf("the older backup wasn't pruned: %v", err)
	}
	if said, err := uiDeleteBackup(db, other); err != nil || !strings.HasPrefix(said, "Deleted the backup") {
		t.Errorf("deleting another vault's: %q, %v", said, err)
	}
	if _, err := uiDeleteBackup(db, db); err == nil || !strings.Contains(err.Error(), "isn't one of the backups") {
		t.Errorf("deleting the vault itself: %v", err)
	}

	to := filepath.Join(t.TempDir(), "copy.db")
	if _, err := uiBackUp(db, to, false); err != nil {
		t.Fatal(err)
	}
	if _, err := uiBackUp(db, to, false); !errors.Is(err, tui.ErrExists) || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("a file there: %v", err)
	}
	if _, err := uiBackUp(db, to, true); err != nil {
		t.Errorf("replacing it: %v", err)
	}
	// Into a folder, a backup made the same moment is named as the file, not the folder.
	into := t.TempDir()
	now = func() time.Time { return clock }
	if _, err := uiBackUp(db, into, false); err != nil {
		t.Fatal(err)
	}
	if _, err := uiBackUp(db, into, false); !errors.Is(err, tui.ErrExists) || strings.HasPrefix(err.Error(), into+" ") {
		t.Errorf("into a folder twice: %v", err)
	}
	now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	for _, typed := range []string{"copy.db", "./copy.db", "~user/copy.db"} {
		if _, err := uiBackUp(db, typed, false); err == nil || !strings.Contains(err.Error(), "isn't a full path") {
			t.Errorf("%q: %v", typed, err)
		}
	}
	// HOME is the test's own folder.
	if said, err := uiBackUp(db, "~", false); err != nil || !strings.HasPrefix(said, "Backed up the vault to ~/") {
		t.Errorf("~: %q, %v", said, err)
	}

	// An entry added after the backup is gone once the vault is restored from it, with the vault open as the app
	// has it.
	populatePasswordStore(t, &rekeyTestEnv{dbPath: db}, map[string]string{"password/added/later": "x"})
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // test cleanup
	// The vault itself, open, isn't backed up over.
	if _, err := uiBackUp(db, db, true); err == nil || !strings.Contains(err.Error(), "is the vault itself") {
		t.Errorf("backing up over the vault: %v", err)
	}
	if _, err := database.VaultSummary(db); err != nil {
		t.Fatalf("the vault after: %v", err)
	}
	q, err := uiPlanRestore(db, first)
	if err != nil || !strings.HasPrefix(q, "Restore the vault from "+filepath.Base(first)) || !strings.Contains(q, "The vault now (5 entries) is backed up first.") {
		t.Fatalf("the question: %q, %v", q, err)
	}
	said, err := uiRestore(db, first)
	if err != nil || !strings.HasPrefix(said, "Restored the vault from "+filepath.Base(first)+" (4 entries).") || strings.Contains(said, "\n") {
		t.Fatalf("restored: %q, %v", said, err)
	}
	if sum, err := database.VaultSummary(db); err != nil || sum.Entries != 4 {
		t.Errorf("after the restore: %+v, %v", sum, err)
	}
	// The store open through it reads the vault as restored.
	if rows, _, err := newUIVault(store).Search(""); err != nil || len(rows) != 4 {
		t.Errorf("the open store after the restore: %d entries, %v", len(rows), err)
	}
	if b, _ := uiBackups(db); len(b.List) != 3 { //nolint:errcheck // checked by the count
		t.Errorf("the vault as it was isn't backed up: %+v", b)
	}

	// A vault that's gone isn't restored from the app.
	if err := os.Rename(db, db+".gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := uiPlanRestore(db, first); !errors.Is(err, tui.ErrRefused) {
		t.Errorf("no vault: %v", err)
	}
}
