package database

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// backupOf copies the vault at p to a new file and returns its path.
func backupOf(t *testing.T, p string) string {
	t.Helper()
	b := filepath.Join(t.TempDir(), "backup.db")
	if err := CopyTo(p, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func services(t *testing.T, s *Store) string {
	t.Helper()
	all, err := s.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := range all {
		names = append(names, all[i].Service)
	}
	return strings.Join(names, " ")
}

func TestInspectBackup(t *testing.T) {
	p, _ := rekeyVault(t)
	b := backupOf(t, p)
	id, err := VaultID(p)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := InspectBackup(b)
	if err != nil || sum.VaultID != id || sum.Entries != 1 {
		t.Errorf("InspectBackup = %+v, %v; want this vault's id and 1 entry", sum, err)
	}
	// Inspecting writes nothing: no -wal or -shm appear beside it.
	if _, err := os.Stat(b + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a -wal file appeared beside the backup: %v", err)
	}

	notSesh := filepath.Join(t.TempDir(), "other.db")
	if err := os.WriteFile(notSesh, []byte("not a database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectBackup(notSesh); err == nil {
		t.Error("a file that isn't a vault passed")
	}
	newer := backupOf(t, p)
	sqlExecIn(t, newer, `INSERT INTO schema_migrations (version, applied_at) VALUES (99, CURRENT_TIMESTAMP)`)
	if _, err := InspectBackup(newer); err == nil || !strings.Contains(err.Error(), "vault format 99; this one reads 1") {
		t.Errorf("a newer format: %v", err)
	}
	noKey := backupOf(t, p)
	sqlExecIn(t, noKey, `DELETE FROM vault_key`)
	if _, err := InspectBackup(noKey); err == nil {
		t.Error("a backup with entries but no key record passed")
	}
	damagedB := backupOf(t, p)
	sqlExecIn(t, damagedB, `PRAGMA writable_schema = ON; UPDATE sqlite_master SET sql = 'CREATE INDEX idx_entries_folder ON entries(service)' WHERE name = 'idx_entries_folder'; PRAGMA writable_schema = OFF`)
	if _, err := InspectBackup(damagedB); !IsDamaged(err) {
		t.Errorf("a damaged backup: %v", err)
	}
}

// A sound vault is restored in place: its entries, key record and recovery
// record come from the backup; its audit log stays, with a restore event.
// A store open on it sees the restored vault.
func TestRestoreFrom_InPlace(t *testing.T) {
	p, s := rekeyVault(t)
	b := backupOf(t, p)
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "newer"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(vault.Key{Kind: vault.KindPassword, Service: "bank"}); err != nil {
		t.Fatal(err)
	}
	events := func() map[string]int {
		rows, err := s.db.Query(`SELECT event_type FROM audit_log`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close() //nolint:errcheck // test cleanup
		n := map[string]int{}
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				t.Fatal(err)
			}
			n[e]++
		}
		return n
	}
	before := events()
	if err := RestoreInPlace(p, b); err != nil {
		t.Fatalf("RestoreInPlace: %v", err)
	}
	if got := services(t, s); got != "bank" {
		t.Errorf("after the restore: %q, want bank", got)
	}
	if secret, err := s.Get(vault.Key{Kind: vault.KindPassword, Service: "bank"}); err != nil || string(secret) != "bank-secret" {
		t.Errorf("bank = %q, %v", secret, err)
	}
	after := events()
	if after["restore"] != 1 || after["delete"] != before["delete"] || after["modify"] < before["modify"] {
		t.Errorf("audit events before %v, after %v; want them kept, plus one restore", before, after)
	}
	if rec, err := ReadRecovery(p); err != nil || rec == nil {
		t.Errorf("the recovery record wasn't restored: %v", err)
	}
}

// A missing vault is replaced, and a -wal file left beside it doesn't
// undo the restore.
func TestReplaceVault_Missing(t *testing.T) {
	p, s := rekeyVault(t)
	b := backupOf(t, p)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	v := filepath.Join(t.TempDir(), "passwords.db")
	if err := os.WriteFile(v+"-wal", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	aside, err := ReplaceVault(v, b, time.Now())
	if err != nil || aside != "" {
		t.Fatalf("ReplaceVault = %q, %v; want nothing moved aside", aside, err)
	}
	if sum, err := VaultSummary(v); err != nil || sum.Entries != 1 {
		t.Errorf("after: %+v, %v", sum, err)
	}
	if b, err := os.ReadFile(v + "-wal"); err == nil && string(b) == "stale" {
		t.Error("the leftover -wal file is still there")
	}
}

// A damaged vault is moved aside, with its -wal, never deleted: what can
// still be read of it, such as an entry newer than the backup, is kept.
func TestReplaceVault_DamagedIsMovedAside(t *testing.T) {
	p, s := rekeyVault(t)
	b := backupOf(t, p)
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "newer"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	sqlExecIn(t, p, `PRAGMA writable_schema = ON; UPDATE sqlite_master SET sql = 'CREATE INDEX idx_entries_folder ON entries(service)' WHERE name = 'idx_entries_folder'; PRAGMA writable_schema = OFF`)
	if _, err := VaultSummary(p); !IsDamaged(err) {
		t.Fatalf("VaultSummary = %v, want damaged", err)
	}
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	aside, err := ReplaceVault(p, b, now)
	if err != nil || filepath.Base(aside) != filepath.Base(p)+".before-restore-2026-10-07T090000Z" {
		t.Fatalf("ReplaceVault = %q, %v", aside, err)
	}
	if sum, err := VaultSummary(p); err != nil || sum.Entries != 1 {
		t.Errorf("the restored vault: %+v, %v", sum, err)
	}
	db, err := sql.Open("sqlite", aside)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM entries NOT INDEXED WHERE service = 'newer'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("the entry newer than the backup isn't in the vault moved aside: %d, %v", n, err)
	}
}

// A symlinked vault is replaced where it really is; the link stays.
func TestReplaceVault_FollowsSymlinks(t *testing.T) {
	p, s := rekeyVault(t)
	b := backupOf(t, p)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(t.TempDir(), "passwords.db")
	if err := os.WriteFile(realPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "passwords.db")
	if err := os.Symlink(realPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceVault(link, b, time.Now()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v", err)
	}
	if sum, err := VaultSummary(realPath); err != nil || sum.Entries != 1 {
		t.Errorf("the link's target: %+v, %v", sum, err)
	}
}

// A new vault, with no key record or entries, counts as no vault; the
// vault's own problems are worded as the vault's.
func TestVaultSummary(t *testing.T) {
	p := vaultPath(t.TempDir())
	s, err := Open(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VaultSummary(p); !errors.Is(err, ErrNoVault) {
		t.Errorf("a new vault: %v, want ErrNoVault", err)
	}
	if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VaultSummary(p); !IsDamaged(err) || !strings.Contains(err.Error(), "the vault") || strings.Contains(err.Error(), "backup") {
		t.Errorf("a garbage vault: %v", err)
	}
}

// Every table but the audit log and the schema version is restored, so a
// table added later can't be left out by mistake.
func TestRestoredTablesCoverTheSchema(t *testing.T) {
	p, _ := rekeyVault(t)
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck // test cleanup
	want := append([]string{"audit_log", "schema_migrations"}, restoredTables...)
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("tables %q, want each restored or kept on purpose: %q", got, want)
	}
}

// sqlExecIn runs q on the SQLite file at path directly.
func sqlExecIn(t *testing.T, path, q string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

// A store that unlocked the vault before it was restored from a backup with
// another key is refused its next write.
func TestRestoreInPlace_RefusesAStoreOnTheOldKey(t *testing.T) {
	p, s := rekeyVault(t)
	other := vaultPath(t.TempDir())
	o, err := Open(other, NewKeySourceOracle(NewMasterPasswordSource(other, staticPrompt("other-password-1", "other-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Put(vault.Key{Kind: vault.KindPassword, Service: "x"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RestoreInPlace(p, backupOf(t, other)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "y"}, []byte("y")); !errors.Is(err, ErrVaultKeyChanged) {
		t.Errorf("Put after the restore = %v, want ErrVaultKeyChanged", err)
	}
}
