package database

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	inPlace, err := RestoreFrom(p, b)
	if err != nil || !inPlace {
		t.Fatalf("RestoreFrom = %v, %v; want in place", inPlace, err)
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

// A missing vault, or a damaged one, is replaced whole, and a -wal file
// left beside it doesn't undo the restore.
func TestRestoreFrom_ReplacesAMissingOrDamagedVault(t *testing.T) {
	p, s := rekeyVault(t)
	b := backupOf(t, p)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(t *testing.T, path string){
		"missing": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+"-wal", []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"damaged": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("garbage that isn't sqlite"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := filepath.Join(t.TempDir(), "passwords.db")
			if err := CopyTo(p, v); err != nil {
				t.Fatal(err)
			}
			spoil(t, v)
			inPlace, err := RestoreFrom(v, b)
			if err != nil || inPlace {
				t.Fatalf("RestoreFrom = %v, %v; want the file replaced", inPlace, err)
			}
			sum, err := VaultSummary(v)
			if err != nil || sum.Entries != 1 {
				t.Errorf("after: %+v, %v", sum, err)
			}
			// The leftover -wal was removed; one there now is the restored
			// vault's own.
			if b, err := os.ReadFile(v + "-wal"); err == nil && string(b) == "stale" {
				t.Error("the leftover -wal file is still there")
			}
		})
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
