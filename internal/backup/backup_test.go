package backup

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
)

// testVault is a vault with one entry.
func testVault(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "passwords.db")
	s, err := database.Open(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if _, err := db.Exec(`INSERT INTO entries (kind, service, username, encrypted_data, salt, created_at, updated_at) VALUES ('password', 'github', '', x'00', x'00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMakeListPrune(t *testing.T) {
	v := testVault(t)
	dir := filepath.Join(t.TempDir(), "backups")
	base := time.Date(2026, 10, 7, 9, 12, 0, 0, time.UTC)
	for i := range 4 {
		b, err := Make(v, dir, base.Add(time.Duration(i)*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if b.Size == 0 {
			t.Errorf("backup %d is empty", i)
		}
	}
	// Other files in the folder are never listed, so never pruned.
	for _, other := range []string{"notes.txt", "passwords-latest.db", "work-2026-10-07T091200Z.db"} {
		if err := os.WriteFile(filepath.Join(dir, other), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	all, err := List(dir, v)
	if err != nil || len(all) != 4 || filepath.Base(all[0].Path) != "passwords-2026-10-10T091200Z.db" || !all[0].Made.Equal(base.Add(72*time.Hour)) {
		t.Fatalf("List = %+v, %v", all, err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the folder is %v, want 0700", info.Mode().Perm())
	}
	if info, err := os.Stat(all[0].Path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("a backup is %v, want 0600", info.Mode().Perm())
	}
	removed, err := Prune(dir, v, 2)
	if err != nil || len(removed) != 2 || filepath.Base(removed[0].Path) != "passwords-2026-10-08T091200Z.db" {
		t.Errorf("Prune = %+v, %v", removed, err)
	}
	left, err := os.ReadDir(dir)
	if err != nil || len(left) != 5 {
		t.Errorf("left %d files, want the 2 newest backups and the 3 others", len(left))
	}
	// A backup is a sound vault, holding the entry.
	db, err := sql.Open("sqlite", all[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM entries`).Scan(&n); err != nil || n != 1 {
		t.Errorf("the backup holds %d entries (%v), want 1", n, err)
	}
}

func TestDue(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	if due, err := Due(dir, v, 1, now); err != nil || !due {
		t.Errorf("with none: %v, %v", due, err)
	}
	if _, err := Make(v, dir, now.Add(-23*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if due, err := Due(dir, v, 1, now); err != nil || due {
		t.Errorf("23 hours old: %v, %v; want not due", due, err)
	}
	if due, err := Due(dir, v, 1, now.Add(time.Hour)); err != nil || !due {
		t.Errorf("24 hours old: %v, %v; want due", due, err)
	}
	if due, err := Due(dir, v, 0, now.Add(48*time.Hour)); err != nil || due {
		t.Errorf("turned off: %v, %v", due, err)
	}
}

// Two backups in the same second: the first stands, and Make still says
// where it is.
func TestMake_SameSecond(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	a, err := Make(v, dir, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Make(v, dir, now)
	if err != nil || b.Path != a.Path {
		t.Errorf("again: %+v, %v", b, err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 { //nolint:errcheck // counted
		t.Errorf("%d files, want 1 and no temporary ones", len(left))
	}
}

func TestMakeTo_RefusesToReplace(t *testing.T) {
	v := testVault(t)
	dest := filepath.Join(t.TempDir(), "copy.db")
	now := time.Now()
	if _, err := MakeTo(v, dest, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := MakeTo(v, dest, false, now); err == nil || !strings.Contains(err.Error(), "already exists; add --force") {
		t.Errorf("again: %v", err)
	}
	if _, err := MakeTo(v, dest, true, now); err != nil {
		t.Errorf("with force: %v", err)
	}
}

// A damaged vault isn't copied, so it can't replace good backups.
func TestMake_RefusesADamagedVault(t *testing.T) {
	v := testVault(t)
	db, err := sql.Open("sqlite", v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA writable_schema = ON; UPDATE sqlite_master SET sql = 'CREATE INDEX idx_entries_folder ON entries(service)' WHERE name = 'idx_entries_folder'; PRAGMA writable_schema = OFF`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := Make(v, dir, time.Now()); !database.IsDamaged(err) {
		t.Errorf("Make = %v, want it refused as damaged", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 { //nolint:errcheck // counted
		t.Errorf("%d files left, want none", len(left))
	}
	if _, err := Make(filepath.Join(t.TempDir(), "none.db"), dir, time.Now()); !errors.Is(err, database.ErrNoVault) {
		t.Errorf("no vault: %v", err)
	}
}
