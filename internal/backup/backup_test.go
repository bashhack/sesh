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

// testVault is a vault with one entry, in a folder of its own.
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

func series(t *testing.T, vaultPath, dir string) Series {
	t.Helper()
	s, err := SeriesOf(vaultPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMakeListPrune(t *testing.T) {
	v := testVault(t)
	dir := filepath.Join(t.TempDir(), "backups")
	s := series(t, v, dir)
	base := time.Date(2026, 10, 7, 9, 12, 0, 0, time.UTC)
	for i := range 4 {
		b, err := s.Make(v, base.Add(time.Duration(i)*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if b.Size == 0 {
			t.Errorf("backup %d is empty", i)
		}
	}
	// Other files in the folder are never listed, so never pruned.
	for _, other := range []string{"notes.txt", "passwords-latest.db", "passwords-2026-10-07T091200Z.db"} {
		if err := os.WriteFile(filepath.Join(dir, other), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List()
	if err != nil || len(all) != 4 || filepath.Base(all[0].Path) != s.Name(base.Add(72*time.Hour)) || !all[0].Made.Equal(base.Add(72*time.Hour)) {
		t.Fatalf("List = %+v, %v", all, err)
	}
	if !strings.HasPrefix(filepath.Base(all[0].Path), "passwords-") || len(filepath.Base(all[0].Path)) != len("passwords-12345678-2026-10-10T091200Z.db") {
		t.Errorf("name %s, want passwords-<vault id>-<time>.db", filepath.Base(all[0].Path))
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the folder is %v, want 0700", info.Mode().Perm())
	}
	if info, err := os.Stat(all[0].Path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("a backup is %v, want 0600", info.Mode().Perm())
	}
	removed, err := s.Prune(2)
	if err != nil || len(removed) != 2 || removed[0].Path != all[2].Path {
		t.Errorf("Prune = %+v, %v", removed, err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 5 { //nolint:errcheck // counted
		t.Errorf("left %d files, want the 2 newest backups and the 3 others", len(left))
	}
	// A backup is a sound vault, holding the entry, with the vault's id.
	db, err := sql.Open("sqlite", all[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM entries`).Scan(&n); err != nil || n != 1 {
		t.Errorf("the backup holds %d entries (%v), want 1", n, err)
	}
	if id, err := database.VaultID(all[0].Path); err != nil || !strings.Contains(filepath.Base(all[0].Path), id[:8]) {
		t.Errorf("the backup's id %q (%v) isn't in its name", id, err)
	}
}

// Two vaults with the same file name, backed up to one folder, keep their
// own backups.
func TestSeries_TwoVaultsShareAFolder(t *testing.T) {
	a, b := testVault(t), testVault(t)
	dir := t.TempDir()
	sa, sb := series(t, a, dir), series(t, b, dir)
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	if _, err := sa.Make(a, now); err != nil {
		t.Fatal(err)
	}
	if due, err := sb.Due(1, now); err != nil || !due {
		t.Errorf("b after a's backup: due %v, %v; want due", due, err)
	}
	if _, err := sb.Make(b, now); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Prune(1); err != nil {
		t.Fatal(err)
	}
	la, _ := sa.List() //nolint:errcheck // checked by length
	lb, _ := sb.List() //nolint:errcheck // checked by length
	if len(la) != 1 || len(lb) != 1 || la[0].Path == lb[0].Path {
		t.Errorf("a's %+v, b's %+v; want one each", la, lb)
	}
}

func TestDue(t *testing.T) {
	v := testVault(t)
	s := series(t, v, t.TempDir())
	at := func(day, hour int) time.Time { return time.Date(2026, 10, day, hour, 0, 0, 0, time.Local) }
	if due, err := s.Due(1, at(7, 9)); err != nil || !due {
		t.Errorf("with none: %v, %v", due, err)
	}
	if _, err := s.Make(v, at(7, 9)); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		now   time.Time
		every int
		want  bool
	}{
		{at(7, 23), 1, false}, // the same day
		{at(8, 8), 1, true},   // the next day, though under 24 hours later
		{at(8, 8), 2, false},
		{at(9, 0), 2, true},
		{at(30, 0), 0, false}, // turned off
	} {
		if due, err := s.Due(tt.every, tt.now); err != nil || due != tt.want {
			t.Errorf("at %v, every %d: %v, %v; want %v", tt.now, tt.every, due, err, tt.want)
		}
	}
}

// A backup dated in the future (a clock set wrong once) doesn't stop the
// ones after it.
func TestDue_IgnoresAFutureBackup(t *testing.T) {
	v := testVault(t)
	s := series(t, v, t.TempDir())
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.Local)
	if _, err := s.Make(v, now.AddDate(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if due, err := s.Due(1, now); err != nil || !due {
		t.Errorf("due %v, %v; want due", due, err)
	}
	if _, err := s.Make(v, now); err != nil {
		t.Fatal(err)
	}
	if due, err := s.Due(1, now.Add(time.Hour)); err != nil || due {
		t.Errorf("after today's: due %v, %v; want not due", due, err)
	}
}

// Two backups in the same second: the first stands.
func TestMake_SameSecond(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	s := series(t, v, dir)
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	a, err := s.Make(v, now)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := s.Make(v, now); err != nil || b.Path != a.Path {
		t.Errorf("again: %+v, %v", b, err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 { //nolint:errcheck // counted
		t.Errorf("%d files, want 1 and no temporary ones", len(left))
	}
}

// Without links (FAT and exFAT), a backup is renamed into place, still
// refusing to replace one.
func TestMake_WithoutLinks(t *testing.T) {
	orig := link
	link = func(string, string) error {
		return &os.LinkError{Op: "link", Err: errors.New("operation not supported")}
	}
	t.Cleanup(func() { link = orig })
	v := testVault(t)
	dir := t.TempDir()
	s := series(t, v, dir)
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	if _, err := s.Make(v, now); err != nil {
		t.Fatalf("Make: %v", err)
	}
	dest := filepath.Join(dir, "copy.db")
	if _, err := MakeTo(v, dest, false, now); err != nil {
		t.Fatalf("MakeTo: %v", err)
	}
	if _, err := MakeTo(v, dest, false, now); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("MakeTo again: %v", err)
	}
}

func TestMakeTo(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "copy.db")
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	if _, err := MakeTo(v, dest, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := MakeTo(v, dest, false, now); err == nil || !strings.Contains(err.Error(), "already exists; add --force") {
		t.Errorf("again: %v", err)
	}
	if _, err := MakeTo(v, dest, true, now); err != nil {
		t.Errorf("with force: %v", err)
	}
	// A folder gets the backup inside it, named as the series names it.
	b, err := MakeTo(v, dir, false, now)
	if err != nil || filepath.Dir(b.Path) != dir || filepath.Base(b.Path) != series(t, v, dir).Name(now) {
		t.Errorf("into a folder: %+v, %v", b, err)
	}
}

// A temporary file left by a backup cut short long ago is removed.
func TestMake_RemovesStaleTemps(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	s := series(t, v, dir)
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	stale := filepath.Join(dir, "."+s.Name(now.Add(-48*time.Hour))+".123.tmp")
	fresh := filepath.Join(dir, "."+s.Name(now)+".456.tmp")
	other := filepath.Join(dir, ".someone-else.tmp")
	for _, f := range []string{stale, fresh, other} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(f, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(fresh, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Make(v, now); err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]bool{stale: false, fresh: true, other: true} {
		if _, err := os.Stat(f); (err == nil) != want {
			t.Errorf("%s exists: %v, want %v", filepath.Base(f), err == nil, want)
		}
	}
}

// A damaged vault isn't copied, so it can't replace good backups.
func TestMake_RefusesADamagedVault(t *testing.T) {
	v := testVault(t)
	s := series(t, v, t.TempDir())
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
	if _, err := s.Make(v, time.Now()); !database.IsDamaged(err) {
		t.Errorf("Make = %v, want it refused as damaged", err)
	}
	if left, _ := os.ReadDir(s.Dir); len(left) != 0 { //nolint:errcheck // counted
		t.Errorf("%d files left, want none", len(left))
	}
	if _, err := SeriesOf(filepath.Join(t.TempDir(), "none.db"), s.Dir); !errors.Is(err, database.ErrNoVault) {
		t.Errorf("no vault: %v", err)
	}
}

// MakeNew never takes another backup for its own: it moves to the next
// free second.
func TestMakeNew(t *testing.T) {
	v := testVault(t)
	s := series(t, v, t.TempDir())
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	a, err := s.Make(v, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.MakeNew(v, now)
	if err != nil || b.Path == a.Path || !b.Made.Equal(now.Add(time.Second)) {
		t.Errorf("MakeNew = %+v, %v; want the next second", b, err)
	}
}
