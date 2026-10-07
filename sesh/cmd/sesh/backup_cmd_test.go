package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/backup"
)

// backupVault is a vault with one entry and automatic backups at the
// defaults; the clock is at clock, which tests move.
func backupVault(t *testing.T, clock *time.Time) *rekeyTestEnv {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "backup-password-1234")
	orig := now
	now = func() time.Time { return *clock }
	t.Cleanup(func() { now = orig })
	return env
}

// unlockOnce opens and closes the vault as any command that unlocks it does.
func unlockOnce(t *testing.T) {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	closeAuditStore(store)
}

func backups(t *testing.T, env *rekeyTestEnv) []backup.Info {
	t.Helper()
	all, err := backup.List(filepath.Join(filepath.Dir(env.dbPath), "backups"), env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

// Unlocking makes a backup when the newest is a day old, not before, and
// keeps backup.keep of them. An empty vault isn't backed up.
func TestAutoBackup(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	env := backupVault(t, &clock)
	t.Setenv("SESH_BACKUP_KEEP", "2")
	unlockOnce(t)
	if got := backups(t, env); len(got) != 0 {
		t.Fatalf("an empty vault was backed up: %+v", got)
	}
	populatePasswordStore(t, env, map[string]string{"password/github": "pw"})
	unlockOnce(t)
	if got := backups(t, env); len(got) != 1 || !got[0].Made.Equal(clock) {
		t.Fatalf("after the first unlock: %+v", got)
	}
	clock = clock.Add(23 * time.Hour)
	unlockOnce(t)
	if got := backups(t, env); len(got) != 1 {
		t.Errorf("23 hours later: %d backups, want still 1", len(got))
	}
	for range 3 {
		clock = clock.Add(25 * time.Hour)
		unlockOnce(t)
	}
	if got := backups(t, env); len(got) != 2 || !got[0].Made.Equal(clock) {
		t.Errorf("after 3 more days: %+v, want the newest 2", got)
	}
	t.Setenv("SESH_BACKUP_EVERY_DAYS", "0")
	clock = clock.Add(72 * time.Hour)
	unlockOnce(t)
	if got := backups(t, env); !got[0].Made.Equal(clock.Add(-72 * time.Hour)) {
		t.Errorf("turned off, a backup was made: %+v", got)
	}
}

func runBackupOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	app := agentTestApp()
	err := runBackup(app, args)
	return app.Stdout.(*bytes.Buffer).String(), err
}

func TestBackupCommand(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.UTC)
	env := backupVault(t, &clock)
	if _, err := runBackupOut(t); err == nil || !strings.Contains(err.Error(), "there's no vault yet") {
		t.Errorf("no vault: %v", err)
	}
	populatePasswordStore(t, env, map[string]string{"password/github": "pw"})
	// No password is needed: it's unset here.
	t.Setenv("SESH_MASTER_PASSWORD", "")
	out, err := runBackupOut(t)
	want := "✅ Backed up the vault to " + tildePath(filepath.Join(filepath.Dir(env.dbPath), "backups", "passwords-2026-10-07T091200Z.db"))
	if err != nil || !strings.HasPrefix(out, want) {
		t.Errorf("into the folder: %q, %v; want it to start %q", out, err, want)
	}
	dest := filepath.Join(t.TempDir(), "copy.db")
	if out, err := runBackupOut(t, dest); err != nil || !strings.Contains(out, "copy.db") {
		t.Errorf("to a file: %q, %v", out, err)
	}
	if _, err := runBackupOut(t, dest); err == nil || !strings.Contains(err.Error(), "already exists; add --force to replace it") {
		t.Errorf("to the file again: %v", err)
	}
	if _, err := runBackupOut(t, "--force", dest); err != nil {
		t.Errorf("with --force: %v", err)
	}
	// A relative file is from the working directory.
	wd := t.TempDir()
	t.Chdir(wd)
	if _, err := runBackupOut(t, "rel.db"); err != nil {
		t.Errorf("a relative file: %v", err)
	} else if _, err := os.Stat(filepath.Join(wd, "rel.db")); err != nil {
		t.Errorf("rel.db isn't in the working directory: %v", err)
	}
	for args, wantSub := range map[string]string{
		"--force": "--force replaces a file you name",
		"a b":     "takes at most one file",
	} {
		if _, err := runBackupOut(t, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%q: %v, want %q", args, err, wantSub)
		}
	}
}

// Doctor's Backups row: none, recent, too old, off.
func TestDoctor_Backups(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local)
	env := backupVault(t, &clock)
	populatePasswordStore(t, env, map[string]string{"password/github": "pw"})
	dir := tildePath(filepath.Join(filepath.Dir(env.dbPath), "backups"))
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  warn  Backups         none yet, in "+dir+"\n") || !strings.Contains(out, "       sesh backup\n") {
		t.Errorf("none: %v\n%s", err, out)
	}
	if _, err := runBackupOut(t); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Hour)
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  ok    Backups         newest today 09:12, 1 kept, in "+dir+"\n") {
		t.Errorf("recent: %v\n%s", err, out)
	}
	clock = clock.Add(72 * time.Hour)
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  warn  Backups         newest 2026-10-07 09:12, 1 kept, in "+dir+": older than expected\n") {
		t.Errorf("too old: %v\n%s", err, out)
	}
	t.Setenv("SESH_BACKUP_EVERY_DAYS", "0")
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  -     Backups         automatic backups are off (backup.every_days = 0); newest 2026-10-07 09:12\n") {
		t.Errorf("off: %v\n%s", err, out)
	}
}

func TestWhen(t *testing.T) {
	at := time.Date(2026, 10, 7, 18, 0, 0, 0, time.Local)
	for _, tt := range []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local), "today 09:12"},
		{time.Date(2026, 10, 6, 23, 59, 0, 0, time.Local), "yesterday 23:59"},
		{time.Date(2026, 10, 5, 9, 12, 0, 0, time.Local), "2026-10-05 09:12"},
	} {
		if got := when(tt.t, at); got != tt.want {
			t.Errorf("when(%v) = %q, want %q", tt.t, got, tt.want)
		}
	}
}
