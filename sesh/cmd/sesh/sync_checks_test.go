package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
)

// cloudTool names the sync tool whose folder a vault is in: by the folder's
// name or its start, through links (the vault's own too), in any case the
// file system ignores, and in the folders iCloud Drive links to.
func TestCloudTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for path, want := range map[string]string{
		filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "sesh", "passwords.db"): "iCloud Drive",
		filepath.Join(home, "Library", "CloudStorage", "Dropbox", "passwords.db"):                         "a cloud storage app (Dropbox, Google Drive, OneDrive, Box)",
		filepath.Join(home, "Dropbox", "passwords.db"):                                                    "Dropbox",
		filepath.Join(home, ".local", "share", "sesh", "passwords.db"):                                    "",
		filepath.Join(home, "DropboxNot", "passwords.db"):                                                 "",
		filepath.Join(home, "Dropbox", "..vault", "passwords.db"):                                         "Dropbox",
		filepath.Join(home, "Sync", "passwords.db"):                                                       "Syncthing",
	} {
		if got := cloudTool(path); got != want {
			t.Errorf("cloudTool(%s) = %q, want %q", path, got, want)
		}
	}
	// Through a link to a synced folder too.
	if err := os.MkdirAll(filepath.Join(home, "Dropbox", "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "Dropbox", "vault"), filepath.Join(home, "vault")); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, "vault", "passwords.db")); got != "Dropbox" {
		t.Errorf("through a link: %q", got)
	}
	// The vault file itself a link into one.
	if err := os.WriteFile(filepath.Join(home, "Dropbox", "vault", "passwords.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "Dropbox", "vault", "passwords.db"), filepath.Join(home, "vault.db")); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, "vault.db")); got != "Dropbox" {
		t.Errorf("the vault file a link: %q", got)
	}
	// In another case, where the file system ignores case.
	if _, err := os.Stat(filepath.Join(home, "DROPBOX")); err == nil {
		if got := cloudTool(filepath.Join(home, "dropbox", "vault", "passwords.db")); got != "Dropbox" {
			t.Errorf("in another case: %q", got)
		}
	}
	// A Dropbox folder named for its account.
	if err := os.MkdirAll(filepath.Join(home, "Dropbox (Personal)"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, "Dropbox (Personal)", "passwords.db")); got != "Dropbox" {
		t.Errorf("Dropbox (Personal): %q", got)
	}
	// Documents, which iCloud Drive keeps through a link in its folder.
	docs := filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs")
	if err := os.MkdirAll(docs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "Documents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "Documents"), filepath.Join(docs, "Documents")); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, "Documents", "passwords.db")); got != "iCloud Drive (Desktop & Documents)" {
		t.Errorf("Documents in iCloud Drive: %q", got)
	}
}

// sesh doctor warns of a vault in a synced folder.
func TestDoctor_VaultInACloudFolder(t *testing.T) {
	doctorVault(t)
	home := os.Getenv("HOME")
	db := filepath.Join(home, "Dropbox", "passwords.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvDBPath, db)
	populatePasswordStore(t, &rekeyTestEnv{dbPath: db}, map[string]string{"password/a": "1"})
	out, _ := runDoctorOut(t) //nolint:errcheck // warnings exit 0; the output is checked
	if !strings.Contains(out, "warn  Vault place     in a folder Dropbox syncs") || !strings.Contains(out, "sesh sync init") ||
		!strings.Contains(out, "move passwords.db (and any passwords.db-wal and passwords.db-shm beside it)") || !strings.Contains(out, "change db_path in") {
		t.Errorf("output:\n%s", out)
	}
}

// sesh doctor's sync row: the folder and when it last synced; entries
// waiting for the sync tool's download; a folder for another vault.
func TestDoctor_SyncRow(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	t.Setenv("SESH_BACKUP_EVERY_DAYS", "0")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	db := syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/github/alice", "pw-1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	putEntry(t, "password/gitlab/alice", "pw-2")
	out, _ := runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "ok    Sync            with "+folder+", last synced ") || !strings.Contains(out, "; 1 to send, 0 to take") {
		t.Errorf("synced:\n%s", out)
	}
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	// The audit log pruned: synced before, when unknown.
	store, err := database.Open(db, nil)
	if err == nil {
		_, err = store.PruneAudit(time.Now().Add(time.Hour))
		closeAuditStore(store)
	}
	if err != nil {
		t.Fatal(err)
	}
	out, _ = runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "synced before (when isn't recorded); 0 to send, 0 to take") {
		t.Errorf("audit log pruned:\n%s", out)
	}
	// Reading the folder changes nothing, its permissions included.
	if err := os.Chmod(filepath.Join(folder, "entries"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _ = runDoctorOut(t); true { //nolint:errcheck // the permissions are checked
		if fi, err := os.Stat(filepath.Join(folder, "entries")); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("the folder's permissions after doctor: %v, %v", fi.Mode(), err)
		}
	}
	// One entry's file evicted by iCloud, as its old placeholder.
	entries, err := os.ReadDir(filepath.Join(folder, "entries"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries: %v, %v", entries, err)
	}
	own := filepath.Join(folder, "entries", entries[0].Name())
	if err := os.Rename(own, filepath.Join(folder, "entries", "."+entries[0].Name()+".icloud")); err != nil {
		t.Fatal(err)
	}
	out, _ = runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "warn  Sync") || !strings.Contains(out, "1 entry waits for the sync tool to download their files") || !strings.Contains(out, "Keep Downloaded") {
		t.Errorf("waiting:\n%s", out)
	}
	// Another vault's folder.
	other := filepath.Join(dir, "other")
	syncComputer(t, filepath.Join(dir, "desktop"), "desktop")
	putEntry(t, "password/b", "2")
	if _, err := runSyncOut(t, "", false, "init", other); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	t.Setenv(config.EnvSyncDir, other)
	out, err = runDoctorOut(t)
	if err == nil || !strings.Contains(out, "FAIL  Sync") || !strings.Contains(out, "another master password") {
		t.Errorf("another vault's folder (%v):\n%s", err, out)
	}
	// A file sealed with another master password's key in its own folder.
	t.Setenv(config.EnvSyncDir, "")
	des, err := os.ReadDir(filepath.Join(other, "entries"))
	if err != nil || len(des) != 1 {
		t.Fatalf("the other folder's files: %v, %v", des, err)
	}
	b, err := os.ReadFile(filepath.Join(other, "entries", des[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "entries", des[0].Name()), b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ = runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "warn  Sync") || !strings.Contains(out, "1 entry's file is sealed with another master password's key") {
		t.Errorf("another key's file:\n%s", out)
	}
	// The folder not there: a drive not connected.
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	out, err = runDoctorOut(t)
	if err != nil || !strings.Contains(out, "warn  Sync") || !strings.Contains(out, "isn't there now") {
		t.Errorf("the folder away (%v):\n%s", err, out)
	}
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	// The key record damaged: the row isn't checked, the vault row says why.
	sqlExec(t, db, `UPDATE vault_key SET kdf = 'scrypt'`)
	out, _ = runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "-     Sync") || !strings.Contains(out, "not checked: the vault's key record is damaged") || strings.Contains(out, "FAIL  Sync") {
		t.Errorf("a damaged key record:\n%s", out)
	}
}

// Restoring a vault that syncs says what the next sync does with it.
func TestRestore_SaysWhatSyncDoes(t *testing.T) {
	cfg := &config.Config{DBPath: config.Setting[string]{Value: filepath.Join(t.TempDir(), "passwords.db")}}
	backupOf := func() string {
		t.Helper()
		t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
		syncComputer(t, filepath.Join(t.TempDir(), "laptop"), "laptop")
		putEntry(t, "password/a", "1")
		c, err := settings()
		if err != nil {
			t.Fatal(err)
		}
		cfg.DBPath = c.DBPath
		return c.DBPath.Value
	}
	path := backupOf()
	p, err := planRestore(cfg, path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.question, "This vault syncs") {
		t.Errorf("not syncing, but said:\n%s", p.question)
	}
	cfg.SyncDir = config.Setting[string]{Value: t.TempDir()}
	if p, err = planRestore(cfg, path); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.question, "This vault syncs") || !strings.Contains(p.question, "anything deleted since, on any computer, stays deleted, unless the backup holds a change to it that was never synced") || !strings.Contains(p.question, "sesh trash") {
		t.Errorf("syncing:\n%s", p.question)
	}
}
