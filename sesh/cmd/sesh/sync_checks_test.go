package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
)

// A vault in a folder a sync tool copies is warned of, with what to do.
func TestCloudTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for path, want := range map[string]string{
		filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "sesh", "passwords.db"): "iCloud Drive",
		filepath.Join(home, "Library", "CloudStorage", "Dropbox", "passwords.db"):                         "a cloud storage app (Dropbox, Google Drive, OneDrive, Box)",
		filepath.Join(home, "Dropbox", "passwords.db"):                                                    "Dropbox",
		filepath.Join(home, ".local", "share", "sesh", "passwords.db"):                                    "",
		filepath.Join(home, "DropboxNot", "passwords.db"):                                                 "",
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
	if !strings.Contains(out, "warn  Vault place     in a folder Dropbox syncs") || !strings.Contains(out, "sesh sync init") {
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
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/github/alice", "pw-1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	out, _ := runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "ok    Sync            with "+folder+", last synced ") {
		t.Errorf("synced:\n%s", out)
	}
	// One entry's file evicted by iCloud, as its old placeholder.
	entries, err := os.ReadDir(filepath.Join(folder, "entries"))
	if err != nil || len(entries) != 1 {
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
	if !strings.Contains(p.question, "This vault syncs") || !strings.Contains(p.question, "anything deleted since, on any computer, stays deleted") || !strings.Contains(p.question, "sesh trash") {
		t.Errorf("syncing:\n%s", p.question)
	}
}
