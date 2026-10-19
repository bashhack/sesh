package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vaultsync"
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
		filepath.Join(home, "Sync", "passwords.db"):                                                       "",
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
	// Another link there, even to the home folder, isn't a folder iCloud
	// keeps.
	if err := os.Symlink(home, filepath.Join(docs, "Home shortcut")); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, ".local", "share", "sesh", "passwords.db")); got != "" {
		t.Errorf("under a link to home in iCloud Drive: %q", got)
	}
	// ~/Desktop isn't kept when iCloud Drive's Desktop leads elsewhere.
	if err := os.Symlink(home, filepath.Join(docs, "Desktop")); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, "Desktop", "passwords.db")); got != "" {
		t.Errorf("~/Desktop, iCloud Drive's Desktop leading elsewhere: %q", got)
	}
	// ~/Sync is Syncthing's once Syncthing marks it as shared.
	if err := os.MkdirAll(filepath.Join(home, "Sync", ".stfolder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := cloudTool(filepath.Join(home, "Sync", "passwords.db")); got != "Syncthing" {
		t.Errorf("Syncthing's folder: %q", got)
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
	usual, err := database.DefaultDBLocation()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := runDoctorOut(t) //nolint:errcheck // warnings exit 0; the output is checked
	if !strings.Contains(out, "warn  Vault place     in a folder Dropbox syncs") || !strings.Contains(out, "sesh sync init") ||
		!strings.Contains(out, "move passwords.db (and any passwords.db-wal and passwords.db-shm and touchid.key beside it)") ||
		!strings.Contains(out, "change SESH_DB_PATH to its new place") || !strings.Contains(out, "(not "+tildePath(filepath.Dir(usual))+": a vault is there already)") {
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
	if !strings.Contains(out, "warn  Sync") || !strings.Contains(out, "1 entry's file is sealed with another master password's key: sync leaves it for the computer that wrote it") {
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
	if status, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(status, "isn't there now: a drive not connected") {
		t.Errorf("status, the folder away (%v):\n%s", err, status)
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

// Doctor fails the sync row when sync would refuse the folder: the vault
// synced with another one, and both hold entries.
func TestDoctor_SyncRowRefusedFolder(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	t.Setenv("SESH_BACKUP_EVERY_DAYS", "0")
	dir := t.TempDir()
	folder, other := filepath.Join(dir, "sync"), filepath.Join(dir, "other")
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	if _, err := runSyncOut(t, "", false, "init", other); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvSyncDir, folder)
	out, err := runDoctorOut(t)
	if err == nil || !strings.Contains(out, "FAIL  Sync") || !strings.Contains(out, "synced with another sync folder") {
		t.Errorf("a folder sync refuses (%v):\n%s", err, out)
	}
}

// Doctor says a sync folder that lost its sesh-sync.json is written again
// by a sync, and that a never-synced vault joins with an empty one.
func TestDoctor_SyncRowLostInfoAndNeverSynced(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	t.Setenv("SESH_BACKUP_EVERY_DAYS", "0")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	db := syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	// A copy of the vault, never synced, for the second half.
	copyDB := filepath.Join(dir, "copy", "passwords.db")
	if err := os.MkdirAll(filepath.Dir(copyDB), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := database.CopyTo(db, copyDB); err != nil {
		t.Fatal(err)
	}
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(folder, "sesh-sync.json")); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctorOut(t)
	if err != nil || !strings.Contains(out, "warn  Sync") || !strings.Contains(out, "sesh sync writes it again") || !strings.Contains(out, "Sync, which writes the sync folder's lost file again:") {
		t.Errorf("a lost info file (%v):\n%s", err, out)
	}
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	t.Setenv(config.EnvDBPath, copyDB)
	t.Setenv(config.EnvSyncDir, folder)
	app := agentTestApp()
	err = runDoctor(app, nil)
	out = app.Stdout.(*bytes.Buffer).String() + app.Stderr.(*bytes.Buffer).String()
	if err == nil || !strings.Contains(out, "never synced with this folder") || !strings.Contains(out, "Join the folder with an empty vault (sesh sync join explains), or stop syncing:") {
		t.Errorf("a never-synced vault (%v):\n%s", err, out)
	}
}

// A sync's warnings are said, even when there was nothing else to do, and
// don't fail it.
func TestWriteSyncSummary_Warnings(t *testing.T) {
	app := agentTestApp()
	err := writeSyncSummary(app, "~/sync", &vaultsync.Summary{Warnings: []string{"make ~/sync/sesh-sync.json readable only by you: not permitted"}})
	out := app.Stdout.(*bytes.Buffer).String()
	if err != nil || !strings.Contains(out, "nothing to do") || !strings.Contains(out, "⚠️  make ~/sync/sesh-sync.json readable only by you") {
		t.Errorf("warnings only: %q, %v", out, err)
	}
}

// Entries set back or held back on taking a password change are said by
// name, by sesh sync and by an automatic sync.
func TestSyncSummary_SetAndHeldBack(t *testing.T) {
	s := &vaultsync.Summary{SetBack: []string{"password/a"}, HeldBack: []string{"password/b", "password/c"}, Retype: []string{"password/d"}}
	app := agentTestApp()
	if err := writeSyncSummary(app, "~/sync", s); err != nil {
		t.Fatal(err)
	}
	auto := strings.Join(autoSummary(s), "\n")
	for _, want := range []string{
		"1 entry (password/a) made the same as on your other computers, under the new master password: what this computer had besides was taken under the old one",
		"2 entries (password/b, password/c): your other computers have no version under the new master password, and it wasn't made here: not sent until one of them has",
		"1 entry (password/d) made here, whose secret this vault no longer has as typed here (forgotten, or trimmed to history.keep): not sent until it's typed again here",
	} {
		if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, want) {
			t.Errorf("sesh sync: %q, want %q", out, want)
		}
		if !strings.Contains(auto, want) {
			t.Errorf("automatic sync: %q, want %q", auto, want)
		}
	}
}

// Entries held back are said even when the sync had nothing else to do.
func TestWriteSyncSummary_HeldBackOnly(t *testing.T) {
	app := agentTestApp()
	err := writeSyncSummary(app, "~/sync", &vaultsync.Summary{HeldBack: []string{"password/b"}})
	out := app.Stdout.(*bytes.Buffer).String()
	if err != nil || !strings.Contains(out, "nothing to do") || !strings.Contains(out, "⚠️  1 entry (password/b): your other computers have no version") {
		t.Errorf("held back only: %q, %v", out, err)
	}
}

// A syncing vault with weaker key settings is told to change its master
// password, which the other computers take; sesh passwd and recover say
// so, and a vault that left says what joining again does.
func TestSync_KeyChangeWarnings(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	t.Setenv("SESH_BACKUP_EVERY_DAYS", "0")
	dir := t.TempDir()
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", filepath.Join(dir, "sync")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_KDF_MEMORY", "32MiB")
	out, _ := runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "warn  Key settings") || !strings.Contains(out, "       sesh passwd\n") || !strings.Contains(out, "the other computers ask for the new master password at their next sync") {
		t.Errorf("doctor, syncing with weaker settings:\n%s", out)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("n\n")
	if err := runRekey(app, nil, rotateTestCfg("sync-password-1234")); err != nil {
		t.Fatalf("passwd: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr.String(), "This vault syncs with") || !strings.Contains(stderr.String(), "the change goes to the sync folder") || !strings.Contains(stderr.String(), "Rotation cancelled") {
		t.Errorf("passwd's warning:\n%s", stderr)
	}
	// The recovery key's change: joining again needs the others' password.
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if w := syncKeyChangeWarning(cfg, true); !strings.Contains(w, "the new master password goes to the sync folder") {
		t.Errorf("recover's warning: %q", w)
	}

	// Left the folder: sesh passwd is offered, saying what it does to
	// joining again.
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	out, _ = runDoctorOut(t) //nolint:errcheck // checked by the output
	if !strings.Contains(out, "warn  Key settings") || !strings.Contains(out, "       sesh passwd\n") || !strings.Contains(out, "joining it again asks for the folder's master password") {
		t.Errorf("doctor, left the folder:\n%s", out)
	}

	// Never synced: no warning.
	syncComputer(t, filepath.Join(dir, "other"), "other")
	putEntry(t, "password/b", "2")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr = rekeyTestApp("n\n")
	if err := runRekey(app, nil, rotateTestCfg("sync-password-1234")); err != nil {
		t.Fatalf("passwd, never synced: %v\n%s", err, stderr)
	}
	if strings.Contains(stderr.String(), "⚠️") {
		t.Errorf("passwd warned a vault that never synced:\n%s", stderr)
	}
}
