package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

func runRestoreOut(t *testing.T, stdin string, terminal bool, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	app.StdinIsTerminal = func() bool { return terminal }
	err = runRestore(app, args)
	return app.Stdout.(*bytes.Buffer).String(), app.Stderr.(*bytes.Buffer).String(), err
}

// restoreVault is a vault with github and gitlab, backed up, then changed:
// gitlab deleted, bitbucket added. It returns the backup's path.
func restoreVault(t *testing.T, clock *time.Time) (*rekeyTestEnv, string) {
	t.Helper()
	env := backupVault(t, clock)
	populatePasswordStore(t, env, map[string]string{"password/github": "a", "password/gitlab": "b"})
	if _, err := runBackupOut(t); err != nil {
		t.Fatal(err)
	}
	backupPath := backups(t, env)[0].Path
	store := openDoctorVault(t, env)
	if err := store.Delete(entryKey(t, "password/gitlab")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(entryKey(t, "password/bitbucket"), []byte("c")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(time.Hour)
	return env, backupPath
}

func vaultEntries(t *testing.T, env *rekeyTestEnv) int {
	t.Helper()
	s, err := database.VaultSummary(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return s.Entries
}

func TestRestore_ListsBackups(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local)
	env := backupVault(t, &clock)
	populatePasswordStore(t, env, map[string]string{"password/github": "a"})
	if out, _, err := runRestoreOut(t, "", false); err != nil || !strings.HasPrefix(out, "No backups in ") {
		t.Errorf("none: %q, %v", out, err)
	}
	if _, err := runBackupOut(t); err != nil {
		t.Fatal(err)
	}
	// Another vault's backup with the same file name, in the same folder.
	other := filepath.Join(filepath.Dir(env.dbPath), "backups", "passwords-00000000-2026-10-01T090000Z.db")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runRestoreOut(t, "", false)
	if err != nil || !strings.Contains(out, "2026-10-07 09:12") || !strings.Contains(out, "passwords-00000000-2026-10-01T090000Z.db  (another vault)") || !strings.HasSuffix(out, "Restore one with: sesh restore <name>\n") {
		t.Errorf("list:\n%s\n%v", out, err)
	}
}

// Restoring saves the vault as it is, then puts the backup's entries back,
// in place.
func TestRestore_InPlace(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local)
	env, b := restoreVault(t, &clock)
	// Answering no changes nothing.
	if _, errOut, err := runRestoreOut(t, "n\n", true, filepath.Base(b)); err != nil || !strings.Contains(errOut, "Restore cancelled; nothing changed.") {
		t.Errorf("no: %q, %v", errOut, err)
	}
	if n := vaultEntries(t, env); n != 2 {
		t.Fatalf("%d entries after cancelling", n)
	}
	out, errOut, err := runRestoreOut(t, "y\n", true, filepath.Base(b))
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, errOut)
	}
	for _, want := range []string{"Restore the vault from " + filepath.Base(b) + ", made 2026-10-07 09:12 (2 entries)?", "The vault now (2 entries) is backed up first."} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the question is missing %q:\n%s", want, errOut)
		}
	}
	if !strings.Contains(out, "✅ Restored the vault from "+filepath.Base(b)+" (2 entries).") || !strings.Contains(out, "The vault as it was is in ") {
		t.Errorf("output: %s", out)
	}
	store := openDoctorVault(t, env)
	if got := services(t, store); got != "github gitlab" {
		t.Errorf("after: %q, want github gitlab", got)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The vault as it was is a backup now: two in the folder.
	if got := backups(t, env); len(got) != 2 {
		t.Errorf("%d backups, want the first and the one saved before restoring", len(got))
	}
}

func TestRestore_Refusals(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local)
	env, b := restoreVault(t, &clock)
	if _, _, err := runRestoreOut(t, "", false, b); err == nil || !strings.Contains(err.Error(), "add --force to restore without asking") {
		t.Errorf("no terminal: %v", err)
	}
	if _, _, err := runRestoreOut(t, "", true, "nope.db"); err == nil || !strings.Contains(err.Error(), "no backup at nope.db; see the backups with: sesh restore") {
		t.Errorf("no such backup: %v", err)
	}
	notVault := filepath.Join(t.TempDir(), "x.db")
	if err := os.WriteFile(notVault, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runRestoreOut(t, "y\n", true, notVault); err == nil {
		t.Error("a file that isn't a vault was restored")
	}
	if n := vaultEntries(t, env); n != 2 {
		t.Errorf("%d entries after refusals, want 2 unchanged", n)
	}
}

// A damaged vault is replaced whole, with --force and no terminal.
func TestRestore_DamagedVault(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local)
	env, b := restoreVault(t, &clock)
	if err := os.WriteFile(env.dbPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, err := runRestoreOut(t, "", false, "--force", b)
	if err != nil || !strings.Contains(errOut, "so it isn't backed up first: it's replaced whole") {
		t.Fatalf("restore: %v\n%s", err, errOut)
	}
	if n := vaultEntries(t, env); n != 2 {
		t.Errorf("%d entries, want the backup's 2", n)
	}
}

// A backup of another vault says so.
func TestRestore_AnotherVault(t *testing.T) {
	clock := time.Date(2026, 10, 7, 9, 12, 0, 0, time.Local)
	env, b := restoreVault(t, &clock)
	sqlExec(t, b, `UPDATE vault_info SET vault_id = 'aaaaaaaabbbbbbbb'`)
	_, errOut, err := runRestoreOut(t, "y\n", true, b)
	if err != nil || !strings.Contains(errOut, "It's a backup of another vault (this one's id is ") || !strings.Contains(errOut, "the backup's aaaaaaaa)") {
		t.Errorf("err = %v\n%s", err, errOut)
	}
	if n := vaultEntries(t, env); n != 2 {
		t.Errorf("%d entries, want the backup's 2", n)
	}
}

// services is the service names of store's entries, in order.
func services(t *testing.T, store *database.Store) string {
	t.Helper()
	all, err := store.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(all))
	for i := range all {
		names[i] = all[i].Service
	}
	return strings.Join(names, " ")
}
