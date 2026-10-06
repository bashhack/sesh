package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

type rekeyTestEnv struct {
	tmpDir      string
	dataDir     string
	dbPath      string
	sidecarPath string
}

func setupRekeyEnv(t *testing.T) *rekeyTestEnv {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "xdg"))
	t.Setenv("SESH_MASTER_PASSWORD", "")
	// Rekey locks a running agent; keep every test away from the user's.
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))

	dbPath, err := database.DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath: %v", err)
	}
	dataDir := filepath.Dir(dbPath)
	return &rekeyTestEnv{
		tmpDir:      tmp,
		dataDir:     dataDir,
		dbPath:      dbPath,
		sidecarPath: filepath.Join(dataDir, "passwords.key"),
	}
}

func rekeyTestApp(stdin string) (*App, *bytes.Buffer) {
	stderr := new(bytes.Buffer)
	return &App{
		Stdin:  strings.NewReader(stdin),
		Stdout: new(bytes.Buffer),
		Stderr: stderr,
		Exit:   func(int) {},
	}, stderr
}

// entryKey reads an entry's key in text form, as the tests name entries.
func entryKey(t *testing.T, id string) vault.Key {
	t.Helper()
	k, err := vault.ParseKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// seedStore opens the vault with ks and stores entries (key text → secret).
func seedStore(t *testing.T, env *rekeyTestEnv, ks database.KeySource, entries map[string]string) {
	t.Helper()
	store, err := database.Open(env.dbPath, database.NewKeySourceOracle(ks))
	if err != nil {
		t.Fatalf("open store for seeding: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close seed store: %v", cerr)
		}
	}()
	if err := store.InitKeyMetadata(); err != nil {
		t.Fatalf("init key metadata: %v", err)
	}
	for id, secret := range entries {
		if err := store.Put(entryKey(t, id), []byte(secret)); err != nil {
			t.Fatalf("seed entry %s: %v", id, err)
		}
	}
}

func populatePasswordStore(t *testing.T, env *rekeyTestEnv, entries map[string]string) {
	t.Helper()
	seedStore(t, env, resolvePasswordPrompt().newSource(env.dataDir), entries)
}

// readEntries opens the vault with ks and returns the secrets of the
// entries ids name.
func readEntries(t *testing.T, env *rekeyTestEnv, ks database.KeySource, ids []string) map[string]string {
	t.Helper()
	store, err := database.Open(env.dbPath, database.NewKeySourceOracle(ks))
	if err != nil {
		t.Fatalf("open store for verify: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close verify store: %v", cerr)
		}
	}()
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		b, err := store.Get(entryKey(t, id))
		if err != nil {
			t.Fatalf("get entry %s: %v", id, err)
		}
		out[id] = string(b)
	}
	return out
}

func readEntriesViaPassword(t *testing.T, env *rekeyTestEnv, ids []string) map[string]string {
	t.Helper()
	return readEntries(t, env, resolvePasswordPrompt().newSource(env.dataDir), ids)
}

func TestAppendErr_NilPrimary(t *testing.T) {
	got := appendErr(nil, "label", errors.New("secondary"))
	if got == nil || got.Error() != "label: secondary" {
		t.Errorf("got %v, want 'label: secondary'", got)
	}
}

func TestAppendErr_WithPrimary(t *testing.T) {
	primary := errors.New("primary failure")
	got := appendErr(primary, "rollback step", errors.New("cleanup failed"))
	if !strings.Contains(got.Error(), "primary failure") {
		t.Errorf("primary not preserved in %q", got.Error())
	}
	if !strings.Contains(got.Error(), "rollback step also failed: cleanup failed") {
		t.Errorf("secondary not labelled correctly in %q", got.Error())
	}
	if !errors.Is(got, primary) {
		t.Errorf("appended error should still wrap primary for errors.Is")
	}
}

func TestPromptYesNo(t *testing.T) {
	cases := map[string]bool{
		"y\n":     true,
		"Y\n":     true,
		"yes\n":   false,
		"n\n":     false,
		"\n":      false,
		"":        false,
		"  y  \n": true,
	}
	for input, want := range cases {
		t.Run(strings.TrimSpace(input), func(t *testing.T) {
			got, err := promptYesNo(strings.NewReader(input), new(bytes.Buffer), "")
			if err != nil {
				t.Fatalf("promptYesNo(%q): %v", input, err)
			}
			if got != want {
				t.Errorf("promptYesNo(%q) = %v, want %v", input, got, want)
			}
		})
	}
}

// sequencedPrompt returns each password in order, erroring once the list
// is exhausted. Used by rotation tests where source unlock and target
// create+confirm need different inputs from the same prompt callback.
func sequencedPrompt(passwords ...string) database.PasswordPromptFunc {
	i := 0
	return func(_ string) ([]byte, error) {
		if i >= len(passwords) {
			return nil, fmt.Errorf("test prompt exhausted at call %d", i+1)
		}
		pw := []byte(passwords[i])
		i++
		return pw, nil
	}
}

// rotateTestCfg builds a non-interactive prompt config from a sequenced
// list of passwords. Non-interactive disables the retry loop, which is
// what we want in tests — a wrong password should fail fast, not consume
// extra entries from the sequence.
func rotateTestCfg(passwords ...string) passwordPromptConfig {
	return passwordPromptConfig{prompt: sequencedPrompt(passwords...), interactive: false}
}

func TestRotate_PasswordChangesPassword(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	entries := map[string]string{
		"password/github/alice": "hunter2",
		"api_key/stripe/admin":  "sk_test_xyz",
	}
	populatePasswordStore(t, env, entries)
	t.Setenv("SESH_MASTER_PASSWORD", "")

	app, stderr := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("runRotateMasterPassword: %v\nstderr:\n%s", err, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Rotated 2 entries") {
		t.Errorf("stderr missing rotation summary:\n%s", stderr.String())
	}
	for _, p := range []string{env.dbPath + rotateBackupSuffix, env.sidecarPath + rotateBackupSuffix} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("old copy %s still exists (err %v)", p, err)
		}
	}
	if !strings.Contains(stderr.String(), "Removed the old vault's copy, so the old key no longer opens anything.") {
		t.Errorf("stderr missing the removal note:\n%s", stderr)
	}

	// New password unlocks the rotated DB.
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	services := []string{"password/github/alice", "api_key/stripe/admin"}
	got := readEntriesViaPassword(t, env, services)
	for svc, want := range entries {
		if got[svc] != want {
			t.Errorf("entry %s under new password = %q, want %q", svc, got[svc], want)
		}
	}
}

func TestRotate_PreservesPerEntryFreshness(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{
		"password/github/alice": "same-secret",
		"password/github/bob":   "same-secret",
	})

	beforeBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	afterBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforeBlob, afterBlob) {
		t.Fatal("rotated DB byte-for-byte identical to original — re-encryption did not run")
	}

	// Sidecar salt must also have changed (proves new KDF derivation, not
	// just a re-encryption with the same derived key).
	afterSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatalf("read rotated sidecar: %v", err)
	}
	if bytes.Equal(beforeSidecar, afterSidecar) {
		t.Fatal("rotated sidecar identical to the old one — salt was not regenerated")
	}
}

func TestRotate_RemovesStagingLockOnSuccess(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	stagingLock := env.sidecarPath + rekeyDestSuffix + ".lock"
	if _, err := os.Stat(stagingLock); !os.IsNotExist(err) {
		t.Errorf("staging sidecar lock %s should be removed after successful rotation, got stat err %v", stagingLock, err)
	}
}

func TestRotate_RemovesStagingLockOnConfirmMismatch(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	// Mismatched confirm fires inside initialize(), AFTER the staging
	// lock file has been created via O_CREATE in initializeLocked. The
	// lock file should be cleaned up by the rollback path.
	cfg := rotateTestCfg("old-pw-1234", "new-pw-aaaaaa", "new-pw-bbbbbb")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "passwords do not match") {
		t.Fatalf("expected passwords-do-not-match error, got %v", err)
	}
	stagingLock := env.sidecarPath + rekeyDestSuffix + ".lock"
	if _, err := os.Stat(stagingLock); !os.IsNotExist(err) {
		t.Errorf("staging sidecar lock %s should be removed after rollback, got stat err %v", stagingLock, err)
	}
}

func TestRotate_RemovesStagingLockOnCancel(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	// Cancel before the destination source is constructed at all — the
	// staging lock should never be created. Regression guard against a
	// future change that moves destKS construction earlier.
	app, _ := rekeyTestApp("n\n")
	cfg := rotateTestCfg("old-pw-1234")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("cancelled rotation should not error: %v", err)
	}
	stagingLock := env.sidecarPath + rekeyDestSuffix + ".lock"
	if _, err := os.Stat(stagingLock); !os.IsNotExist(err) {
		t.Errorf("staging sidecar lock %s should not exist after cancel, got stat err %v", stagingLock, err)
	}
}

func TestRotate_RefusesIfDatabaseMissing(t *testing.T) {
	setupRekeyEnv(t)
	app, _ := rekeyTestApp("")
	err := runRotateMasterPassword(app, rotateTestCfg("any-pw-1234"))
	if err == nil || !strings.Contains(err.Error(), "no database to rotate") {
		t.Fatalf("expected no-database error, got %v", err)
	}
}

func TestRotate_RefusesIfSidecarMissing(t *testing.T) {
	env := setupRekeyEnv(t)
	// Create a DB file directly (bypassing sesh) so the DB-stat check passes
	// but the sidecar doesn't exist.
	if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.dbPath, []byte("not a real db"), 0o600); err != nil {
		t.Fatalf("write fake db: %v", err)
	}
	app, _ := rekeyTestApp("")
	err := runRotateMasterPassword(app, rotateTestCfg("any-pw-1234"))
	if err == nil || !strings.Contains(err.Error(), "its key file") {
		t.Fatalf("expected the missing key file named, got %v", err)
	}
}

// Files an earlier change left behind (an older sesh kept backups; an
// interrupted change can leave staged files) are removed once the current
// password is verified, and the change goes ahead.
func TestRotate_ClearsLeftovers(t *testing.T) {
	for _, tt := range []struct {
		leftover func(*rekeyTestEnv) string
		name     string
	}{
		{func(e *rekeyTestEnv) string { return e.dbPath + rekeyDestSuffix }, "staged vault"},
		{func(e *rekeyTestEnv) string { return e.dbPath + rotateBackupSuffix }, "old vault copy"},
		{func(e *rekeyTestEnv) string { return e.sidecarPath + rekeyDestSuffix }, "staged key file"},
		{func(e *rekeyTestEnv) string { return e.sidecarPath + rotateBackupSuffix }, "old key file copy"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := setupRekeyEnv(t)
			t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
			populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
			leftover := tt.leftover(env)
			if err := os.WriteFile(leftover, []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}

			t.Setenv("SESH_MASTER_PASSWORD", "")
			app, stderr := rekeyTestApp("y\n")
			if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
				t.Fatalf("rotate with a leftover: %v\n%s", err, stderr)
			}
			if !strings.Contains(stderr.String(), "Removed files left by an earlier change: "+filepath.Base(leftover)) {
				t.Errorf("stderr missing the leftovers note:\n%s", stderr)
			}
			for _, p := range []string{env.dbPath + rekeyDestSuffix, env.dbPath + rotateBackupSuffix, env.sidecarPath + rekeyDestSuffix, env.sidecarPath + rotateBackupSuffix} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("%s exists after the change (err %v)", p, err)
				}
			}
		})
	}
}

func TestRotate_WrongSourcePassword(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "right-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	beforeSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	// Only a verified current password clears an earlier change's files.
	leftover := env.dbPath + rotateBackupSuffix
	if err := os.WriteFile(leftover, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := os.Stat(leftover); err != nil {
			t.Errorf("leftover removed although the password was wrong (err %v)", err)
		}
	})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	// Wrong source password — fails at unlock before any prompt for a new
	// password. cfg only provides the wrong one; if we accidentally drained
	// further from the sequence, the "test prompt exhausted" error would
	// surface and tell us the test no longer pins the right behavior.
	cfg := rotateTestCfg("wrong-pw-1234")
	err = runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "unlock current sidecar") {
		t.Fatalf("expected unlock error for wrong source password, got %v", err)
	}
	if !strings.Contains(err.Error(), "wrong master password") {
		t.Errorf("error %q should bubble up the underlying wrong-password message", err.Error())
	}
	// Canonical sidecar must be untouched. No write path is reachable
	// before the failed unlock, so this is a regression guard against
	// future refactors that move sidecar writes earlier in the flow.
	afterSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeSidecar, afterSidecar) {
		t.Error("canonical sidecar modified after wrong-password failure")
	}
}

func TestRotate_PasswordCancelledLeavesNoChanges(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	beforeBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	// Pass "n" to the y/N prompt to abort. Source unlock still happens (one
	// password drained from the sequence); target Create+Confirm is never
	// reached, so only the source password is consumed.
	app, _ := rekeyTestApp("n\n")
	cfg := rotateTestCfg("old-pw-1234")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("cancelled rotation should not error: %v", err)
	}

	afterBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeBlob, afterBlob) {
		t.Error("DB modified after cancelled rotation")
	}
	afterSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeSidecar, afterSidecar) {
		t.Error("canonical sidecar modified after cancelled rotation")
	}
	for _, p := range []string{
		env.dbPath + rekeyDestSuffix,
		env.dbPath + rotateBackupSuffix,
		env.sidecarPath + rekeyDestSuffix,
		env.sidecarPath + rotateBackupSuffix,
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("staging/backup file %s should not exist after cancel: %v", p, err)
		}
	}
}

func TestCheckCopied(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "check-copied-1234")
	populatePasswordStore(t, env, map[string]string{"password/a/b": "1", "password/c/d": "2"})
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	if err := checkCopied(store, 2); err != nil {
		t.Errorf("a complete copy: %v", err)
	}
	if err := checkCopied(store, 3); err == nil || !strings.Contains(err.Error(), "the new vault holds 2 entries, but 3 were copied; nothing was changed") {
		t.Errorf("a short copy: err = %v", err)
	}
	wrong, err := database.Open(env.dbPath, database.NewKeySourceOracle(&recoveredKey{key: bytes.Repeat([]byte{1}, 32)}))
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(wrong)
	if err := checkCopied(wrong, 2); err == nil || !strings.Contains(err.Error(), "check the new vault's key") {
		t.Errorf("a vault the key doesn't open: err = %v", err)
	}
}

// failingAfter fails every write once one contains marker.
type failingAfter struct {
	marker string
	failed bool
}

func (w *failingAfter) Write(p []byte) (int, error) {
	if w.failed || strings.Contains(string(p), w.marker) {
		w.failed = true
		return 0, errors.New("stderr closed")
	}
	return len(p), nil
}

// The old copies go even if the success message can't be written.
func TestRotate_RemovesOldCopiesBeforeReporting(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	app.Stderr = &failingAfter{marker: "Rotated"}
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err == nil {
		t.Fatal("expected the write failure to be returned")
	}
	for _, p := range []string{env.dbPath + rotateBackupSuffix, env.sidecarPath + rotateBackupSuffix} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left behind after a failed write (err %v)", p, err)
		}
	}
}

// Only one key change runs on a vault at a time; a second one refuses
// before touching anything, including the first one's in-progress files.
func TestRotate_OneAtATime(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	inProgress := env.dbPath + rotateBackupSuffix // another change's in-progress copy
	if err := os.WriteFile(inProgress, []byte("first change's copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := lockKeyChange(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	err = runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678"))
	if err == nil || !strings.Contains(err.Error(), "another sesh command is changing this vault's key") {
		t.Errorf("second change: err = %v", err)
	}
	if _, err := os.Stat(inProgress); err != nil {
		t.Errorf("the second change removed the first one's copy: %v", err)
	}
	release()
	app, _ = rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Errorf("after the lock was released: %v", err)
	}
}

// failRename makes renameFile fail for one source → destination pair, and
// calls during(src, dst) on every rename, so a test can look at the state
// while the change or its rollback is running.
func failRename(t *testing.T, src, dst string, during func(src, dst string)) {
	t.Helper()
	orig := renameFile
	renameFile = func(s, d string) error {
		if during != nil {
			during(s, d)
		}
		if s == src && d == dst {
			return errors.New("injected rename failure")
		}
		return orig(s, d)
	}
	t.Cleanup(func() { renameFile = orig })
}

// If the new key file can't be moved into place after the old one was moved
// aside, rollback puts both the old vault and the old key file back, while
// still holding the key-change lock.
func TestRotate_RollsBackAPartialSwap(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "the secret"})
	lockFreeDuringRollback := false
	failRename(t, env.sidecarPath+rekeyDestSuffix, env.sidecarPath, func(src, dst string) {
		if src == env.dbPath+rotateBackupSuffix && dst == env.dbPath { // rollback restoring the vault
			if release, err := lockKeyChange(env.dataDir); err == nil {
				lockFreeDuringRollback = true
				release()
			}
		}
	})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678"))
	if err == nil || !strings.Contains(err.Error(), "injected rename failure") {
		t.Fatalf("err = %v, want the injected failure", err)
	}
	if strings.Contains(err.Error(), "finish the rename manually") {
		t.Errorf("error points at files the rollback removes: %v", err)
	}
	if lockFreeDuringRollback {
		t.Error("another key change could take the lock while rollback was running")
	}
	if _, err := os.Stat(env.sidecarPath); err != nil {
		t.Fatalf("the vault has no passwords.key after rollback: %v", err)
	}
	for _, p := range []string{env.sidecarPath + rotateBackupSuffix, env.dbPath + rotateBackupSuffix, env.sidecarPath + rekeyDestSuffix} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left after rollback (err %v)", p, err)
		}
	}
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	got := readEntriesViaPassword(t, env, []string{"password/x/y"})
	if got["password/x/y"] != "the secret" {
		t.Errorf("entry after rollback = %q, want the old password to open the old vault", got["password/x/y"])
	}
}

// A change that stops before staging anything leaves another change's
// staging lock alone.
func TestRotate_LeavesAnotherChangesStagingLock(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	staging := env.sidecarPath + rekeyDestSuffix + ".lock"
	if err := os.WriteFile(staging, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")

	app, _ := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("wrong-pw-1234")); err == nil {
		t.Fatal("expected the wrong password to fail")
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("a change with the wrong password removed another change's staging lock: %v", err)
	}

	release, err := lockKeyChange(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	app, _ = rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234")); err == nil {
		t.Fatal("expected the held lock to refuse the change")
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("a refused change removed another change's staging lock: %v", err)
	}
}

func TestEntryCount(t *testing.T) {
	for n, want := range map[int]string{0: "0 entries", 1: "1 entry", 2: "2 entries"} {
		if got := entryCount(n); got != want {
			t.Errorf("entryCount(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestRekey_TakesNoArguments(t *testing.T) {
	for _, args := range [][]string{{"--to", "password"}, {"--key-source", "password"}} {
		app, _ := rekeyTestApp("")
		err := runRekey(app, args, rotateTestCfg())
		if wantSub := "--rekey takes no arguments"; err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%q: err = %v, want it to contain %q", args, err, wantSub)
		}
	}
	app, _ := rekeyTestApp("")
	if err := runRekey(app, []string{"--help"}, rotateTestCfg()); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "Usage: sesh --rekey") {
		t.Errorf("--help printed %q", out)
	}
}

func TestRekey_ChangesTheMasterPassword(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "the secret"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, nil, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rekey: %v\n%s", err, stderr)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	if got := readEntriesViaPassword(t, env, []string{"password/x/y"}); got["password/x/y"] != "the secret" {
		t.Errorf("entry under the new password = %q", got["password/x/y"])
	}
}

// Entries named before the name rules (a trailing space, a long name) are
// still copied by a password change.
func TestRotate_KeepsNamesSavedBeforeTheNameRules(t *testing.T) {
	env := setupRekeyEnv(t)
	long := "password/" + strings.Repeat("x", 300)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/github ": "spaced", long: "long"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	got := readEntriesViaPassword(t, env, []string{"password/github ", long})
	if got["password/github "] != "spaced" || got[long] != "long" {
		t.Errorf("after the change: %q", got)
	}
}
