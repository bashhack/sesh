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
	tmpDir  string
	dataDir string
	dbPath  string
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
	return &rekeyTestEnv{tmpDir: tmp, dataDir: dataDir, dbPath: dbPath}
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
	for id, secret := range entries {
		if err := store.Put(entryKey(t, id), []byte(secret)); err != nil {
			t.Fatalf("seed entry %s: %v", id, err)
		}
	}
}

func populatePasswordStore(t *testing.T, env *rekeyTestEnv, entries map[string]string) {
	t.Helper()
	seedStore(t, env, resolvePasswordPrompt().newSource(env.dbPath), entries)
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
	return readEntries(t, env, resolvePasswordPrompt().newSource(env.dbPath), ids)
}

// keySalt is the salt in the key record of the vault at dbPath.
func keySalt(t *testing.T, dbPath string) []byte {
	t.Helper()
	m, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return m.Salt
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
	if _, err := os.Stat(env.dbPath + rotateBackupSuffix); !os.IsNotExist(err) {
		t.Errorf("the old copy still exists (err %v)", err)
	}
	if !strings.Contains(stderr.String(), "Removed the old vault's copy, so the old key no longer opens anything.") {
		t.Errorf("stderr missing the removal note:\n%s", stderr)
	}
	// The vault is one file; the key-change lock is the only other.
	names, err := os.ReadDir(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n.Name() != filepath.Base(env.dbPath) && n.Name() != keyChangeLockFile {
			t.Errorf("the vault folder holds %s after the change", n.Name())
		}
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

// stubTerminalPrompt makes terminalPasswordPrompt return cfg.
func stubTerminalPrompt(t *testing.T, cfg passwordPromptConfig) {
	t.Helper()
	orig := terminalPasswordPrompt
	terminalPasswordPrompt = func() passwordPromptConfig { return cfg }
	t.Cleanup(func() { terminalPasswordPrompt = orig })
}

func TestRotate_EnvPasswordIsOnlyTheCurrentOne(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})

	// SESH_MASTER_PASSWORD answers every prompt it's given; the new
	// password has to come from the terminal instead.
	stubTerminalPrompt(t, passwordPromptConfig{prompt: sequencedPrompt("new-pw-5678", "new-pw-5678"), interactive: true})
	app, stderr := rekeyTestApp("y\n")
	envCfg := passwordPromptConfig{prompt: func(string) ([]byte, error) { return []byte("old-pw-1234"), nil }, fromEnv: true}
	if err := runRotateMasterPassword(app, envCfg); err != nil {
		t.Fatalf("runRotateMasterPassword: %v\nstderr:\n%s", err, stderr.String())
	}
	// The variable still holds the old password, so the next command
	// would fail with "wrong master password" without saying why.
	if want := "SESH_MASTER_PASSWORD still holds the old password"; !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr doesn't say %q:\n%s", want, stderr.String())
	}

	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	if got := readEntriesViaPassword(t, env, []string{"password/github/alice"}); got["password/github/alice"] != "hunter2" {
		t.Errorf("the new password doesn't open the rotated vault: %v", got)
	}
}

func TestRotate_EnvPasswordWithoutATerminalRefuses(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})

	stubTerminalPrompt(t, passwordPromptConfig{prompt: sequencedPrompt(), interactive: false})
	app, _ := rekeyTestApp("y\n")
	envCfg := passwordPromptConfig{prompt: func(string) ([]byte, error) { return []byte("old-pw-1234"), nil }, fromEnv: true}
	err := runRotateMasterPassword(app, envCfg)
	if wantSub := "the new master password is asked at a terminal"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("runRotateMasterPassword without a terminal = %v, want it to contain %q", err, wantSub)
	}

	// Nothing changed: no staging was started, and the old password still
	// opens the vault.
	if _, err := os.Stat(env.dbPath + rekeyDestSuffix); !os.IsNotExist(err) {
		t.Errorf("a staged vault exists after the refusal (stat: %v)", err)
	}
	if got := readEntriesViaPassword(t, env, []string{"password/github/alice"}); got["password/github/alice"] != "hunter2" {
		t.Errorf("the old password no longer opens the vault: %v", got)
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
	beforeSalt := keySalt(t, env.dbPath)

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

	// The salt must also have changed (proves new KDF derivation, not
	// just a re-encryption with the same derived key).
	if bytes.Equal(beforeSalt, keySalt(t, env.dbPath)) {
		t.Fatal("the rotated vault has the old salt")
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

// A vault that holds entries but lost its key record is refused, not given
// a new master password that couldn't read them.
func TestRotate_RefusesAVaultWithoutItsKeyRecord(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	dropKeyRecord(t, env.dbPath)
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678"))
	if err == nil || !strings.Contains(err.Error(), "holds entries but not the record its key is made from") {
		t.Fatalf("expected the missing key record named, got %v", err)
	}
	if _, err := os.Stat(env.dbPath + rekeyDestSuffix); !os.IsNotExist(err) {
		t.Errorf("a staged vault was made (stat: %v)", err)
	}
}

// A new password that isn't confirmed leaves no staged vault.
func TestRotate_ConfirmMismatchStagesNothing(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-aaaaaa", "new-pw-bbbbbb"))
	if err == nil || !strings.Contains(err.Error(), "passwords do not match") {
		t.Fatalf("expected passwords-do-not-match error, got %v", err)
	}
	for _, p := range keyChangeLeftovers(env.dbPath) {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s exists after the mismatch (stat: %v)", p, err)
		}
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
		{func(e *rekeyTestEnv) string { return e.dbPath + rekeyDestSuffix + "-wal" }, "staged vault's journal"},
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
			for _, p := range keyChangeLeftovers(env.dbPath) {
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
	beforeSalt := keySalt(t, env.dbPath)
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
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "unlock the vault") {
		t.Fatalf("expected unlock error for wrong source password, got %v", err)
	}
	if !strings.Contains(err.Error(), "wrong master password") {
		t.Errorf("error %q should bubble up the underlying wrong-password message", err.Error())
	}
	if !bytes.Equal(beforeSalt, keySalt(t, env.dbPath)) {
		t.Error("the key record changed after a wrong password")
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
	beforeSalt := keySalt(t, env.dbPath)

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
	if !bytes.Equal(beforeSalt, keySalt(t, env.dbPath)) {
		t.Error("the key record changed after a cancelled rotation")
	}
	for _, p := range keyChangeLeftovers(env.dbPath) {
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
	key, err := resolvePasswordPrompt().newSource(env.dbPath).GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCopied(store, env.dbPath, key, 2); err != nil {
		t.Errorf("a complete copy: %v", err)
	}
	if err := checkCopied(store, env.dbPath, key, 3); err == nil || !strings.Contains(err.Error(), "the new vault holds 2 entries, but 3 were copied; nothing was changed") {
		t.Errorf("a short copy: err = %v", err)
	}
	if err := checkCopied(store, env.dbPath, bytes.Repeat([]byte{1}, 32), 2); err == nil || !strings.Contains(err.Error(), "check the new vault's key") {
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
	if _, err := os.Stat(env.dbPath + rotateBackupSuffix); !os.IsNotExist(err) {
		t.Errorf("the old copy was left behind after a failed write (err %v)", err)
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

// If the new vault can't be moved into place after the old one was moved
// aside, rollback puts the old vault back, while still holding the
// key-change lock.
func TestRotate_RollsBackAPartialSwap(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "the secret"})
	lockFreeDuringRollback := false
	failRename(t, env.dbPath+rekeyDestSuffix, env.dbPath, func(src, dst string) {
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
	for _, p := range keyChangeLeftovers(env.dbPath) {
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
