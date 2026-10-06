package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/touchid"
)

// dropKeyRecord removes the key record of the vault at dbPath, as damage
// would.
func dropKeyRecord(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM vault_key`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// A vault with entries but no key record is refused by every command that
// opens it, and isn't given a new key that couldn't read them.
func TestVaultWithoutKeyRecord_IsRefused(t *testing.T) {
	commands := map[string]func(app *App) error{
		"open": func(*App) error {
			store, err := openSQLiteStore()
			if err == nil {
				closeAuditStore(store)
			}
			return err
		},
		"recovery new":   func(app *App) error { return runRecovery(app, []string{"new"}) },
		"touchid enable": func(app *App) error { return runTouchID(app, []string{"enable"}) },
		"recover":        func(app *App) error { return runRecover(app, nil) },
		"--rekey":        func(app *App) error { return runRekey(app, nil, rotateTestCfg("pw-1234-5678")) },
	}
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			env := setupRekeyEnv(t)
			t.Setenv("SESH_MASTER_PASSWORD", "pw-1234-5678")
			populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})
			dropKeyRecord(t, env.dbPath)
			origAvail := touchIDAvailable
			touchIDAvailable = func() bool { return true }
			t.Cleanup(func() { touchIDAvailable = origAvail })
			app, _ := rekeyTestApp("y\n")
			wantSub := "holds entries but not the record its key is made from"
			if err := run(app); err == nil || !strings.Contains(err.Error(), wantSub) {
				t.Errorf("err = %v, want it to contain %q", err, wantSub)
			}
			if _, err := database.ReadUnlockMaterial(env.dbPath); err == nil {
				t.Error("a new key record was made")
			}
		})
	}
}

// A vault folder that can't be read isn't taken for a first run.
func TestUnreadableVaultFolder_FailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil { //nolint:gosec // deliberately unreadable
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // restore for cleanup
			t.Error(err)
		}
	})
	dbPath := filepath.Join(dir, "passwords.db")
	if vaultMissing(dbPath) {
		t.Error("an unreadable vault folder counts as no vault")
	}
	err := requireVault(dbPath, "no vault")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want the permission error", err)
	}
}

// A vault swapped in while this command was unlocking (another command's
// password change) is refused, so nothing is written to it under the old key.
func TestOpenStore_RefusesAVaultSwappedInAfterUnlock(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "first-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})
	oracle, err := buildKeySourceWith(env.dbPath, resolvePasswordPrompt())
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "passwords.db")
	if _, err := database.NewMasterPasswordSource(other, func(string) ([]byte, error) { return []byte("second-password-1234"), nil }).GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, env.dbPath); err != nil {
		t.Fatal(err)
	}
	store, err := openStoreWith(env.dbPath, oracle)
	if err == nil {
		closeAuditStore(store)
	}
	if wantSub := "changed while"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("err = %v, want it to contain %q", err, wantSub)
	}
}

// otherVaultsTouchID writes a Touch ID file in dir for another vault, and
// returns what it holds.
func otherVaultsTouchID(t *testing.T, dir string) []byte {
	t.Helper()
	k, err := recovery.New()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tw, err := touchid.Wrap(pub, bytes.Repeat([]byte{7}, 32), []byte("another-vault"))
	if err != nil {
		t.Fatal(err)
	}
	if err := touchid.NewFile("another-vault", []byte("key blob"), pub, tw).Write(dir); err != nil {
		t.Fatal(err)
	}
	held, err := os.ReadFile(filepath.Join(dir, touchid.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// A password change leaves alone another vault's Touch ID file in the same
// folder.
func TestRotate_LeavesAnotherVaultsFiles(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	held := otherVaultsTouchID(t, env.dataDir)

	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	if got, err := os.ReadFile(filepath.Join(env.dataDir, touchid.FileName)); err != nil || !bytes.Equal(got, held) {
		t.Errorf("touchid.key changed (err %v)", err)
	}
	if out := stderr.String(); strings.Contains(out, "Touch ID") {
		t.Errorf("stderr talks about another vault's Touch ID:\n%s", out)
	}
}

// A new vault in a folder whose Touch ID file belongs to another vault
// isn't offered Touch ID at its first run, which would take it from the
// other vault; it's still offered a recovery key of its own.
func TestFirstRun_LeavesAnotherVaultsFiles(t *testing.T) {
	startTestAgent(t)
	softwareTouchID(t)
	_, last := fixedRecoveryKey(t)
	dir := t.TempDir()
	held := otherVaultsTouchID(t, dir)
	cfg := withLines(withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), true), last)
	restore := testutil.RedirectStderr(t)
	oracle, err := buildKeySourceWith(filepath.Join(dir, "work.db"), cfg)
	out := restore()
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	closeKeySource(t, oracle)
	if got, err := os.ReadFile(filepath.Join(dir, touchid.FileName)); err != nil || !bytes.Equal(got, held) {
		t.Errorf("touchid.key changed (err %v)", err)
	}
	for _, want := range []string{"Touch ID unlock isn't offered for this vault: touchid.key in this folder is another vault's", "The recovery key is set for this vault."} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
}

// sesh touchid enable asks before taking touchid.key from another vault in
// the folder, and disable leaves that vault's file alone.
func TestRunTouchID_AnotherVaultsFile(t *testing.T) {
	startTestAgent(t)
	softwareTouchID(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "work.db")
	oracle, err := buildKeySourceWith(dbPath, withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), false))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	held := otherVaultsTouchID(t, dir)
	useConfigFile(t, "db_path = \""+dbPath+"\"\n")
	unchanged := func(when string) {
		t.Helper()
		if got, err := os.ReadFile(filepath.Join(dir, touchid.FileName)); err != nil || !bytes.Equal(got, held) {
			t.Errorf("%s: touchid.key changed (err %v)", when, err)
		}
	}

	app := agentTestApp()
	if err := runTouchID(app, []string{"disable"}); err != nil {
		t.Fatal(err)
	}
	unchanged("disable")
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "touchid.key in this folder is another vault's") {
		t.Errorf("disable said %q", out)
	}

	answer := "n"
	orig := terminalPasswordPrompt
	terminalPasswordPrompt = func() passwordPromptConfig {
		return withLines(interactivePrompt(t, "first-password-1234"), answer)
	}
	t.Cleanup(func() { terminalPasswordPrompt = orig })
	if err := runTouchID(agentTestApp(), []string{"enable"}); err != nil {
		t.Fatal(err)
	}
	unchanged("enable, declined")

	answer = "y"
	if err := runTouchID(agentTestApp(), []string{"enable"}); err != nil {
		t.Fatal(err)
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := touchid.ReadFile(dir); err != nil || f.UnlockID != database.UnlockID(mat.Verify) {
		t.Errorf("enable, accepted: touchid.key = %+v, %v; want it for this vault", f, err)
	}
}
