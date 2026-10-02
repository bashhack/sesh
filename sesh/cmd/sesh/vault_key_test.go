package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wantOpenRefused fails unless openSQLiteStore refuses with every one of subs.
func wantOpenRefused(t *testing.T, subs ...string) {
	t.Helper()
	store, err := openSQLiteStore()
	if err == nil {
		if cerr := store.Close(); cerr != nil {
			t.Error(cerr)
		}
		t.Fatal("openSQLiteStore succeeded, want a refusal")
	}
	for _, sub := range subs {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("err = %q, want it to contain %q", err, sub)
		}
	}
}

func TestOpenSQLiteStore_RefusesStaleKeySourceAfterRekey(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/github/alice": "hunter2"})
	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=keychain"}, newKCMock(nil)); err != nil {
		t.Fatalf("rekey: %v\n%s", err, stderr)
	}

	// SESH_KEY_SOURCE still says password, and the old passwords.key is
	// still there. Before the check, this unlocked and wrote entries under
	// the old key.
	wantOpenRefused(t, "this vault uses the keychain key source, but sesh is using password", "SESH_KEY_SOURCE=keychain")
}

func TestOpenSQLiteStore_RefusesNewKeyNextToExistingVault(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/github/alice": "hunter2"})
	if err := os.Remove(env.sidecarPath); err != nil {
		t.Fatal(err)
	}

	wantOpenRefused(t, "its key file", "is missing", "restore it from a backup")
	if _, err := os.Stat(env.sidecarPath); !os.IsNotExist(err) {
		t.Errorf("a new passwords.key was created next to the existing vault (stat: %v)", err)
	}
}

func TestOpenSQLiteStore_RefusesReplacedPasswordsKey(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "first-password-1234")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSecret(env.account, "sesh-password/password/github/alice", []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// A passwords.key for a different password, copied over the vault's.
	other := t.TempDir()
	t.Setenv("SESH_MASTER_PASSWORD", "second-password-1234")
	key, err := resolvePasswordPrompt().newSource(other).GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	body, err := os.ReadFile(filepath.Join(other, sidecarFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.sidecarPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	wantOpenRefused(t, "the password key in use is not the one this vault was created with", "If passwords.key was replaced")
}

func TestRefuseNewKeyForExistingVault_UnreadableDirFailsClosed(t *testing.T) {
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
	err := refuseNewKeyForExistingVault(filepath.Join(dir, "passwords.db"))
	if err == nil || !strings.Contains(err.Error(), "check for") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want a refusal carrying the permission error: an unreadable vault dir isn't a first run", err)
	}
}
