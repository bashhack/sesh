package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
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

// A vault whose key was kept in the macOS Keychain has no passwords.key,
// and is refused by name rather than given a new one.
func TestOpenSQLiteStore_RefusesAKeychainVault(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})
	recordKeychainSource(t, env.dbPath)
	if err := os.Remove(env.sidecarPath); err != nil {
		t.Fatal(err)
	}

	wantOpenRefused(t, "this vault's key was kept in the macOS Keychain, which sesh no longer supports", "start a new vault")
	if _, err := os.Stat(env.sidecarPath); !os.IsNotExist(err) {
		t.Errorf("a new passwords.key was created next to the vault (stat: %v)", err)
	}
}

func TestOpenSQLiteStore_RefusesNewKeyNextToExistingVault(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})
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
	t.Setenv("SESH_MASTER_PASSWORD", "first-password-1234")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}, []byte("hunter2")); err != nil {
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

	wantOpenRefused(t, "the master password key in use is not the one this vault was created with", "If passwords.key was replaced")
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

// Commands that check for passwords.key before opening the vault say what's
// wrong with an existing vault that has none, rather than that there's no vault.
func TestKeyFileCommands_NameAVaultWithoutItsKeyFile(t *testing.T) {
	commands := map[string]func(app *App) error{
		"recovery new":   func(app *App) error { return runRecovery(app, []string{"new"}) },
		"touchid enable": func(app *App) error { return runTouchID(app, []string{"enable"}) },
		"recover":        func(app *App) error { return runRecover(app, nil) },
		"--rekey":        func(app *App) error { return runRekey(app, nil, rotateTestCfg("pw-1234-5678")) },
	}
	for name, run := range commands {
		for vault, wantSub := range map[string]string{
			"lost passwords.key": "its key file",
			"keychain vault":     "kept in the macOS Keychain, which sesh no longer supports",
		} {
			t.Run(name+", "+vault, func(t *testing.T) {
				env := setupRekeyEnv(t)
				t.Setenv("SESH_MASTER_PASSWORD", "pw-1234-5678")
				populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2"})
				t.Setenv("SESH_MASTER_PASSWORD", "")
				if vault == "keychain vault" {
					recordKeychainSource(t, env.dbPath)
				}
				if err := os.Remove(env.sidecarPath); err != nil {
					t.Fatal(err)
				}
				origAvail := touchIDAvailable
				touchIDAvailable = func() bool { return true }
				t.Cleanup(func() { touchIDAvailable = origAvail })
				app, _ := rekeyTestApp("y\n")
				if err := run(app); err == nil || !strings.Contains(err.Error(), wantSub) {
					t.Errorf("err = %v, want it to contain %q", err, wantSub)
				}
			})
		}
	}
}

// recordKeychainSource makes the vault at dbPath record the Keychain key
// source, as a development build's Keychain-key vault did.
func recordKeychainSource(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO vault_key (id, key_source, check_data, check_salt, created_at) VALUES (1, 'keychain', x'00', x'00', '2026-01-01')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
