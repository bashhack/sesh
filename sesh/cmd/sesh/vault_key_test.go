package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
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
