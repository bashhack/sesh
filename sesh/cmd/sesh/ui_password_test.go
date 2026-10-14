package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// The app's master password change re-encrypts the vault as sesh --rekey does, opens it again with the new one,
// and offers the backups made before; a wrong current password changes nothing.
func TestUI_ChangePassword(t *testing.T) {
	healthVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runBackupOut(t); err != nil {
		t.Fatal(err)
	}
	if _, err := uiChangePassword(cfg, []byte("not-the-password"), []byte("new-password-5678")); !errors.Is(err, tui.ErrWrongPassword) {
		t.Fatalf("a wrong current password: %v", err)
	}
	if _, err := u.Check(); err != nil {
		t.Fatalf("the vault after a wrong password: %v", err)
	}
	ch, err := uiChangePassword(cfg, []byte("health-password-1234"), []byte("new-password-5678"))
	if err != nil {
		t.Fatal(err)
	}
	said := strings.Join(ch.Said, " ")
	for _, want := range []string{"Changed the master password, and re-encrypted 4 entries.", "SESH_MASTER_PASSWORD still holds the old password"} {
		if !strings.Contains(said, want) {
			t.Errorf("missing %q in %q", want, said)
		}
	}
	if !strings.HasPrefix(ch.OldBackups, "1 backup made before this change still opens with the old master password, in ") {
		t.Errorf("old backups: %q", ch.OldBackups)
	}
	if ch.Vault == nil {
		t.Fatal("not opened again")
	}
	defer ch.Vault.Close() //nolint:errcheck // test cleanup
	if rows, _, err := ch.Vault.Search(""); err != nil || len(rows) != 4 {
		t.Errorf("the vault opened again: %d entries, %v", len(rows), err)
	}
	if _, err := u.Check(); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("the vault open before: %v", err)
	}
	if _, err := reopenWith(cfg, []byte("health-password-1234")); !errors.Is(err, tui.ErrWrongPassword) {
		t.Errorf("the old password: %v", err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-5678")
	if log := mustRun(t, runAudit); !strings.Contains(log, "master password changed, 4 entries re-encrypted") {
		t.Errorf("audit:\n%s", log)
	}
	said, err = uiRenewBackups(cfg.DBPath.Value)
	if err != nil || !strings.HasPrefix(said, "Deleted 1 backup; made a fresh one: ") {
		t.Errorf("renewing the backups: %q, %v", said, err)
	}
}

// Through the agent, as the app usually is: the recovery key goes on working, and the agent holds the new key.
func TestUI_ChangePasswordAgent(t *testing.T) {
	env, k := recoverableVault(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := reopenWith(cfg, []byte("forgotten-pw-1234"))
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	ch, err := uiChangePassword(cfg, []byte("forgotten-pw-1234"), []byte("new-password-5678"))
	if err != nil {
		t.Fatal(err)
	}
	if said := strings.Join(ch.Said, " "); !strings.Contains(said, "Your recovery key still works") || strings.Contains(said, "agent") {
		t.Errorf("said %q", said)
	}
	opensVault(t, k, env.dbPath)
	if ch.Vault == nil {
		t.Fatal("not opened again")
	}
	defer ch.Vault.Close() //nolint:errcheck // test cleanup
	if v, err := ch.Vault.Secret(vault.Key{Kind: vault.KindPassword, Service: "x", Username: "y"}, "test"); err != nil || string(v) != "the secret" {
		t.Errorf("a secret through the agent after: %q, %v", v, err)
	}
	if _, err := u.Check(); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("the vault open before: %v", err)
	}
}
