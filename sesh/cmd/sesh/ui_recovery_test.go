package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/tui"
)

// The app makes a recovery key through the agent, as sesh recovery new does, saving it once confirmed, and removes
// one; replacing or removing one offers the backups made before.
func TestUI_Recovery(t *testing.T) {
	env, _ := recoverableVault(t)
	t.Setenv("SESH_MASTER_PASSWORD", "forgotten-pw-1234")
	if _, err := runBackupOut(t); err != nil {
		t.Fatal(err)
	}
	if _, err := uiNewRecovery(dbCfg(env.dbPath)); err == nil || !strings.Contains(err.Error(), "SESH_MASTER_PASSWORD") {
		t.Errorf("with SESH_MASTER_PASSWORD set: %v", err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	if _, err := uiNewRecovery(dbCfg(env.dbPath)); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("the agent locked: %v", err)
	}
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAgentConn(conn)
	mat, err := database.ReadUnlockMaterial(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Unlock(conn, []byte("forgotten-pw-1234"), mat.Salt, mat.Verify, mat.Params); err != nil {
		t.Fatal(err)
	}
	if r, err := uiRecovery(dbCfg(env.dbPath)); err != nil || !r.Set || !strings.HasPrefix(r.Said, "set, made ") {
		t.Fatalf("before: %+v, %v", r, err)
	}

	k, last := fixedRecoveryKey(t)
	nr, err := uiNewRecovery(dbCfg(env.dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if nr.Key != k.String() || !nr.Matches(" "+strings.ToLower(last)+" ") || nr.Matches("0000") {
		t.Errorf("key %q, matching %q", nr.Key, last)
	}
	if before, err := database.ReadRecovery(env.dbPath); err != nil || !nr.Replacing || !nr.Made.Equal(before.CreatedAt) {
		t.Errorf("replacing %v, made %v (the one there: %v)", nr.Replacing, nr.Made, err)
	}
	done, err := nr.Save()
	if err != nil || done.Said != "The recovery key is set for this vault." || !strings.Contains(done.OldBackups, "1 backup made before this change still opens with the old recovery key") || done.Renew != "Delete it and make a fresh backup?" {
		t.Fatalf("saved: %+v, %v", done, err)
	}
	opensVault(t, k, env.dbPath)

	done, err = uiRemoveRecovery(dbCfg(env.dbPath))
	if err != nil || !strings.HasPrefix(done.Said, "Removed the recovery key") || done.OldBackups == "" {
		t.Errorf("removed: %+v, %v", done, err)
	}
	if r, err := uiRecovery(dbCfg(env.dbPath)); err != nil || r.Set || r.Said != "none" {
		t.Errorf("after: %+v, %v", r, err)
	}
	// A first one replaces nothing, so no backups are offered.
	if nr, err = uiNewRecovery(dbCfg(env.dbPath)); err != nil || nr.Replacing {
		t.Fatalf("a first one: %+v, %v", nr, err)
	}
	if done, err := nr.Save(); err != nil || done.OldBackups != "" {
		t.Errorf("a first one: %+v, %v", done, err)
	}
	// One shown while another command changed the master password isn't saved.
	if nr, err = uiNewRecovery(dbCfg(env.dbPath)); err != nil {
		t.Fatal(err)
	}
	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("forgotten-pw-1234", "new-password-5678", "new-password-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	if _, err := nr.Save(); !errors.Is(err, tui.ErrRefused) || !strings.Contains(err.Error(), "it wasn't saved and opens nothing") {
		t.Errorf("saved after the password changed: %v", err)
	}
}

// A record for another vault, or one that can't be read, is said in the row, which offers replacing or removing it.
func TestUI_RecoveryRows(t *testing.T) {
	healthVault(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	db := cfg.DBPath.Value
	sqlExec(t, db, `INSERT INTO recovery (id, unlock_id, public_key, ephemeral_pub, ciphertext, created_at) VALUES (1, 'another-key', x'01', x'02', x'03', CURRENT_TIMESTAMP)`)
	if r, err := uiRecovery(dbCfg(db)); err != nil || !r.Set || r.Said != "made for another vault: it doesn't open this one" {
		t.Errorf("another vault's: %+v, %v", r, err)
	}
	sqlExec(t, db, `UPDATE recovery SET unlock_id = ''`)
	if r, err := uiRecovery(dbCfg(db)); err != nil || !r.Set || r.Said != "its record can't be read" {
		t.Errorf("unreadable: %+v, %v", r, err)
	}
	// With no agent running, it says so plainly.
	t.Setenv("SESH_MASTER_PASSWORD", "")
	if _, err := uiNewRecovery(dbCfg(db)); err == nil || err.Error() != "a recovery key is made through sesh's agent, which isn't running; run: sesh recovery new" {
		t.Errorf("no agent: %v", err)
	}
}

// dbCfg is settings naming the vault at path, and no sync folder.
func dbCfg(path string) *config.Config {
	return &config.Config{DBPath: config.Setting[string]{Value: path}}
}
