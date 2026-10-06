package main

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/touchid"
)

// verifyVault is a vault with two entries, opened with SESH_MASTER_PASSWORD.
func verifyVault(t *testing.T) *rekeyTestEnv {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "verify-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2", "api_key/openai": "sk-test"})
	return env
}

func runVerifyOut(t *testing.T) (string, error) {
	t.Helper()
	app := agentTestApp()
	err := runVerify(app, nil)
	return app.Stdout.(*bytes.Buffer).String(), err
}

// sqlExec runs q on the vault file directly, as damage would.
func sqlExec(t *testing.T, dbPath, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func auditEvents(t *testing.T, dbPath string) map[string]int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	rows, err := db.Query(`SELECT event_type FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck // test cleanup
	n := map[string]int{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatal(err)
		}
		n[e]++
	}
	return n
}

// A sound vault passes, and the check leaves one audit event, not one read
// per entry.
func TestVerify_ASoundVault(t *testing.T) {
	env := verifyVault(t)
	before := auditEvents(t, env.dbPath)
	out, err := runVerifyOut(t)
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	for _, want := range []string{"  File: ok\n", "  Entries: 2 entries, all readable\n", "  Recovery key: none\n", "  Touch ID: off\n", "Vault OK.\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	after := auditEvents(t, env.dbPath)
	if after["verify"] != 1 || after["access"] != before["access"] {
		t.Errorf("audit events before %v, after %v; want one verify event and no reads", before, after)
	}
}

// Every entry that can't be read is named, and the check fails.
func TestVerify_UnreadableEntries(t *testing.T) {
	env := verifyVault(t)
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'github'`)
	sqlExec(t, env.dbPath, `UPDATE entries SET settings = '{' WHERE service = 'openai'`)
	out, err := runVerifyOut(t)
	if err == nil || !strings.Contains(err.Error(), "the vault has 2 problems") {
		t.Fatalf("err = %v, want 2 problems", err)
	}
	for _, want := range []string{"  Entries: 2 of 2 entries can't be read:\n", "    password/github/alice: its secret doesn't decrypt", "    api_key/openai: read the settings of api_key/openai"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "sk-test") {
		t.Error("the output shows a secret")
	}
}

// A recovery key record made for another key fails the check; Touch ID set
// up for another only warns.
func TestVerify_RecoveryAndTouchID(t *testing.T) {
	env := verifyVault(t)
	k, err := recovery.New()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	w := keywrap.Wrapped{EphemeralPub: []byte("e"), Ciphertext: []byte("c")}
	sqlExec(t, env.dbPath, `INSERT INTO recovery (id, unlock_id, public_key, ephemeral_pub, ciphertext, created_at) VALUES (1, 'another-key', ?, ?, ?, CURRENT_TIMESTAMP)`, pub, w.EphemeralPub, w.Ciphertext)
	tw, err := touchid.Wrap(pub, bytes.Repeat([]byte{7}, 32), []byte("another-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := touchid.NewFile("another-key", []byte("blob"), pub, tw).Write(env.dataDir); err != nil {
		t.Fatal(err)
	}
	out, err := runVerifyOut(t)
	if err == nil || !strings.Contains(err.Error(), "the vault has 1 problem") {
		t.Fatalf("err = %v, want 1 problem (the recovery key)", err)
	}
	for _, want := range []string{"  Recovery key: its record is for another vault or key", "  Touch ID: warning: it was set up for another vault or an earlier master password"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// A good recovery key record passes.
	sqlExec(t, env.dbPath, `DELETE FROM recovery`)
	mat, err := database.ReadUnlockMaterial(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.WriteRecovery(env.dbPath, recovery.NewRecord(database.UnlockID(mat.Verify), pub, w)); err != nil {
		t.Fatal(err)
	}
	if out, err := runVerifyOut(t); err != nil || !strings.Contains(out, "  Recovery key: set, and made for this vault's key\n") {
		t.Errorf("with a good recovery key: %v\n%s", err, out)
	}
}

func TestVerify_Refusals(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	if _, err := runVerifyOut(t); err == nil || !strings.Contains(err.Error(), "there's no vault yet") {
		t.Errorf("no vault: err = %v", err)
	}
	if err := runVerify(agentTestApp(), []string{"extra"}); err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Errorf("extra argument: err = %v", err)
	}
}
