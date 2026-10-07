package main

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
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
	rows, err := db.Query(`SELECT event_type FROM audit_log NOT INDEXED`)
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
	want := "\n\n" +
		"  ok    File          ok\n" +
		"  ok    Entries       2 entries, all readable\n" +
		"  -     Recovery key  none\n" +
		"  -     Touch ID      off\n" +
		"\nOK: no problems\n"
	if !strings.HasSuffix(out, want) || strings.Contains(out, "What to do") {
		t.Errorf("output:\n%s\nwant it to end:\n%s", out, want)
	}
	for _, want := range []string{"sesh verify: "} {
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
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899', service = 'git hub' WHERE service = 'github'`)
	sqlExec(t, env.dbPath, `UPDATE entries SET settings = '{' WHERE service = 'openai'`)
	out, err := runVerifyOut(t)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want the failure reported", err)
	}
	for _, want := range []string{
		"  FAIL  Entries       2 of 2 entries can't be read\n" +
			"                        api_key/openai: settings don't read\n" +
			"                        password/git hub/alice: secret doesn't decrypt\n" +
			"                        (damaged, or encrypted with another key)\n",
		"  1. Restore these entries from a backup (an encrypted export), or delete them:\n" +
			"       sesh --service password --delete api_key/openai 'password/git hub/alice'\n",
		"\nFAIL: 2 problems\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "sk-test") {
		t.Error("the output shows a secret")
	}
}

// openVerifyVault opens the verifyVault's store, as a command would.
func openVerifyVault(t *testing.T, env *rekeyTestEnv) *database.Store {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(env.dbPath, database.NewKeySourceOracle(resolvePasswordPrompt().withKDF(cfg.KDF()).newSource(env.dbPath)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() }) //nolint:errcheck // test cleanup
	return store
}

// damageThree damages a secret, settings, and times, one entry each.
func damageThree(t *testing.T) *rekeyTestEnv {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "verify-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/a/u": "1", "password/b/u": "2", "password/c/u": "3"})
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'a'`)
	sqlExec(t, env.dbPath, `UPDATE entries SET settings = '{' WHERE service = 'b'`)
	sqlExec(t, env.dbPath, `UPDATE entries SET created_at = 'garbage' WHERE service = 'c'`)
	return env
}

// The delete verify prints works for every kind of damage.
func TestVerify_PrintedDeleteWorks(t *testing.T) {
	env := damageThree(t)
	out, err := runVerifyOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "       sesh --service password --delete password/a/u password/b/u password/c/u\n") {
		t.Fatalf("err = %v, output:\n%s", err, out)
	}
	store := openVerifyVault(t, env)
	if _, err := provider.DeleteEntries(store, []string{"password/a/u", "password/b/u", "password/c/u"}, nil, nil, true, nil); err != nil {
		t.Fatalf("the printed delete: %v", err)
	}
	if out, err := runVerifyOut(t); err != nil {
		t.Errorf("verify after the delete: %v\n%s", err, out)
	}
}

// An entry whose name is damaged into another entry's ID isn't offered for
// deletion by that ID, which would delete the other entry.
func TestVerify_DamagedNameIsNotOfferedForDelete(t *testing.T) {
	env := verifyVault(t)
	sqlExec(t, env.dbPath, `INSERT INTO entries (kind, service, username, encrypted_data, salt, created_at, updated_at) SELECT kind, 'github/alice', '', x'00112233445566778899aabbccddeeff00112233445566778899', salt, created_at, updated_at FROM entries WHERE service = 'github'`)
	out, err := runVerifyOut(t)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if strings.Contains(out, "--delete") || !strings.Contains(out, `password entry with a damaged name (service "github/alice", no username): secret doesn't decrypt`) {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "  1. Restore the vault from a backup, such as an encrypted export: an entry's name is damaged, so sesh can't name it to delete it.\n") {
		t.Errorf("output:\n%s", out)
	}
}

// Importing a backup over damaged entries, as verify says, repairs them.
func TestVerify_RestoreFromABackupWorks(t *testing.T) {
	env := damageThree(t)
	store := openVerifyVault(t, env)
	backup := `[{"service":"a","username":"u","type":"password","secret":"1"},{"service":"b","username":"u","type":"password","secret":"2"},{"service":"c","username":"u","type":"password","secret":"3"}]`
	res, err := password.NewManager(store).Import(strings.NewReader(backup), password.ImportOptions{Format: password.FormatJSON, OnConflict: password.ConflictOverwrite})
	if err != nil || len(res.Errors) != 0 || res.Imported != 3 {
		t.Fatalf("import = %+v, %v", res, err)
	}
	if out, err := runVerifyOut(t); err != nil {
		t.Errorf("verify after the restore: %v\n%s", err, out)
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
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want the failure reported", err)
	}
	for _, want := range []string{
		"  FAIL  Recovery key  made for another vault or key\n",
		"  warn  Touch ID      set up for another vault or an earlier master password\n",
		"  1. Make a new recovery key:\n       sesh recovery new\n",
		"  2. Optional: turn Touch ID back on:\n       sesh touchid enable\n",
		"\nFAIL: 1 problem, 1 warning\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// A record for this vault's key, but not shaped like a wrapped key,
	// fails; a real one passes.
	sqlExec(t, env.dbPath, `DELETE FROM recovery`)
	mat, err := database.ReadUnlockMaterial(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	id := database.UnlockID(mat.Verify)
	if err := database.WriteRecovery(env.dbPath, recovery.NewRecord(id, pub, w)); err != nil {
		t.Fatal(err)
	}
	if out, err := runVerifyOut(t); err == nil || !strings.Contains(out, "  FAIL  Recovery key  its record is damaged\n") {
		t.Errorf("with a damaged recovery key record: %v\n%s", err, out)
	}
	good, err := recovery.Wrap(pub, bytes.Repeat([]byte{9}, 32), []byte(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.WriteRecovery(env.dbPath, recovery.NewRecord(id, pub, good)); err != nil {
		t.Fatal(err)
	}
	// Touch ID's warning alone doesn't fail the check.
	if out, err := runVerifyOut(t); err != nil || !strings.Contains(out, "  ok    Recovery key  set, for this vault's key\n") || !strings.HasSuffix(out, "\nOK, with 1 warning\n") {
		t.Errorf("with a good recovery key: %v\n%s", err, out)
	}
}

// A file SQLite finds damaged fails, isn't written to, and, since the
// entries still read, says to export them now.
func TestVerify_DamagedFile(t *testing.T) {
	env := verifyVault(t)
	before := auditEvents(t, env.dbPath)
	// The audit log's time index, redefined over another column, no
	// longer matches its table.
	sqlExec(t, env.dbPath, `PRAGMA writable_schema = ON; UPDATE sqlite_master SET sql = 'CREATE INDEX idx_audit_log_created_at ON audit_log(event_type)' WHERE name = 'idx_audit_log_created_at'; PRAGMA writable_schema = OFF`)
	out, err := runVerifyOut(t)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want the failure reported\n%s", err, out)
	}
	for _, want := range []string{
		"  FAIL  File          damaged; SQLite reports:\n                        ",
		"  ok    Entries       2 entries, all readable\n",
		"  1. Your entries all read, so save them now, then start a new vault and import them:\n" +
			"       sesh --service password --action export --format encrypted --file backup.enc\n",
		"\nFAIL: 1 problem\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if after := auditEvents(t, env.dbPath); after["verify"] != 0 || len(after) != len(before) {
		t.Errorf("audit events before %v, after %v; want nothing written", before, after)
	}
	// With an entry unreadable too, the whole vault is restored instead.
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'github'`)
	out, err = runVerifyOut(t)
	if !errors.Is(err, errReported) || strings.Contains(out, "--delete") || !strings.Contains(out, "  1. Restore the vault from a backup, such as an encrypted export.\n\nFAIL: 2 problems\n") {
		t.Errorf("err = %v, output:\n%s", err, out)
	}
}

// One unreadable entry is named in the step, with the command for it.
func TestVerify_OneUnreadableEntry(t *testing.T) {
	env := verifyVault(t)
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'github'`)
	out, err := runVerifyOut(t)
	want := "  1. Restore password/github/alice from a backup (an encrypted export), or delete it:\n" +
		"       sesh --service password --delete password/github/alice\n"
	if !errors.Is(err, errReported) || !strings.Contains(out, want) {
		t.Errorf("err = %v, output:\n%s", err, out)
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

// A failure the command has already reported exits 1 without a second line.
func TestFatal_AlreadyReported(t *testing.T) {
	app := agentTestApp()
	code := 0
	app.Exit = func(c int) { code = c }
	fatal(app, errReported)
	if got := app.Stderr.(*bytes.Buffer).String(); got != "" || code != 1 {
		t.Errorf("stderr %q, exit %d; want nothing and 1", got, code)
	}
}
