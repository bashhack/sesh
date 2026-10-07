package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/touchid"
)

// doctorVault is a vault with two entries, opened with SESH_MASTER_PASSWORD.
func doctorVault(t *testing.T) *rekeyTestEnv {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "verify-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/github/alice": "hunter2", "api_key/openai": "sk-test"})
	return env
}

func runDoctorOut(t *testing.T) (string, error) {
	t.Helper()
	app := agentTestApp()
	err := runDoctor(app, nil)
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

// A sound vault passes, warning only that there's no recovery key, and the
// check leaves one audit event, not one read per entry.
func TestDoctor_ASoundVault(t *testing.T) {
	env := doctorVault(t)
	before := auditEvents(t, env.dbPath)
	out, err := runDoctorOut(t)
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	want := "sesh doctor\n\n" +
		"Setup\n" +
		"  -     Config          no file, so the defaults\n" +
		"  ok    Vault file      only you can read it\n" +
		"  -     Agent           not running; it starts when a command needs it\n" +
		"  ok    Key settings    19 MiB, 2 passes, 1 thread\n" +
		"\nVault: " + tildePath(env.dbPath) + "\n" +
		"  ok    File            ok\n" +
		"  ok    Entries         2 entries, all readable\n" +
		"  warn  Recovery key    none: if you forget the master password, the vault can't be opened\n" +
		"  -     Touch ID        off\n" +
		"  -     AWS CLI         no AWS entries\n" +
		"\nWhat to do\n" +
		"  1. Make a recovery key, in case you forget the master password:\n" +
		"       sesh recovery new\n" +
		"\nOK, with 1 warning\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	after := auditEvents(t, env.dbPath)
	if after["doctor"] != 1 || after["access"] != before["access"] {
		t.Errorf("audit events before %v, after %v; want one doctor event and no reads", before, after)
	}
}

// Every entry that can't be read is named, and the check fails.
func TestDoctor_UnreadableEntries(t *testing.T) {
	env := doctorVault(t)
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899', service = 'git hub' WHERE service = 'github'`)
	sqlExec(t, env.dbPath, `UPDATE entries SET settings = '{' WHERE service = 'openai'`)
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want the failure reported", err)
	}
	for _, want := range []string{
		"  FAIL  Entries         2 of 2 entries can't be read\n" +
			"                        api_key/openai: settings don't read\n" +
			"                        password/git hub/alice: secret doesn't decrypt\n" +
			"                        (damaged, or encrypted with another key)\n",
		"  1. Restore these entries from a backup (an encrypted export), or delete them:\n" +
			"       sesh --service password --delete api_key/openai 'password/git hub/alice'\n",
		"\nFAIL: 2 problems, 1 warning\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "sk-test") {
		t.Error("the output shows a secret")
	}
}

// openDoctorVault opens the doctorVault's store, as a command would.
func openDoctorVault(t *testing.T, env *rekeyTestEnv) *database.Store {
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

// The delete doctor prints works for every kind of damage.
func TestDoctor_PrintedDeleteWorks(t *testing.T) {
	env := damageThree(t)
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "       sesh --service password --delete password/a/u password/b/u password/c/u\n") {
		t.Fatalf("err = %v, output:\n%s", err, out)
	}
	store := openDoctorVault(t, env)
	if _, err := provider.DeleteEntries(store, []string{"password/a/u", "password/b/u", "password/c/u"}, nil, nil, true, nil); err != nil {
		t.Fatalf("the printed delete: %v", err)
	}
	if out, err := runDoctorOut(t); err != nil {
		t.Errorf("doctor after the delete: %v\n%s", err, out)
	}
}

// An entry whose name is damaged into another entry's ID isn't offered for
// deletion by that ID, which would delete the other entry.
func TestDoctor_DamagedNameIsNotOfferedForDelete(t *testing.T) {
	env := doctorVault(t)
	sqlExec(t, env.dbPath, `INSERT INTO entries (kind, service, username, encrypted_data, salt, created_at, updated_at) SELECT kind, 'github/alice', '', x'00112233445566778899aabbccddeeff00112233445566778899', salt, created_at, updated_at FROM entries WHERE service = 'github'`)
	out, err := runDoctorOut(t)
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

// Importing a backup over damaged entries, as doctor says, repairs them.
func TestDoctor_RestoreFromABackupWorks(t *testing.T) {
	env := damageThree(t)
	store := openDoctorVault(t, env)
	backup := `[{"service":"a","username":"u","type":"password","secret":"1"},{"service":"b","username":"u","type":"password","secret":"2"},{"service":"c","username":"u","type":"password","secret":"3"}]`
	res, err := password.NewManager(store).Import(strings.NewReader(backup), password.ImportOptions{Format: password.FormatJSON, OnConflict: password.ConflictOverwrite})
	if err != nil || len(res.Errors) != 0 || res.Imported != 3 {
		t.Fatalf("import = %+v, %v", res, err)
	}
	if out, err := runDoctorOut(t); err != nil {
		t.Errorf("doctor after the restore: %v\n%s", err, out)
	}
}

// A recovery key record made for another key fails the check; Touch ID set
// up for another only warns.
func TestDoctor_RecoveryAndTouchID(t *testing.T) {
	env := doctorVault(t)
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
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want the failure reported", err)
	}
	for _, want := range []string{
		"  FAIL  Recovery key    made for another vault or key\n",
		"  warn  Touch ID        set up for another vault or an earlier master password\n",
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
	if out, err := runDoctorOut(t); err == nil || !strings.Contains(out, "  FAIL  Recovery key    its record is damaged\n") {
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
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  ok    Recovery key    set, for this vault's key\n") || !strings.HasSuffix(out, "\nOK, with 1 warning\n") {
		t.Errorf("with a good recovery key: %v\n%s", err, out)
	}
}

// A file SQLite finds damaged fails, isn't written to, and, since the
// entries still read, says to export them now.
func TestDoctor_DamagedFile(t *testing.T) {
	env := doctorVault(t)
	before := auditEvents(t, env.dbPath)
	// The audit log's time index, redefined over another column, no
	// longer matches its table.
	sqlExec(t, env.dbPath, `PRAGMA writable_schema = ON; UPDATE sqlite_master SET sql = 'CREATE INDEX idx_audit_log_created_at ON audit_log(event_type)' WHERE name = 'idx_audit_log_created_at'; PRAGMA writable_schema = OFF`)
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want the failure reported\n%s", err, out)
	}
	for _, want := range []string{
		"  FAIL  File            damaged; SQLite reports:\n                        ",
		"  ok    Entries         2 entries, all readable\n",
		"  1. Your entries all read, so save them now, then start a new vault and import them:\n" +
			"       sesh --service password --action export --format encrypted --file backup.enc\n",
		"\nFAIL: 1 problem, 1 warning\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if after := auditEvents(t, env.dbPath); after["doctor"] != 0 || len(after) != len(before) {
		t.Errorf("audit events before %v, after %v; want nothing written", before, after)
	}
	// With an entry unreadable too, the whole vault is restored instead.
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'github'`)
	out, err = runDoctorOut(t)
	if !errors.Is(err, errReported) || strings.Contains(out, "--delete") || !strings.Contains(out, "  1. Restore the vault from a backup, such as an encrypted export.\n") || !strings.HasSuffix(out, "\nFAIL: 2 problems, 1 warning\n") {
		t.Errorf("err = %v, output:\n%s", err, out)
	}
}

// One unreadable entry is named in the step, with the command for it.
func TestDoctor_OneUnreadableEntry(t *testing.T) {
	env := doctorVault(t)
	sqlExec(t, env.dbPath, `UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'github'`)
	out, err := runDoctorOut(t)
	want := "  1. Restore password/github/alice from a backup (an encrypted export), or delete it:\n" +
		"       sesh --service password --delete password/github/alice\n"
	if !errors.Is(err, errReported) || !strings.Contains(out, want) {
		t.Errorf("err = %v, output:\n%s", err, out)
	}
}

func TestDoctor_Refusals(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "  FAIL  Vault file      no vault at "+tildePath(env.dbPath)+"\n") ||
		!strings.Contains(out, "  -     Vault           not checked: there's no vault\n") || !strings.Contains(out, "       sesh init\n") {
		t.Errorf("no vault: err = %v\n%s", err, out)
	}
	if err := runDoctor(agentTestApp(), []string{"extra"}); err == nil || !strings.Contains(err.Error(), "takes no arguments") {
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

// A config that doesn't load fails, and the vault isn't checked.
func TestDoctor_ConfigDoesntLoad(t *testing.T) {
	doctorVault(t)
	useConfigFile(t, "bogus = 1\n")
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "  FAIL  Config          doesn't load\n") || !strings.Contains(out, "  -     Vault           not checked: the config doesn't load\n") ||
		!strings.HasSuffix(out, "\nFAIL: 1 problem; the vault wasn't checked\n") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

// A vault others can read warns, with the chmod to run.
func TestDoctor_LoosePermissions(t *testing.T) {
	env := doctorVault(t)
	if err := os.Chmod(env.dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctorOut(t)
	if err != nil || !strings.Contains(out, "  warn  Vault file      others can read it or its folder\n") || !strings.Contains(out, "       chmod 600 "+shell.Quote(env.dbPath)+"\n") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

// A key made with weaker settings than configured warns, naming --rekey.
func TestDoctor_WeakerKeySettings(t *testing.T) {
	doctorVault(t)
	t.Setenv("SESH_KDF_MEMORY", "32MiB")
	out, err := runDoctorOut(t)
	if err != nil || !strings.Contains(out, "  warn  Key settings    19 MiB, 2 passes, 1 thread: weaker than configured\n                        configured: 32 MiB, 2 passes, 1 thread\n") || !strings.Contains(out, "       sesh --rekey\n") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

// Without a terminal, a password in the environment, or an unlocked agent,
// the setup is still checked and the vault part is skipped, without asking.
func TestDoctor_SkipsTheVaultWhenItCantAsk(t *testing.T) {
	doctorVault(t)
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app := agentTestApp()
	app.StdinIsTerminal = func() bool { return false }
	err := runDoctor(app, nil)
	out := app.Stdout.(*bytes.Buffer).String()
	if err != nil || !strings.Contains(out, "Setup\n") || !strings.Contains(out, "  -     Vault           not checked: unlocking it needs a terminal to ask at, SESH_MASTER_PASSWORD, or an unlocked agent\n") ||
		!strings.HasSuffix(out, "\nOK: no problems; the vault wasn't checked\n") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

// AWS entries need the AWS CLI.
func TestDoctor_AWSCLI(t *testing.T) {
	env := doctorVault(t)
	populatePasswordStore(t, env, map[string]string{"totp/aws/default": "JBSWY3DPEHPK3PXP"})
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  warn  AWS CLI         not found, so the AWS entries can't be used\n") || !strings.Contains(out, "Install the AWS CLI") {
		t.Errorf("no aws: err = %v\n%s", err, out)
	}
	lookPath = func(string) (string, error) { return "/usr/local/bin/aws", nil }
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "  ok    AWS CLI         /usr/local/bin/aws\n") {
		t.Errorf("aws found: err = %v\n%s", err, out)
	}
}
