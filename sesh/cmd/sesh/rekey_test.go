package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// The vault is changed in place: it's still the only file.
	names, err := os.ReadDir(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n.Name() != filepath.Base(env.dbPath) {
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

}

// A new password that isn't confirmed changes nothing.
func TestRotate_ConfirmMismatchChangesNothing(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-aaaaaa", "new-pw-bbbbbb"))
	if err == nil || !strings.Contains(err.Error(), "passwords do not match") {
		t.Fatalf("expected passwords-do-not-match error, got %v", err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	if got := readEntriesViaPassword(t, env, []string{"password/x/y"}); got["password/x/y"] != "v" {
		t.Errorf("the old password no longer opens the vault: %v", got)
	}
}

func TestRotate_WrongSourcePassword(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "right-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	beforeSalt := keySalt(t, env.dbPath)

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

// A change whose summary can't be written still committed: it returns the
// new key with the error, and the new password opens the vault.
func TestRotate_CommittedEvenIfReportingFails(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	app.Stderr = &failingAfter{marker: "Rotated"}
	newKey, err := rotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678"), nil)
	if err == nil || newKey == nil {
		t.Fatalf("rotate = %v, %v; want the new key and the write failure", newKey != nil, err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	if got := readEntriesViaPassword(t, env, []string{"password/x/y"}); got["password/x/y"] != "v" {
		t.Errorf("the new password doesn't open the vault: %v", got)
	}
}

// A password change finished by another command while this one waits for
// its new password makes this one refuse, rather than undo the other's.
func TestRotate_AnotherChangeWhileThisOneWaits(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	asked := 0
	cfg := passwordPromptConfig{prompt: func(p string) ([]byte, error) {
		asked++
		if strings.HasPrefix(p, "Create") && asked == 2 {
			app, stderr := rekeyTestApp("y\n")
			if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "other-pw-5678", "other-pw-5678")); err != nil {
				t.Fatalf("the other change: %v\n%s", err, stderr)
			}
		}
		if asked == 1 {
			return []byte("old-pw-1234"), nil
		}
		return []byte("this-pw-5678"), nil
	}}
	app, _ := rekeyTestApp("y\n")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "changed by another sesh command") {
		t.Fatalf("err = %v, want the other change named", err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "other-pw-5678")
	if got := readEntriesViaPassword(t, env, []string{"password/x/y"}); got["password/x/y"] != "v" {
		t.Errorf("the other change's password no longer opens the vault: %v", got)
	}
}

// A command that unlocked the vault before a password change can't save
// into it afterwards under the old key.
func TestRotate_SavesFromAnEarlierUnlockAreRefused(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
	other, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(other)
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	if err := other.Put(vault.Key{Kind: vault.KindPassword, Service: "late"}, []byte("v")); err == nil || !strings.Contains(err.Error(), "changed by another sesh command") {
		t.Errorf("save after the change: err = %v", err)
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

// TestRekeyHolderProcess is the other process in
// TestRotate_WithTheVaultOpenElsewhere: it opens the vault and reads, waits
// for the change, then reads and saves again, and reports what happened.
func TestRekeyHolderProcess(t *testing.T) {
	dir := os.Getenv("SESH_TEST_HOLDER_DIR")
	if dir == "" {
		t.Skip("run by TestRotate_WithTheVaultOpenElsewhere")
	}
	report := func(lines ...string) {
		_ = os.WriteFile(filepath.Join(dir, "result"), []byte(strings.Join(lines, "\n")), 0o600) //nolint:errcheck // the parent fails on a missing report
	}
	store, err := openSQLiteStore()
	if err != nil {
		report("open: " + err.Error())
		return
	}
	defer closeAuditStore(store)
	if _, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "s0"}); err != nil {
		report("read before: " + err.Error())
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600) //nolint:errcheck // the parent times out without it
	if !waitForFile(filepath.Join(dir, "go"), 20*time.Second) {
		report("no go")
		return
	}
	_, getErr := store.Get(vault.Key{Kind: vault.KindPassword, Service: "s0"})
	putErr := store.Put(vault.Key{Kind: vault.KindPassword, Service: "from-holder"}, []byte("v"))
	report(fmt.Sprintf("get: %v", getErr), fmt.Sprintf("put: %v", putErr))
}

func waitForFile(p string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// A password change while another sesh process has the vault open leaves a
// sound vault: every entry opens with the new password, and the other
// process can't save under the old key.
func TestRotate_WithTheVaultOpenElsewhere(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	entries := map[string]string{}
	for i := range 40 {
		entries[fmt.Sprintf("password/s%d", i)] = strings.Repeat("secret", 60)
	}
	populatePasswordStore(t, env, entries)

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	holder := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRekeyHolderProcess$") //nolint:gosec // the test binary itself
	holder.Env = append(os.Environ(), "SESH_TEST_HOLDER_DIR="+dir)
	var out bytes.Buffer
	holder.Stdout, holder.Stderr = &out, &out
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Wait() }() //nolint:errcheck // its report is what's checked
	if !waitForFile(filepath.Join(dir, "ready"), 20*time.Second) {
		r, _ := os.ReadFile(filepath.Join(dir, "result")) //nolint:errcheck // shown if present
		t.Fatalf("the other process never got ready: %s\n%s", r, out.String())
	}

	old := sealedSecrets(t, env.dbPath)
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	// With the other process still open, the vault file itself (what a
	// backup copies) no longer holds the vault under the old key.
	b, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range old {
		if bytes.Contains(b, c) {
			t.Error("the vault file still holds an entry encrypted under the old key")
			break
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(filepath.Join(dir, "result"), 20*time.Second) {
		t.Fatalf("no report from the other process:\n%s", out.String())
	}
	report, err := os.ReadFile(filepath.Join(dir, "result"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"get: decrypt password/s0: the vault's master password was changed", "put: store password/from-holder: the vault's master password was changed"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("the other process reported:\n%s\nwant %q", report, want)
		}
	}

	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	got := readEntriesViaPassword(t, env, ids)
	for id, want := range entries {
		if got[id] != want {
			t.Errorf("%s under the new password = %q", id, got[id])
		}
	}
	db, err := sql.Open("sqlite", env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	var check string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Errorf("integrity_check = %q, %v", check, err)
	}
}

// sealedSecrets reads every entry's encrypted secret from the vault at
// dbPath.
func sealedSecrets(t *testing.T, dbPath string) [][]byte {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	rows, err := db.Query(`SELECT encrypted_data FROM entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck // test cleanup
	var all [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		all = append(all, b)
	}
	return all
}
