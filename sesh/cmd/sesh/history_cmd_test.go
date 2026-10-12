package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/vault"
)

// putSecrets stores each secret over k in turn, through the vault as sesh
// opens it, so its history is kept.
func putSecrets(t *testing.T, k vault.Key, secrets ...string) {
	t.Helper()
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	for _, s := range secrets {
		if err := store.Put(k, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
}

// sesh history lists an entry's versions, shows and copies one, restores
// one (keeping the one it replaces), and forgets one.
func TestHistoryCommands(t *testing.T) {
	filingVault(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "gitlab"}
	if got := mustRun(t, runHistory, "password/gitlab"); !strings.Contains(got, "1        now\n") || !strings.Contains(got, "No earlier secrets yet") {
		t.Errorf("no history:\n%s", got)
	}
	putSecrets(t, k, "two", "three")
	list := mustRun(t, runHistory, "password/gitlab")
	if !strings.Contains(list, "VERSION  SECRET") || !strings.Contains(list, "2        replaced ") || !strings.Contains(list, "3        replaced ") ||
		!strings.Contains(list, "See one with: sesh history password/gitlab --show <version>") || strings.Contains(list, "two") {
		t.Errorf("list:\n%s", list)
	}
	if got := mustRun(t, runHistory, "password/gitlab", "--show", "3"); got != "b\n" {
		t.Errorf("--show 3 = %q, want the first secret", got)
	}
	if got := mustRun(t, runHistory, "--show", "1", "password/gitlab"); got != "three\n" {
		t.Errorf("--show 1 = %q", got)
	}
	var copied string
	app := agentTestApp()
	app.ClipboardCopy = func(s string) error { copied = s; return nil }
	if err := runHistory(app, []string{"password/gitlab", "--clip", "2"}); err != nil || copied != "two" {
		t.Errorf("--clip 2 copied %q, %v", copied, err)
	}
	if got := mustRun(t, runHistory, "password/gitlab", "--restore", "3"); got != "✅ password/gitlab's secret is version 3's again; the one it replaced is now version 2.\n" {
		t.Errorf("--restore: %q", got)
	}
	if got := mustRun(t, runHistory, "password/gitlab", "--show", "1"); got != "b\n" {
		t.Errorf("after restore, --show 1 = %q", got)
	}
	if got := mustRun(t, runHistory, "password/gitlab", "--show", "2"); got != "three\n" {
		t.Errorf("after restore, --show 2 = %q", got)
	}
	if got := mustRun(t, runHistory, "password/gitlab", "--forget", "2"); got != "✅ Deleted password/gitlab's version 2 for good.\n" {
		t.Errorf("--forget: %q", got)
	}
	for args, want := range map[string]string{
		"password/gitlab --restore 1":       "version 1 is the secret now",
		"password/gitlab --forget 0":        "--forget takes a version number, 1 or more",
		"password/gitlab --show 2,3":        "--show takes one version",
		"password/gitlab --show 9":          "no such version: password/gitlab has versions 1 (the current secret) to",
		"password/gitlab --show 2 --clip 3": "use one of --show, --clip, --restore and --forget at a time",
		"password/nope":                     "not found",
	} {
		if _, err := runFiling(t, runHistory, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", args, err, want)
		}
	}
}

// Lowering history.keep drops what's past it when the vault is next
// unlocked, and says so in the audit log; 0 keeps no new earlier secrets
// but drops none of those kept.
func TestHistory_KeepLoweredOrNone(t *testing.T) {
	filingVault(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "gitlab"}
	putSecrets(t, k, "two", "three")
	t.Setenv(config.EnvHistoryKeep, "1")
	if got := mustRun(t, runHistory, "password/gitlab"); !strings.Contains(got, "2        replaced") || strings.Contains(got, "3        replaced") {
		t.Errorf("history.keep lowered to 1:\n%s", got)
	}
	if got := mustRun(t, runAudit); !strings.Contains(got, "1 earlier secret past history.keep (1) dropped") {
		t.Errorf("audit:\n%s", got)
	}
	t.Setenv(config.EnvHistoryKeep, "0")
	putSecrets(t, k, "four")
	got := mustRun(t, runHistory, "password/gitlab")
	if !strings.Contains(got, "2        replaced") || strings.Contains(got, "3        replaced") {
		t.Errorf("history.keep 0 kept a new one or dropped the old:\n%s", got)
	}
	if got := mustRun(t, runHistory, "password/gitlab", "--forget", "2,2"); got != "✅ Deleted password/gitlab's version 2 for good.\n" {
		t.Errorf("--forget 2,2: %q", got)
	}
}

// Two unreadable versions of one entry get one --forget naming both, which
// forgets just those.
func TestDoctor_HistorySeveralDamaged(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/a": "one"})
	k := vault.Key{Kind: vault.KindPassword, Service: "a"}
	putSecrets(t, k, "two", "three", "four", "five", "six")
	// Versions: 2 five, 3 four, 4 three, 5 two, 6 one; damage 3 and 5.
	sqlExec(t, env.dbPath, `UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE id IN (
		SELECT id FROM history ORDER BY id DESC LIMIT 1 OFFSET 1)`)
	sqlExec(t, env.dbPath, `UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE id IN (
		SELECT id FROM history ORDER BY id DESC LIMIT 1 OFFSET 3)`)
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "sesh history password/a --forget 3,5") {
		t.Fatalf("%v\n%s", err, out)
	}
	mustRun(t, runHistory, "password/a", "--forget", "3,5")
	for v, want := range map[string]string{"2": "five\n", "3": "three\n", "4": "one\n"} {
		if got := mustRun(t, runHistory, "password/a", "--show", v); got != want {
			t.Errorf("version %s = %q, want %q", v, got, want)
		}
	}
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "3 earlier secrets, all readable") {
		t.Errorf("after the printed forget: %v\n%s", err, out)
	}
}

// sesh doctor shows the history, names an earlier secret that can't be
// read by its version, and the --forget it prints clears it.
func TestDoctor_History(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/a": "one"})
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "a"}, "two", "three")
	out, err := runDoctorOut(t)
	if err != nil || !strings.Contains(out, "History") || !strings.Contains(out, "2 earlier secrets, all readable") {
		t.Fatalf("%v\n%s", err, out)
	}
	sqlExec(t, env.dbPath, `UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE id = (SELECT min(id) FROM history)`)
	out, err = runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "password/a, version 3: earlier secret doesn't decrypt") || !strings.Contains(out, "sesh history password/a --forget 3") {
		t.Fatalf("%v\n%s", err, out)
	}
	mustRun(t, runHistory, "password/a", "--forget", "3")
	if out, err := runDoctorOut(t); err != nil || !strings.Contains(out, "1 earlier secret, all readable") {
		t.Errorf("after the printed forget: %v\n%s", err, out)
	}
}

// An entry with both a version that doesn't decrypt and one whose time
// alone doesn't read gets one --forget, naming the other as optional, so
// doing what doctor says can't renumber the versions it names.
func TestDoctor_HistoryMixedDamage(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/a": "one"})
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "a"}, "two", "three", "four", "five")
	// Versions: 2 four (time damaged), 3 three, 4 two (doesn't decrypt), 5 one.
	sqlExec(t, env.dbPath, `UPDATE history SET replaced_at = 'garbage' WHERE id = (SELECT max(id) FROM history)`)
	sqlExec(t, env.dbPath, `UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE id IN (
		SELECT id FROM history ORDER BY id DESC LIMIT 1 OFFSET 2)`)
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "add 2, whose time alone doesn't read, only if you don't need it") ||
		!strings.Contains(out, "sesh history password/a --forget 4\n") || strings.Contains(out, "--forget 2\n") {
		t.Fatalf("%v\n%s", err, out)
	}
	mustRun(t, runHistory, "password/a", "--forget", "4")
	if got := mustRun(t, runHistory, "password/a", "--show", "4"); got != "one\n" {
		t.Errorf("after the printed forget, version 4 = %q, want one", got)
	}
}
