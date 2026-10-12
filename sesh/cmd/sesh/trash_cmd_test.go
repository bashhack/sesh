package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
)

// trashDelete deletes ids through the app over the real vault, answering
// yes at the terminal, with --purge when purge.
func trashDelete(t *testing.T, purge bool, ids ...string) (string, string) {
	t.Helper()
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	app := NewDefaultApp(VersionInfo{}, store, AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout})
	app.Stdin = strings.NewReader("y\n")
	app.StdinIsTerminal = func() bool { return true }
	var out, errOut bytes.Buffer
	app.Stdout, app.Stderr = &out, &errOut
	if err := app.DeleteEntries("password", ids, purge); err != nil {
		t.Fatalf("delete %v: %v", ids, err)
	}
	return out.String(), errOut.String()
}

// Deleting moves entries to the trash, which lists them; restoring puts
// one back, onto a name in use only with --as; remove, empty and --purge
// delete for good, asking first.
func TestTrashCommands(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{
		"password/github/alice": "a", "password/gitlab": "b", "api_key/openai": "c", "password/My Bank": "d",
	})
	if got := mustRun(t, runTrash); got != "The trash is empty.\n" {
		t.Errorf("empty: %q", got)
	}
	out, asked := trashDelete(t, false, "password/github/alice", "password/gitlab")
	if out != "✅ Moved 2 entries to the trash, kept 30 days: sesh trash lists them, and sesh trash restore <id> puts one back\n" ||
		!strings.Contains(asked, "Delete these 2 entries? [y/N]") {
		t.Errorf("delete: %q, asked %q", out, asked)
	}
	list := mustRun(t, runTrash, "list")
	if !strings.Contains(list, "ID  ENTRY") || !strings.Contains(list, "password/github/alice") || !strings.Contains(list, "password/gitlab") ||
		!strings.Contains(list, "Put one back with: sesh trash restore <id>") {
		t.Errorf("list:\n%s", list)
	}
	ids := map[string]string{}
	for _, line := range strings.Split(list, "\n")[1:] {
		if f := strings.Fields(line); len(f) >= 2 && strings.Contains(f[1], "/") {
			ids[f[1]] = f[0]
		}
	}
	if got := mustRun(t, runTrash, "restore", ids["password/github/alice"]); got != "✅ Restored password/github/alice from the trash.\n" {
		t.Errorf("restore: %q", got)
	}
	// Another gitlab, then the trashed one only under another name.
	populatePasswordStore(t, env, map[string]string{"password/gitlab": "new"})
	if _, err := runFiling(t, runTrash, "restore", ids["password/gitlab"]); err == nil || !strings.Contains(err.Error(), "password/gitlab already exists: rename or delete it first, or restore with --as <new name>") {
		t.Errorf("restore onto a name in use: %v", err)
	}
	if got := mustRun(t, runTrash, "restore", ids["password/gitlab"], "--as", "password/gitlab-old"); got != "✅ Restored password/gitlab-old from the trash.\n" {
		t.Errorf("restore --as: %q", got)
	}
	if _, err := runFiling(t, runTrash, "restore", "x"); err == nil || !strings.Contains(err.Error(), `"x" isn't a trash id`) {
		t.Errorf("a bad id: %v", err)
	}

	// Flags before the ids, and an id named twice, removed once.
	trashDelete(t, false, "password/gitlab-old")
	list = mustRun(t, runTrash)
	oldID := strings.Fields(strings.Split(list, "\n")[1])[0]
	if got := mustRun(t, runTrash, "remove", "--force", oldID, oldID); got != "✅ Deleted 1 entry for good.\n" {
		t.Errorf("remove --force id id: %q", got)
	}
	trashDelete(t, false, "password/gitlab")
	list = mustRun(t, runTrash)
	newID := strings.Fields(strings.Split(list, "\n")[1])[0]
	if got := mustRun(t, runTrash, "restore", "--as", "password/gitlab-2", newID); got != "✅ Restored password/gitlab-2 from the trash.\n" {
		t.Errorf("restore --as before the id: %q", got)
	}

	trashDelete(t, false, "api_key/openai")
	if _, err := runFiling(t, runTrash, "empty"); err == nil || !strings.Contains(err.Error(), "add --force") {
		t.Errorf("empty with nobody to ask: %v", err)
	}
	if got := mustRun(t, runTrash, "empty", "--force"); got != "✅ Emptied the trash: 1 entry deleted for good.\n" {
		t.Errorf("empty: %q", got)
	}
	out, asked = trashDelete(t, true, "password/My Bank")
	if out != "✅ Deleted 1 entry for good\n" || !strings.Contains(asked, `Delete "password/My Bank" for good? [y/N]`) {
		t.Errorf("--purge: %q, asked %q", out, asked)
	}
	if got := mustRun(t, runTrash); got != "The trash is empty.\n" {
		t.Errorf("after purge and empty: %q", got)
	}
}

// With trash.keep_days 0, deleting is for good.
func TestTrash_KeepNone(t *testing.T) {
	filingVault(t)
	t.Setenv(config.EnvTrashKeepDays, "0")
	if out, _ := trashDelete(t, false, "password/gitlab"); out != "✅ Deleted 1 entry for good\n" {
		t.Errorf("delete: %q", out)
	}
	if got := mustRun(t, runTrash); got != "The trash is empty. Deleting is for good (trash.keep_days is 0).\n" {
		t.Errorf("list: %q", got)
	}
}

// What's been in the trash longer than trash.keep_days goes for good when
// the vault is next unlocked.
func TestTrash_ExpiresOnUnlock(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	t.Setenv(config.EnvTrashKeepDays, "1")
	populatePasswordStore(t, env, map[string]string{"password/old": "a", "password/new": "b"})
	trashDelete(t, false, "password/old", "password/new")
	sqlExec(t, env.dbPath, `UPDATE trash SET deleted_at = datetime('now', '-2 days') WHERE service = 'old'`)
	got := mustRun(t, runTrash)
	if strings.Contains(got, "password/old") || !strings.Contains(got, "password/new") {
		t.Errorf("after unlocking, the trash:\n%s", got)
	}
}

// sesh doctor shows the trash when it holds entries, and names one that
// can't be read with the command that deletes it for good.
func TestDoctor_Trash(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/a": "a", "password/b": "b"})
	trashDelete(t, false, "password/a")
	out, err := runDoctorOut(t)
	if err != nil || !strings.Contains(out, "Trash") || !strings.Contains(out, "1 entry, all readable") {
		t.Fatalf("%v\n%s", err, out)
	}
	sqlExec(t, env.dbPath, `UPDATE trash SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'`)
	out, err = runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "1 of 1 entry can't be read") || !strings.Contains(out, "password/a: secret doesn't decrypt") ||
		!strings.Contains(out, "sesh trash remove ") {
		t.Errorf("%v\n%s", err, out)
	}
}

// A trash entry with damaged tags is shown by doctor with restoring as the
// fix, not deleting; one whose deletion time doesn't read lists with "?".
func TestTrash_DamagedRowAdvice(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{"password/a": "a", "password/b": "b"})
	trashDelete(t, false, "password/a", "password/b")
	sqlExec(t, env.dbPath, `UPDATE trash SET tags = 'nope' WHERE service = 'a'`)
	sqlExec(t, env.dbPath, `UPDATE trash SET deleted_at = 'garbage' WHERE service = 'b'`)
	out, err := runDoctorOut(t)
	if !errors.Is(err, errReported) || !strings.Contains(out, "password/a: tags don't read") || !strings.Contains(out, "it comes back without its tags") ||
		!strings.Contains(out, "sesh trash restore ") || !strings.Contains(out, "password/b: times don't read") || !strings.Contains(out, "sesh trash remove ") {
		t.Errorf("%v\n%s", err, out)
	}
	list := mustRun(t, runTrash)
	for line := range strings.SplitSeq(list, "\n") {
		if strings.Contains(line, "password/b") && !strings.Contains(line, "?") || strings.Contains(line, "password/b") && !strings.Contains(line, "unknown") {
			t.Errorf("a row with no deletion time: %q", line)
		}
	}
}
