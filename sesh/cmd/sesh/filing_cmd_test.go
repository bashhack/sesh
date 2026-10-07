package main

import (
	"bytes"
	"strings"
	"testing"
)

// filingVault is a vault with four entries, opened with SESH_MASTER_PASSWORD.
func filingVault(t *testing.T) {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "filing-password-1234")
	populatePasswordStore(t, env, map[string]string{
		"password/github/alice": "a", "password/gitlab": "b", "api_key/openai": "c", "password/My Bank": "d",
	})
}

func runFiling(t *testing.T, run func(*App, []string) error, args ...string) (string, error) {
	t.Helper()
	app := agentTestApp()
	err := run(app, args)
	return app.Stdout.(*bytes.Buffer).String(), err
}

func mustRun(t *testing.T, run func(*App, []string) error, args ...string) string {
	t.Helper()
	out, err := runFiling(t, run, args...)
	if err != nil {
		t.Fatalf("%q: %v", args, err)
	}
	return out
}

func TestFolderCommands(t *testing.T) {
	filingVault(t)
	if got := mustRun(t, runFolder, "list"); got != "No folders yet. File entries in one with: sesh folder move <folder> <id>…\n4 entries are in no folder.\n" {
		t.Errorf("an empty list:\n%s", got)
	}
	if got := mustRun(t, runFolder, "move", "work/dev", "password/github/alice", "password/gitlab"); got != "✅ Moved 2 entries to work/dev\n" {
		t.Errorf("move: %q", got)
	}
	// Named twice, and one already there.
	if got := mustRun(t, runFolder, "move", "work", "api_key/openai", "api_key/openai", "password/My Bank"); got != "✅ Moved 2 entries to work\n" {
		t.Errorf("move: %q", got)
	}
	if got := mustRun(t, runFolder, "move", "work", "api_key/openai"); got != "✅ Moved 0 entries to work (1 was already there)\n" {
		t.Errorf("move again: %q", got)
	}
	if got := mustRun(t, runFolder, "move", "", "password/My Bank"); got != "✅ Took 1 entry out of its folder\n" {
		t.Errorf("out of its folder: %q", got)
	}
	want := "Folders:\n" +
		"  work   1  (3 in all)\n" +
		"    dev  2\n" +
		"1 entry is in no folder.\n"
	if got := mustRun(t, runFolder, "list"); got != want {
		t.Errorf("list:\n%s\nwant:\n%s", got, want)
	}
	if got := mustRun(t, runFolder, "rename", "work", "job"); got != "✅ Renamed folder work to job, on 3 entries\n" {
		t.Errorf("rename: %q", got)
	}
	if got := mustRun(t, runFolder, "rename", "job/dev", "job"); !strings.Contains(got, "on 2 entries; job was already in use, so the two are now one") {
		t.Errorf("rename onto a folder in use: %q", got)
	}
}

func TestTagCommands(t *testing.T) {
	filingVault(t)
	if got := mustRun(t, runTag, "list"); got != "No tags yet. Tag entries with: sesh tag add <tag> <id>…\n4 entries have no tags.\n" {
		t.Errorf("an empty list:\n%s", got)
	}
	if got := mustRun(t, runTag, "add", "code", "password/github/alice", "password/gitlab"); got != "✅ Tagged 2 entries code\n" {
		t.Errorf("add: %q", got)
	}
	if got := mustRun(t, runTag, "add", "urgent", "password/github/alice", "password/My Bank"); got != "✅ Tagged 2 entries urgent\n" {
		t.Errorf("add: %q", got)
	}
	if got := mustRun(t, runTag, "remove", "code", "password/gitlab", "api_key/openai"); got != "✅ Took tag code off 1 entry (1 didn't have it)\n" {
		t.Errorf("remove: %q", got)
	}
	want := "Tags:\n" +
		"  code    1\n" +
		"  urgent  2\n" +
		"2 entries have no tags.\n"
	if got := mustRun(t, runTag, "list"); got != want {
		t.Errorf("list:\n%s\nwant:\n%s", got, want)
	}
	if got := mustRun(t, runTag, "rename", "code", "urgent"); got != "✅ Renamed tag code to urgent, on 1 entry; urgent was already in use, so the two are now one\n" {
		t.Errorf("rename: %q", got)
	}
}

func TestFilingCommands_Refusals(t *testing.T) {
	filingVault(t)
	for name, tt := range map[string]struct {
		wantSub string
		run     func(*App, []string) error
		args    []string
	}{
		"a missing entry, by case":  {"did you mean password/github/alice?", runTag, []string{"add", "x", "password/GitHub/alice"}},
		"several problems":          {"nothing was changed:\n  entry ID \"bad\"", runFolder, []string{"move", "w", "bad", "worse", "password/gitlab"}},
		"several missing":           {"nothing was changed:\n  entry not found: password/nope\n  entry not found: password/none", runFolder, []string{"move", "w", "password/nope", "password/gitlab", "password/none"}},
		"a bad folder":              {"has an empty part", runFolder, []string{"move", "w/", "password/gitlab"}},
		"a bad tag":                 {`can't start with "-"`, runTag, []string{"remove", "-x", "password/gitlab"}},
		"no IDs":                    {"needs a tag and at least one entry ID", runTag, []string{"add", "x"}},
		"a missing folder, by case": {`there's no folder "Nope"`, runFolder, []string{"rename", "Nope", "x"}},
		"into itself":               {"into a folder under itself", runFolder, []string{"rename", "a", "a/b"}},
		"a missing tag":             {`there's no tag "nope"`, runTag, []string{"rename", "nope", "x"}},
		"an unknown command":        {`unknown sesh tag command "move"`, runTag, []string{"move"}},
		"list with arguments":       {"takes no arguments", runFolder, []string{"list", "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runFiling(t, tt.run, tt.args...); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantSub)
			}
		})
	}
	// Nothing was changed by any of them.
	if got := mustRun(t, runTag, "list"); !strings.HasPrefix(got, "No tags yet") {
		t.Errorf("after refusals: %s", got)
	}
}

// IDs are checked before the vault is unlocked, and a missing vault isn't
// created.
func TestFilingCommands_BeforeUnlocking(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	if _, err := runFiling(t, runTag, "add", "x", "bad"); err == nil || !strings.Contains(err.Error(), `entry ID "bad"`) {
		t.Errorf("a bad ID: %v", err)
	}
	if _, err := runFiling(t, runFolder, "list"); err == nil || !strings.Contains(err.Error(), "there's no vault yet") {
		t.Errorf("no vault: %v", err)
	}
}
