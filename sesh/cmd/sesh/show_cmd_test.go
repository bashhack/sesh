package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// showVault is editVault with details on password/github/alice, filed in
// work with the tag code.
func showVault(t *testing.T) *rekeyTestEnv {
	t.Helper()
	env := editVault(t)
	mustRun(t, runFolder, "move", "work", "password/github/alice")
	mustRun(t, runTag, "add", "code", "password/github/alice")
	store := openDoctorVault(t, env)
	d := vault.Details{
		URL:   "https://github.com/login",
		Notes: []byte("line one\nline two\n"),
		Fields: []vault.Field{
			{Name: "recovery-email", Value: []byte("alice@example.com")},
			{Name: "pin", Value: []byte("4321"), Secret: true},
		},
	}
	if err := store.SetDetails(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}, &d); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return env
}

func runShowOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	app := agentTestApp()
	err := runShow(app, args)
	return app.Stdout.(*bytes.Buffer).String(), err
}

// Without --reveal, the secret, notes and secret fields show as hidden,
// and none of them is read.
func TestShow_HidesSecrets(t *testing.T) {
	env := showVault(t)
	before := auditEvents(t, env.dbPath)
	out, err := runShowOut(t, "password/github/alice")
	if err != nil {
		t.Fatal(err)
	}
	want := "password/github/alice\n" +
		"  URL       https://github.com/login\n" +
		"  Folder    work\n" +
		"  Tags      code\n" +
		"  Password  ••••••••   (--reveal)\n" +
		"  Notes     ••••••••   (--reveal)\n" +
		"  Fields\n" +
		"    recovery-email   alice@example.com\n" +
		"    pin (secret)     ••••••••\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	if after := auditEvents(t, env.dbPath); after["access"] != before["access"] {
		t.Errorf("access events before %d, after %d; want none", before["access"], after["access"])
	}
	// An entry with nothing more shows its secret's row alone.
	out, err = runShowOut(t, "api_key/openai")
	if err != nil || out != "api_key/openai\n  API key  ••••••••   (--reveal)\n" {
		t.Errorf("bare entry: %q, %v", out, err)
	}
}

// --reveal unlocks the vault and shows everything, notes indented under
// their first line; reading them is recorded as access.
func TestShow_Reveal(t *testing.T) {
	env := showVault(t)
	before := auditEvents(t, env.dbPath)
	out, err := runShowOut(t, "password/github/alice", "--reveal")
	if err != nil {
		t.Fatal(err)
	}
	want := "password/github/alice\n" +
		"  URL       https://github.com/login\n" +
		"  Folder    work\n" +
		"  Tags      code\n" +
		"  Password  old-pw\n" +
		"  Notes     line one\n" +
		"            line two\n" +
		"  Fields\n" +
		"    recovery-email   alice@example.com\n" +
		"    pin (secret)     4321\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	if after := auditEvents(t, env.dbPath); after["access"] != before["access"]+2 {
		t.Errorf("access events before %d, after %d; want the secret and the details read", before["access"], after["access"])
	}
}

// --format json gives the same, hidden values left out unless revealed.
func TestShow_JSON(t *testing.T) {
	showVault(t)
	type field struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Secret bool   `json:"secret"`
	}
	var got struct {
		ID       string   `json:"id"`
		Kind     string   `json:"kind"`
		Service  string   `json:"service"`
		Username string   `json:"username"`
		URL      string   `json:"url"`
		Folder   string   `json:"folder"`
		Secret   *string  `json:"secret"`
		Notes    *string  `json:"notes"`
		Tags     []string `json:"tags"`
		Fields   []field  `json:"fields"`
		HasNotes bool     `json:"has_notes"`
	}
	out, err := runShowOut(t, "password/github/alice", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.ID != "password/github/alice" || got.URL != "https://github.com/login" || got.Folder != "work" || !got.HasNotes ||
		got.Secret != nil || got.Notes != nil || len(got.Fields) != 2 || got.Fields[1] != (field{Name: "pin", Secret: true}) {
		t.Errorf("hidden JSON = %+v\n%s", got, out)
	}
	if strings.Contains(out, "4321") || strings.Contains(out, "old-pw") {
		t.Errorf("hidden JSON shows a secret: %s", out)
	}
	got.Fields = nil
	out, err = runShowOut(t, "password/github/alice", "--format", "json", "--reveal")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.Secret == nil || *got.Secret != "old-pw" || got.Notes == nil || *got.Notes != "line one\nline two\n" || got.Fields[1].Value != "4321" {
		t.Errorf("revealed JSON = %+v\n%s", got, out)
	}
}

func TestShow_Refusals(t *testing.T) {
	showVault(t)
	for _, tc := range []struct {
		wantSub string
		args    []string
	}{
		{"name the entry first", []string{"--reveal", "password/github/alice"}},
		{"sesh show shows one entry", []string{"password/github/alice", "extra"}},
		{"entry not found: password/GitHub/alice; did you mean password/github/alice?", []string{"password/GitHub/alice"}},
		{"--format is text or json", []string{"password/github/alice", "--format", "yaml"}},
		{"want kind/service or kind/service/username", []string{"github"}},
	} {
		if _, err := runShowOut(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("show %q = %v, want an error containing %q", tc.args, err, tc.wantSub)
		}
	}
}
