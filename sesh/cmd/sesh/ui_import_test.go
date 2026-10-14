package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// The app's import is sesh import's: a protected export asks for its password, the plan is the same summary however
// often it's planned, and applying it imports and records it.
func TestUI_Import(t *testing.T) {
	env := importVault(t)
	store := openDoctorVault(t, env)
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	file, err := filepath.Abs(bitwardenFixture("password.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.StartImport("bitwarden", []string{file}, nil); !errors.Is(err, tui.ErrNeedsPassword) || err.Error() != "the Bitwarden export is protected by a password" {
		t.Fatalf("without its password: %v", err)
	}
	if _, err := u.StartImport("bitwarden", []string{file}, []byte("wrong")); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("a wrong password: %v", err)
	}
	im, err := u.StartImport("bitwarden", []string{file}, []byte("export-pass-1"))
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	plan, err := im.Plan("")
	if err != nil || plan.Clashes != 1 || !strings.Contains(plan.Summary, "Already in the vault (1):\n  totp/GitHub/alice") {
		t.Fatalf("%+v, %v", plan, err)
	}
	// Planned again, from the files read again: the same summary, no note said twice.
	again, err := im.Plan("overwrite")
	if err != nil {
		t.Fatal(err)
	}
	again2, _ := im.Plan("overwrite") //nolint:errcheck // compared
	if again.Summary != again2.Summary || again.Count != plan.Count+1 {
		t.Errorf("planned twice:\n%s\n---\n%s", again.Summary, again2.Summary)
	}
	// What was read before is wiped when the files are read again.
	before := im.(*uiImport).f.entries[0]
	if _, err := im.Plan("skip"); err != nil {
		t.Fatal(err)
	}
	if len(before.Secret) > 0 && strings.Trim(string(before.Secret), "\x00") != "" {
		t.Errorf("the earlier read's secret wasn't wiped: %q", before.Secret)
	}
	said, err := im.Apply()
	if err != nil || !strings.HasPrefix(said, "Imported 11 entries from Bitwarden.") || strings.Contains(said, "\n") {
		t.Errorf("applied: %q, %v", said, err)
	}
	// Another command that only reads after it: the app's own import isn't taken for its change.
	other := openDoctorVault(t, env)
	if _, err := other.Get(vault.Key{Kind: vault.KindTOTP, Service: "GitHub", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	other.Close() //nolint:errcheck,gosec // test cleanup
	if changed, err := u.Check(); err != nil || changed {
		t.Errorf("the app's own import seen as another command's change: %v, %v", changed, err)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "import") {
		t.Errorf("audit:\n%s", log)
	}
	for _, files := range [][]string{{"bw.json"}, {"-"}, {}} {
		if _, err := u.StartImport("bitwarden", files, nil); err == nil {
			t.Errorf("%q taken", files)
		}
	}
}
