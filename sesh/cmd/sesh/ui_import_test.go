package main

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

// Let go while it's being written, the import finishes before what it read is wiped: entries are stored, none with a
// wiped secret. After it's let go, nothing is read again.
func TestUI_ImportClosedWhileApplied(t *testing.T) {
	env := importVault(t)
	store := openDoctorVault(t, env)
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	file, err := filepath.Abs(browserFixture("chromium.csv"))
	if err != nil {
		t.Fatal(err)
	}
	im, err := u.StartImport("chrome", []string{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := im.Plan("skip"); err != nil {
		t.Fatal(err)
	}
	// The vault's write lock, held from another connection, keeps Apply
	// writing, its own lock held, until it's let go.
	db, err := sql.Open("sqlite", env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := im.Apply()
		done <- err
	}()
	mu := &im.(*uiImport).mu
	for mu.TryLock() {
		mu.Unlock()
		runtime.Gosched()
	}
	closed := make(chan struct{})
	go func() {
		im.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Error("let go while it was being written")
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := conn.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-closed
	keys, err := store.List(&vault.Filter{Kind: vault.KindPassword})
	if err != nil || len(keys) == 0 {
		t.Fatalf("stored %d, %v", len(keys), err)
	}
	for _, e := range keys {
		secret, err := store.Get(e.Key)
		if err != nil || len(secret) == 0 || strings.Trim(string(secret), "\x00") == "" {
			t.Errorf("%s stored with %q, %v", e.Key, secret, err)
		}
	}
	if _, err := im.Plan(""); !errors.Is(err, errImportClosed) || im.(*uiImport).f != nil {
		t.Errorf("planned after it was let go: %v", err)
	}
}

// A plan that fails leaves nothing to apply, so the plan before it, whose entries it wiped, isn't written.
func TestUI_ImportPlanFails(t *testing.T) {
	env := importVault(t)
	store := openDoctorVault(t, env)
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	src, err := os.ReadFile(browserFixture("chromium.csv"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "chrome.csv")
	if err := os.WriteFile(file, src, 0o600); err != nil {
		t.Fatal(err)
	}
	im, err := u.StartImport("chrome", []string{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if _, err := im.Plan(""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := im.Plan("skip"); err == nil {
		t.Fatal("planned with the file gone")
	}
	if _, err := im.Apply(); err == nil || err.Error() != "nothing is planned" {
		t.Errorf("applied after a failed plan: %v", err)
	}
	if n, err := store.List(&vault.Filter{Kind: vault.KindPassword}); err != nil || len(n) != 0 {
		t.Errorf("entries written: %d, %v", len(n), err)
	}
}
