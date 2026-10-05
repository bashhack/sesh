package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/vault"
)

// auditTestVault creates a password-protected vault holding one entry,
// read once (two audit events), and returns its path.
func auditTestVault(t *testing.T) string {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "audit-password-1234")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := store.Put(gh, []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(gh); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return env.dbPath
}

// addOldAuditEvent writes an audit event days old straight into the vault.
func addOldAuditEvent(t *testing.T, dbPath, entry string, days int) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := db.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES ('access', ?, 'GetSecret', ?)`,
		entry, time.Now().UTC().AddDate(0, 0, -days)); err != nil {
		t.Fatal(err)
	}
}

func runAuditOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	app := agentTestApp()
	err := runAudit(app, args)
	return app.Stdout.(*bytes.Buffer).String(), err
}

func TestAudit_ShowsNewestFirst(t *testing.T) {
	auditTestVault(t)
	out, err := runAuditOut(t)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.HasPrefix(lines[0], "Audit log: 2 events since ") || !strings.Contains(lines[0], "Events older than 90 days are removed automatically (audit.retention_days).") {
		t.Errorf("summary = %q", lines[0])
	}
	if len(lines) != 4 || !strings.HasSuffix(lines[2], "  access  password     github (alice)") || !strings.HasSuffix(lines[3], "  modify  password     github (alice)") {
		t.Errorf("events not listed newest first:\n%s", out)
	}
}

func TestAudit_Limit(t *testing.T) {
	auditTestVault(t)
	out, err := runAuditOut(t, "--limit", "1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "github (alice)") != 1 || !strings.Contains(out, "Showing the newest 1 of 2; --limit 0 shows them all.") {
		t.Errorf("output:\n%s", out)
	}
}

func TestAudit_Prune(t *testing.T) {
	dbPath := auditTestVault(t)
	t.Setenv(config.EnvAuditRetentionDays, "0") // keep everything unless pruned
	addOldAuditEvent(t, dbPath, "old", 100)
	addOldAuditEvent(t, dbPath, "older", 200)
	addOldAuditEvent(t, dbPath, "future", -1) // stamped by a clock that was ahead

	out, err := runAuditOut(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Audit log: 5 events since ") || !strings.Contains(out, "Nothing is removed automatically (audit.retention_days = 0); remove old events with: sesh audit prune --older-than <days>") {
		t.Errorf("summary with retention 0:\n%s", out)
	}
	compacted := regexp.MustCompile(`, and compacted the vault from [0-9.]+ (KB|MB) to [0-9.]+ (KB|MB)\.\n$`)
	if out, err := runAuditOut(t, "prune", "--older-than", "150"); err != nil || !strings.HasPrefix(out, "Removed 1 event older than 150 days, and compacted") || !compacted.MatchString(out) {
		t.Errorf("prune 150 = %q, %v", out, err)
	}
	if out, err := runAuditOut(t, "prune", "--older-than", "150"); err != nil || out != "No events older than 150 days.\n" {
		t.Errorf("prune 150 again = %q, %v", out, err)
	}
	if out, err := runAuditOut(t, "prune", "--older-than", "0"); err != nil || !strings.HasPrefix(out, "Removed all 4 events, and compacted") || !compacted.MatchString(out) {
		t.Errorf("prune 0 = %q, %v", out, err)
	}
	if out, err := runAuditOut(t); err != nil || out != "Audit log: no events.\n" {
		t.Errorf("after pruning everything = %q, %v", out, err)
	}
}

func TestAudit_RetentionPrunesOnOpen(t *testing.T) {
	dbPath := auditTestVault(t)
	addOldAuditEvent(t, dbPath, "old", 100)
	addOldAuditEvent(t, dbPath, "recent", 10)

	t.Setenv(config.EnvAuditRetentionDays, "0")
	if out, err := runAuditOut(t); err != nil || !strings.Contains(out, "4 events") {
		t.Fatalf("retention 0 removed events (%v):\n%s", err, out)
	}
	t.Setenv(config.EnvAuditRetentionDays, "30")
	out, err := runAuditOut(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "3 events") || strings.Contains(out, " old\n") || !strings.Contains(out, " recent\n") {
		t.Errorf("retention 30 should remove only the 100-day-old event:\n%s", out)
	}
}

func TestAudit_Refusals(t *testing.T) {
	auditTestVault(t)
	for _, tt := range []struct {
		wantSub string
		args    []string
	}{
		{"sesh audit prune needs --older-than <days>", []string{"prune"}},
		{"--older-than wants a whole number of days from 0 (everything) to 36500, got -1", []string{"prune", "--older-than", "-1"}},
		{`sesh audit prune takes no arguments, got "extra"`, []string{"prune", "--older-than", "30", "extra"}},
		{`sesh audit takes no arguments, got "list"`, []string{"list"}},
		{"--limit wants 0 (all events) or more, got -1", []string{"--limit", "-1"}},
	} {
		if _, err := runAuditOut(t, tt.args...); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
			t.Errorf("sesh audit %q: err = %v, want %q", tt.args, err, tt.wantSub)
		}
	}
}

func TestAuditEntryName(t *testing.T) {
	for _, tt := range []struct{ id, kind, name string }{
		{"password/github/alice", "password", "github (alice)"},
		{"api_key/openai", "api_key", "openai"},
		{"totp/github/work", "totp", "github (work)"},
		{"totp/aws/prod", "totp", "aws (prod)"},
		{"secure_note/wifi/home", "secure_note", "wifi (home)"},
		{"password/github/alice/extra", "", "password/github/alice/extra"},
		{"sesh-totp/github", "", "sesh-totp/github"},
		{"password", "", "password"},
		{"something/else", "", "something/else"},
		{"", "", ""},
	} {
		if kind, name := auditEntryName(tt.id); kind != tt.kind || name != tt.name {
			t.Errorf("auditEntryName(%q) = %q, %q; want %q, %q", tt.id, kind, name, tt.kind, tt.name)
		}
	}
}

func TestVaultSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 KB", 1: "1 KB", 69632: "70 KB", 999_999: "1000 KB", 1_000_000: "1.0 MB", 133_849_088: "133.8 MB"} {
		if got := vaultSize(n); got != want {
			t.Errorf("vaultSize(%d) = %q, want %q", n, got, want)
		}
	}
}

// warnAuditSizeAt sets up the size warning for a test: limit events, a
// terminal or not, and a marker file in a temp dir. It returns the marker.
func warnAuditSizeAt(t *testing.T, limit int64, terminal bool) string {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "audit-size-warned")
	origLimit, origTerm, origPath := auditWarnEvents, stderrIsTerminal, auditWarnedPath
	auditWarnEvents = limit
	stderrIsTerminal = func() bool { return terminal }
	auditWarnedPath = func(string) string { return marker }
	t.Cleanup(func() { auditWarnEvents, stderrIsTerminal, auditWarnedPath = origLimit, origTerm, origPath })
	return marker
}

// openForWarning opens the vault as any command does and returns stderr.
func openForWarning(t *testing.T) string {
	t.Helper()
	restore := testutil.RedirectStderr(t)
	store, err := openSQLiteStore()
	out := restore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAuditSizeWarning(t *testing.T) {
	dbPath := auditTestVault(t)
	t.Setenv(config.EnvAuditRetentionDays, "0")
	addOldAuditEvent(t, dbPath, "old", 100)
	addOldAuditEvent(t, dbPath, "older", 200)

	t.Run("not at a terminal", func(t *testing.T) {
		marker := warnAuditSizeAt(t, 3, false)
		if out := openForWarning(t); strings.Contains(out, "audit log") {
			t.Errorf("warned without a terminal: %q", out)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("marker written without a warning (err %v)", err)
		}
	})
	t.Run("below the limit", func(t *testing.T) {
		warnAuditSizeAt(t, 1000, true)
		if out := openForWarning(t); strings.Contains(out, "audit log") {
			t.Errorf("warned below the limit: %q", out)
		}
	})
	t.Run("once a day, with advice for the setting", func(t *testing.T) {
		marker := warnAuditSizeAt(t, 3, true)
		out := openForWarning(t)
		for _, want := range []string{
			"warning: the vault's audit log has about 4 events, and the vault is ",
			"Set audit.retention_days (now 0, which keeps everything), or remove old events now with: sesh audit prune --older-than <days>",
			"This warning shows at most once a day.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("warning missing %q:\n%s", want, out)
			}
		}
		if again := openForWarning(t); strings.Contains(again, "audit log") {
			t.Errorf("warned twice in a day: %q", again)
		}
		yesterday := time.Now().Add(-25 * time.Hour)
		if err := os.Chtimes(marker, yesterday, yesterday); err != nil {
			t.Fatal(err)
		}
		t.Setenv(config.EnvAuditRetentionDays, "365")
		out = openForWarning(t)
		if !strings.Contains(out, "Keep fewer days with audit.retention_days (now 365 days), or remove old events now with: sesh audit prune --older-than <days>") {
			t.Errorf("no warning a day later, or wrong advice:\n%s", out)
		}
		// A marker from a clock that was ahead doesn't silence the warning.
		ahead := time.Now().Add(48 * time.Hour)
		if err := os.Chtimes(marker, ahead, ahead); err != nil {
			t.Fatal(err)
		}
		if out := openForWarning(t); !strings.Contains(out, "audit log") {
			t.Errorf("a marker dated in the future silenced the warning: %q", out)
		}
	})
}

// The marker sits next to the vault, so the warning doesn't depend on a
// cache directory (none without HOME, for instance).
func TestAuditSizeWarning_MarkerNextToTheVault(t *testing.T) {
	dbPath := auditTestVault(t)
	t.Setenv(config.EnvAuditRetentionDays, "0")
	warnAuditSizeAt(t, 1000, true) // no warning while opening
	auditWarnedPath = defaultAuditWarnedPath
	addOldAuditEvent(t, dbPath, "old", 100)
	addOldAuditEvent(t, dbPath, "older", 200)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	auditWarnEvents = 3
	restore := testutil.RedirectStderr(t)
	warnAuditSize(store, cfg)
	if out := restore(); !strings.Contains(out, "audit log") {
		t.Errorf("no warning without a cache directory: %q", out)
	}
	if _, err := os.Stat(dbPath + ".audit-warned"); err != nil {
		t.Errorf("marker not next to the vault: %v", err)
	}
}

func TestThousands(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1000009: "1,000,009", -1234: "-1,234"} {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q, want %q", n, got, want)
		}
	}
}

// The marker never overwrites anything, even a vault whose name collides
// with a marker's.
func TestAuditSizeWarning_NeverTruncatesTheVault(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "audit-password-1234")
	dbPath := filepath.Join(t.TempDir(), "audit-size-warned")
	t.Setenv(config.EnvDBPath, dbPath)
	t.Setenv(config.EnvAuditRetentionDays, "0")
	warnAuditSizeAt(t, 3, true)
	auditWarnedPath = defaultAuditWarnedPath

	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	for range 4 { // 4 audit events, over the limit of 3
		if err := store.Put(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}, []byte("hunter2")); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Day-to-day writes go to the write-ahead log, so the vault file's own
	// time can be days old.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(dbPath, old, old); err != nil {
		t.Fatal(err)
	}
	if out := openForWarning(t); !strings.Contains(out, "audit log") {
		t.Fatalf("expected the size warning: %q", out)
	}
	store, err = openSQLiteStore()
	if err != nil {
		t.Fatalf("vault unusable after the warning: %v", err)
	}
	defer closeAuditStore(store)
	if got, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}); err != nil || string(got) != "hunter2" {
		t.Errorf("entry after the warning = %q, %v", got, err)
	}
}

func TestTouchMarker(t *testing.T) {
	dir := t.TempDir()
	created := filepath.Join(dir, "new.audit-warned")
	touchMarker(created)
	if fi, err := os.Stat(created); err != nil || fi.Size() != 0 || time.Since(fi.ModTime()) > time.Minute {
		t.Errorf("new marker: %v, %v", fi, err)
	}
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(existing, old, old); err != nil {
		t.Fatal(err)
	}
	touchMarker(existing)
	got, err := os.ReadFile(existing) //nolint:gosec // the test's own temp file
	if err != nil || string(got) != "keep me" {
		t.Errorf("existing file's contents = %q, %v; want them untouched", got, err)
	}
	if fi, err := os.Stat(existing); err != nil || time.Since(fi.ModTime()) > time.Minute {
		t.Errorf("existing file's time not updated: %v, %v", fi, err)
	}
}
