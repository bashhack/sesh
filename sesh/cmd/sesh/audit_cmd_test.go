package main

import (
	"bytes"
	"database/sql"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
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
	if err := store.SetSecret("alice", "sesh-password/password/github/alice", []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSecret("alice", "sesh-password/password/github/alice"); err != nil {
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

	out, err := runAuditOut(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Audit log: 4 events since ") || !strings.Contains(out, "Nothing is removed automatically (audit.retention_days = 0); remove old events with: sesh audit prune --older-than <days>") {
		t.Errorf("summary with retention 0:\n%s", out)
	}
	compacted := regexp.MustCompile(`, and compacted the vault from [0-9.]+ (KB|MB) to [0-9.]+ (KB|MB)\.\n$`)
	if out, err := runAuditOut(t, "prune", "--older-than", "150"); err != nil || !strings.HasPrefix(out, "Removed 1 event older than 150 days, and compacted") || !compacted.MatchString(out) {
		t.Errorf("prune 150 = %q, %v", out, err)
	}
	if out, err := runAuditOut(t, "prune", "--older-than", "150"); err != nil || out != "No events older than 150 days.\n" {
		t.Errorf("prune 150 again = %q, %v", out, err)
	}
	if out, err := runAuditOut(t, "prune", "--older-than", "0"); err != nil || !strings.HasPrefix(out, "Removed all 3 events, and compacted") || !compacted.MatchString(out) {
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
	t.Setenv(config.EnvBackend, "keychain")
	if _, err := runAuditOut(t); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Errorf("keychain backend: err = %v", err)
	}
}

func TestAuditEntryName(t *testing.T) {
	for _, tt := range []struct{ id, kind, name string }{
		{"sesh-password/password/github/alice/me", "password", "github (alice)"},
		{"sesh-password/api_key/stripe/me", "api_key", "stripe"},
		{"sesh-password/secure_note/wifi/home/me", "secure_note", "wifi (home)"},
		{"sesh-password/totp/gitlab/me", "totp", "gitlab"},
		{"sesh-totp/github/me", "totp", "github"},
		{"sesh-totp/github/work/me", "totp", "github (work)"},
		{"sesh-aws/default/me", "aws", "default"},
		{"sesh-aws-serial/prod/me", "aws serial", "prod"},
		{"sesh-password/password/me", "", "sesh-password/password/me"},
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
