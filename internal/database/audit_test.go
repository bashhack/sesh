package database

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// addAuditAt writes an audit event as audit does, but at the given time.
func addAuditAt(t *testing.T, s *Store, event, entry string, at time.Time) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES (?, ?, ?, ?)`,
		event, entry, "test", at.UTC()); err != nil {
		t.Fatal(err)
	}
}

func auditCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAuditLog_HasCreatedAtIndex(t *testing.T) {
	s := newTestStore(t)
	var detail string
	if err := s.db.QueryRow(`EXPLAIN QUERY PLAN DELETE FROM audit_log WHERE created_at < ?`, time.Now().UTC()).Scan(new(int), new(int), new(int), &detail); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(detail, "SEARCH audit_log USING") || !strings.Contains(detail, "INDEX idx_audit_log_created_at") {
		t.Errorf("prune query plan = %q, want a search on idx_audit_log_created_at", detail)
	}
}

func TestPruneAudit(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	addAuditAt(t, s, "access", "a", now.AddDate(0, 0, -100))
	addAuditAt(t, s, "access", "b", now.AddDate(0, 0, -50))
	// Either side of the cutoff within one second: stored text compares
	// "12:00:00 +0000" with "12:00:00.5 +0000".
	cutoff := now.AddDate(0, 0, -10)
	addAuditAt(t, s, "access", "c", cutoff.Add(-500*time.Millisecond))
	addAuditAt(t, s, "access", "d", cutoff)
	addAuditAt(t, s, "access", "e", cutoff.Add(500*time.Millisecond))
	addAuditAt(t, s, "modify", "f", now.Add(-time.Hour))

	n, err := s.PruneAudit(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("pruned %d, want 3 (a, b, c)", n)
	}
	events, err := s.AuditEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.EntryID)
	}
	if want := []string{"f", "e", "d"}; !slices.Equal(got, want) {
		t.Errorf("left %q, want %q", got, want)
	}

	if n, err := s.PruneAudit(now); err != nil || n != 3 {
		t.Errorf("pruning up to now removed %d, %v; want all 3", n, err)
	}
}

func TestAuditEvents(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetSecret("alice", "svc", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecret("alice", "svc"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEntry("alice", "svc"); err != nil {
		t.Fatal(err)
	}

	events, err := s.AuditEvents(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventType != "delete" || events[1].EventType != "access" {
		t.Fatalf("events = %+v, want the newest two: delete, then access", events)
	}
	if events[0].EntryID != "svc/alice" || events[0].Detail != "DeleteEntry" {
		t.Errorf("event = %+v", events[0])
	}
	if age := time.Since(events[0].CreatedAt); age < 0 || age > time.Minute {
		t.Errorf("CreatedAt = %v, want about now", events[0].CreatedAt)
	}

	all, err := s.AuditEvents(0)
	if err != nil || len(all) != 3 {
		t.Errorf("AuditEvents(0) = %d events, %v; want all 3", len(all), err)
	}
}

func TestAuditSummary(t *testing.T) {
	s := newTestStore(t)
	n, oldest, err := s.AuditSummary()
	if err != nil || n != 0 || !oldest.IsZero() {
		t.Fatalf("empty log: %d, %v, %v", n, oldest, err)
	}
	first := time.Date(2026, 4, 26, 17, 52, 0, 0, time.UTC)
	addAuditAt(t, s, "access", "a", first)
	addAuditAt(t, s, "access", "b", first.AddDate(0, 1, 0))
	addAuditAt(t, s, "access", "c", first.AddDate(0, 2, 0))
	if _, err := s.PruneAudit(first.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, oldest, err = s.AuditSummary()
	if err != nil || n != 2 || !oldest.Equal(first.AddDate(0, 1, 0)) {
		t.Errorf("summary = %d since %v, %v; want 2 since %v", n, oldest, err, first.AddDate(0, 1, 0))
	}
	if auditCount(t, s) != 2 {
		t.Errorf("count = %d", auditCount(t, s))
	}
}

func TestCompact(t *testing.T) {
	s := newTestStore(t)
	path := s.Path()
	if _, err := s.db.Exec(`WITH RECURSIVE c(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM c WHERE x < 19999)
		INSERT INTO audit_log (event_type, entry_id, detail, created_at)
		SELECT 'access', 'sesh-totp/github/me', 'GetSecret', '2026-01-01 00:00:00 +0000 UTC' FROM c`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneAudit(time.Now()); err != nil {
		t.Fatal(err)
	}
	before, err := s.Size()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	after, err := s.Size()
	if err != nil {
		t.Fatal(err)
	}
	if after >= before/4 {
		t.Errorf("%s: %d bytes before compacting, %d after; want it much smaller", path, before, after)
	}
	if err := s.SetSecret("alice", "svc", []byte("still works")); err != nil {
		t.Fatalf("store after compacting: %v", err)
	}
}

// Events are listed in the order they were written. A timestamp from a
// clock that was ahead must not push later events out of the newest few.
func TestAuditEvents_WriteOrderNotTimestamp(t *testing.T) {
	s := newTestStore(t)
	addAuditAt(t, s, "access", "clock-ahead", time.Now().Add(24*time.Hour))
	addAuditAt(t, s, "access", "after-the-fix", time.Now())
	events, err := s.AuditEvents(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EntryID != "after-the-fix" {
		t.Errorf("newest event = %+v, want the last one written", events)
	}
}

func TestClearAudit(t *testing.T) {
	s := newTestStore(t)
	addAuditAt(t, s, "access", "past", time.Now().AddDate(0, 0, -1))
	addAuditAt(t, s, "access", "future", time.Now().AddDate(0, 0, 1))
	if n, err := s.ClearAudit(); err != nil || n != 2 || auditCount(t, s) != 0 {
		t.Errorf("ClearAudit = %d, %v, %d left; want 2 removed, none left", n, err, auditCount(t, s))
	}
}

// Another sesh command reading the vault (an open read transaction) stops
// the write-ahead log from being folded back; Compact must say so.
func TestCompact_ReaderHoldsTheLog(t *testing.T) {
	orig := compactWait
	compactWait = 100 * time.Millisecond
	t.Cleanup(func() { compactWait = orig })
	s := newTestStore(t)
	if _, err := s.db.Exec(`WITH RECURSIVE c(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM c WHERE x < 4999)
		INSERT INTO audit_log (event_type, entry_id, detail, created_at)
		SELECT 'access', 'sesh-totp/github/me', 'GetSecret', '2026-01-01 00:00:00 +0000 UTC' FROM c`); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", s.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(new(int)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneAudit(time.Now()); err != nil {
		t.Fatal(err)
	}
	err = s.Compact()
	if rerr := tx.Rollback(); rerr != nil {
		t.Fatal(rerr)
	}
	if !errors.Is(err, ErrVaultBusy) {
		t.Errorf("Compact with a reader holding the log: err = %v, want ErrVaultBusy", err)
	}
}

// A reader that finishes while Compact waits doesn't stop it.
func TestCompact_WaitsForAReader(t *testing.T) {
	s := newTestStore(t)
	reader, err := sql.Open("sqlite", s.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(new(int)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		done <- tx.Rollback()
	}()
	if err := s.Compact(); err != nil {
		t.Errorf("Compact after the reader finished: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuditCountEstimate(t *testing.T) {
	s := newTestStore(t)
	if n, err := s.AuditCountEstimate(); err != nil || n != 0 {
		t.Fatalf("empty log = %d, %v", n, err)
	}
	day := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		addAuditAt(t, s, "access", "x", day.AddDate(0, 0, i))
	}
	if n, err := s.AuditCountEstimate(); err != nil || n != 5 {
		t.Errorf("5 events = %d, %v", n, err)
	}
	// Pruning removes the oldest, which are also the first written.
	if _, err := s.PruneAudit(day.AddDate(0, 0, 2)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.AuditCountEstimate(); err != nil || n != 3 {
		t.Errorf("after pruning 2 = %d, %v; want 3", n, err)
	}
}

func TestAuditCountEstimate_NoScan(t *testing.T) {
	s := newTestStore(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN SELECT COALESCE((SELECT MAX(id) FROM audit_log) - (SELECT MIN(id) FROM audit_log) + 1, 0)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}()
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(detail, "SCAN audit_log") {
			t.Errorf("query plan scans the table: %q", detail)
		}
	}
}
