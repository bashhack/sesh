package database

import (
	"database/sql"
	"fmt"
	"time"
)

// migrateV3 indexes the audit log by time, so pruning old events on every
// open doesn't scan the whole table.
func migrateV3(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)`); err != nil {
		return fmt.Errorf("migration v3: %w", err)
	}
	return nil
}

// AuditEvents returns the newest limit audit events, newest first; limit 0
// returns them all.
func (s *Store) AuditEvents(limit int) (_ []AuditEntry, err error) {
	q := `SELECT id, event_type, COALESCE(entry_id, ''), COALESCE(detail, ''), created_at FROM audit_log ORDER BY id DESC`
	args := []any{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	var events []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.EventType, &e.EntryID, &e.Detail, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("read audit log: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// AuditSummary returns how many events the audit log holds and when the
// oldest was written (zero when it's empty).
func (s *Store) AuditSummary() (count int64, oldest time.Time, err error) {
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&count); err != nil {
		return 0, time.Time{}, fmt.Errorf("read audit log: %w", err)
	}
	if count == 0 {
		return 0, time.Time{}, nil
	}
	if err := s.db.QueryRow(`SELECT created_at FROM audit_log ORDER BY created_at LIMIT 1`).Scan(&oldest); err != nil {
		return 0, time.Time{}, fmt.Errorf("read audit log: %w", err)
	}
	return count, oldest, nil
}

// PruneAudit deletes the audit events written before before and returns
// how many it deleted.
func (s *Store) PruneAudit(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE created_at < ?`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune audit log: %w", err)
	}
	return res.RowsAffected()
}
