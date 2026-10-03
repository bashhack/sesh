package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
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

// ClearAudit deletes every audit event, whatever its timestamp, and
// returns how many it deleted.
func (s *Store) ClearAudit() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_log`)
	if err != nil {
		return 0, fmt.Errorf("clear audit log: %w", err)
	}
	return res.RowsAffected()
}

// Path is the vault file the store opened.
func (s *Store) Path() string { return s.path }

// Size is the vault's size on disk in bytes: the database file and its
// write-ahead log.
func (s *Store) Size() (int64, error) {
	var total int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += fi.Size()
	}
	return total, nil
}

// ErrVaultBusy means another connection, such as another sesh command,
// was reading the vault for longer than Compact waits.
var ErrVaultBusy = errors.New("another sesh command was using the vault")

// compactWait is how long Compact waits for other readers of the vault to
// finish. Tests shorten it.
var compactWait = 5 * time.Second

// Compact rewrites the vault without the free space that deleted rows
// leave behind (SQLite keeps it for reuse rather than shrinking the file),
// then folds the write-ahead log back into the file. That last step needs
// every other reader to have finished; it waits up to compactWait for
// them, then returns ErrVaultBusy.
func (s *Store) Compact() error {
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("compact vault: %w", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA busy_timeout = %d`, compactWait.Milliseconds())); err != nil {
		return fmt.Errorf("compact vault: %w", err)
	}
	var busy, logFrames, checkpointed int
	err := s.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
	if _, rerr := s.db.Exec(`PRAGMA busy_timeout = 0`); err == nil {
		err = rerr
	}
	if err != nil {
		return fmt.Errorf("compact vault: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("compact vault: %w", ErrVaultBusy)
	}
	return nil
}
