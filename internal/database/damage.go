package database

import (
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// damageError is an error that shows the vault file is damaged.
type damageError struct{ err error }

func (e *damageError) Error() string { return e.err.Error() }
func (e *damageError) Unwrap() error { return e.err }

// damaged marks err as showing the vault file is damaged.
func damaged(err error) error { return &damageError{err} }

// IsDamaged reports whether err shows the vault file is damaged: SQLite
// finding it corrupt or not a database, or a key record that fails its
// checks.
func IsDamaged(err error) bool {
	if d, ok := errors.AsType[*damageError](err); ok && d != nil {
		return true
	}
	if se, ok := errors.AsType[*sqlite.Error](err); ok {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
			return true
		}
	}
	return false
}
