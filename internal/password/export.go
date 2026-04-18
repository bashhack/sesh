package password

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/secure"
)

// ExportEntry is an entry with its decrypted secret, used for export/import.
// Timestamps are preserved through round-trip when the underlying store
// implements keychain.TimestampedStore (the SQLite backend does).
type ExportEntry struct {
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	Service   string    `json:"service"`
	Username  string    `json:"username,omitempty"`
	Type      EntryType `json:"type"`
	Secret    string    `json:"secret"`
}

// ExportFormat specifies the output format for export.
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
)

// ExportOptions controls what gets exported and how.
type ExportOptions struct {
	Format    ExportFormat
	EntryType EntryType // empty means all types
}

// Export decrypts entries and streams them to w, one at a time, so only
// one plaintext record is live in memory at a time. Returns the number of
// entries successfully written; a partial count + error is possible if a
// decrypt or write fails mid-stream (prior entries remain in the writer).
func (m *Manager) Export(w io.Writer, opts ExportOptions) (int, error) {
	filter := ListFilter{}
	if opts.EntryType != "" {
		filter.EntryType = opts.EntryType
	}

	entries, err := m.ListEntriesFiltered(filter)
	if err != nil {
		return 0, fmt.Errorf("failed to list entries: %w", err)
	}

	switch opts.Format {
	case "", FormatJSON:
		return m.exportJSON(w, entries)
	case FormatCSV:
		return m.exportCSV(w, entries)
	default:
		return 0, fmt.Errorf("unsupported export format %q (want json or csv)", opts.Format)
	}
}

// exportJSON writes entries as a JSON array, decrypting and marshaling one
// record at a time. The output matches what json.Encoder.Encode on a full
// slice would produce, but without holding every plaintext secret in
// memory simultaneously.
func (m *Manager) exportJSON(w io.Writer, entries []Entry) (int, error) {
	if _, err := io.WriteString(w, "["); err != nil {
		return 0, err
	}
	count := 0
	for i := range entries {
		e := &entries[i]
		secretBytes, err := m.GetPassword(e.Service, e.Username, e.Type)
		if err != nil {
			return count, fmt.Errorf("failed to decrypt %s/%s: %w", e.Service, e.Username, err)
		}

		sep := "\n  "
		if count > 0 {
			sep = ",\n  "
		}
		if _, err := io.WriteString(w, sep); err != nil {
			secure.SecureZeroBytes(secretBytes)
			return count, err
		}

		ee := ExportEntry{
			Service:   e.Service,
			Username:  e.Username,
			Type:      e.Type,
			Secret:    string(secretBytes),
			CreatedAt: e.CreatedAt,
			UpdatedAt: e.UpdatedAt,
		}
		// Source buffer can go immediately; the Secret string copy is
		// ephemeral per iteration and out of scope after this block.
		secure.SecureZeroBytes(secretBytes)

		b, err := json.MarshalIndent(ee, "  ", "  ")
		if err != nil {
			return count, err
		}
		_, writeErr := w.Write(b)
		secure.SecureZeroBytes(b)
		if writeErr != nil {
			return count, writeErr
		}
		count++
	}
	if count > 0 {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return count, err
		}
	}
	if _, err := io.WriteString(w, "]\n"); err != nil {
		return count, err
	}
	return count, nil
}

// exportCSV writes entries as CSV, one row at a time.
func (m *Manager) exportCSV(w io.Writer, entries []Entry) (int, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"service", "username", "type", "secret", "created_at", "updated_at"}); err != nil {
		return 0, err
	}

	count := 0
	for i := range entries {
		e := &entries[i]
		secretBytes, err := m.GetPassword(e.Service, e.Username, e.Type)
		if err != nil {
			cw.Flush()
			return count, fmt.Errorf("failed to decrypt %s/%s: %w", e.Service, e.Username, err)
		}

		writeErr := cw.Write([]string{
			e.Service,
			e.Username,
			string(e.Type),
			string(secretBytes),
			e.CreatedAt.Format(time.RFC3339),
			e.UpdatedAt.Format(time.RFC3339),
		})
		secure.SecureZeroBytes(secretBytes)
		if writeErr != nil {
			cw.Flush()
			return count, writeErr
		}
		count++
	}

	cw.Flush()
	return count, cw.Error()
}

// ConflictStrategy controls how import handles duplicate entries.
type ConflictStrategy string

const (
	ConflictSkip      ConflictStrategy = "skip"
	ConflictOverwrite ConflictStrategy = "overwrite"
)

// ImportOptions controls how entries are imported.
type ImportOptions struct {
	Format     ExportFormat
	OnConflict ConflictStrategy
}

// ImportResult reports what happened during import.
type ImportResult struct {
	Errors   []string
	Imported int
	Skipped  int
}

// Import reads entries from the given reader and stores them.
func (m *Manager) Import(r io.Reader, opts ImportOptions) (ImportResult, error) {
	var entries []ExportEntry

	switch opts.Format {
	case "", FormatJSON:
		var err error
		entries, err = readJSON(r)
		if err != nil {
			return ImportResult{}, fmt.Errorf("failed to read JSON: %w", err)
		}
	case FormatCSV:
		var err error
		entries, err = readCSV(r)
		if err != nil {
			return ImportResult{}, fmt.Errorf("failed to read CSV: %w", err)
		}
	default:
		return ImportResult{}, fmt.Errorf("unsupported import format %q (want json or csv)", opts.Format)
	}

	result := ImportResult{}

	for _, e := range entries {
		if e.Service == "" {
			result.Errors = append(result.Errors, "entry with empty service name, skipping")
			continue
		}
		if e.Secret == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: empty secret", e.Service, e.Username))
			continue
		}
		if !validEntryTypes[e.Type] {
			result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: invalid entry type %q", e.Service, e.Username, e.Type))
			continue
		}

		// Existence probe: only ErrNotFound means "safe to create".
		// Any other error is ambiguous — fail this entry rather than
		// risk an upsert that silently overwrites real data.
		_, err := m.GetPassword(e.Service, e.Username, e.Type)
		var exists bool
		switch {
		case err == nil:
			exists = true
		case errors.Is(err, keychain.ErrNotFound):
			exists = false
		default:
			result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: failed to check existence: %v", e.Service, e.Username, err))
			continue
		}

		if exists {
			switch opts.OnConflict {
			case ConflictSkip:
				result.Skipped++
				continue
			case ConflictOverwrite:
				// Fall through to store
			default:
				result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: already exists (use --on-conflict to resolve)", e.Service, e.Username))
				continue
			}
		}

		// Pass timestamps through so backends that support them (SQLite)
		// preserve original audit history on round-trip. Zero values are
		// treated as "use now" by the option.
		if err := m.StorePasswordString(e.Service, e.Username, e.Secret, e.Type, WithTimestamps(e.CreatedAt, e.UpdatedAt)); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %v", e.Service, e.Username, err))
			continue
		}
		result.Imported++
	}

	return result, nil
}

func readJSON(r io.Reader) ([]ExportEntry, error) {
	var entries []ExportEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func readCSV(r io.Reader) ([]ExportEntry, error) {
	cr := csv.NewReader(r)

	// Read header
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Build column index
	idx := make(map[string]int, len(header))
	for i, col := range header {
		idx[strings.TrimSpace(strings.ToLower(col))] = i
	}

	// Verify required columns
	for _, required := range []string{"service", "type", "secret"} {
		if _, ok := idx[required]; !ok {
			return nil, fmt.Errorf("missing required CSV column: %s", required)
		}
	}

	var entries []ExportEntry
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV row: %w", err)
		}

		e := ExportEntry{
			Service: record[idx["service"]],
			Type:    EntryType(record[idx["type"]]),
			Secret:  record[idx["secret"]],
		}
		if i, ok := idx["username"]; ok && i < len(record) {
			e.Username = record[i]
		}
		if i, ok := idx["created_at"]; ok && i < len(record) {
			if t, err := time.Parse(time.RFC3339, record[i]); err == nil {
				e.CreatedAt = t
			}
		}
		if i, ok := idx["updated_at"]; ok && i < len(record) {
			if t, err := time.Parse(time.RFC3339, record[i]); err == nil {
				e.UpdatedAt = t
			}
		}

		entries = append(entries, e)
	}

	return entries, nil
}
