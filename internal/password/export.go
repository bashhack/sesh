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
type ExportEntry struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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

// Export decrypts all matching entries and writes them to the given writer.
func (m *Manager) Export(w io.Writer, opts ExportOptions) (int, error) {
	filter := ListFilter{}
	if opts.EntryType != "" {
		filter.EntryType = opts.EntryType
	}

	entries, err := m.ListEntriesFiltered(filter)
	if err != nil {
		return 0, fmt.Errorf("failed to list entries: %w", err)
	}

	var exported []ExportEntry
	for i := range entries {
		e := &entries[i]
		secretBytes, err := m.GetPassword(e.Service, e.Username, e.Type)
		if err != nil {
			return 0, fmt.Errorf("failed to decrypt %s/%s: %w", e.Service, e.Username, err)
		}

		exported = append(exported, ExportEntry{
			Service:   e.Service,
			Username:  e.Username,
			Type:      e.Type,
			Secret:    string(secretBytes),
			CreatedAt: e.CreatedAt,
			UpdatedAt: e.UpdatedAt,
		})

		secure.SecureZeroBytes(secretBytes)
	}

	switch opts.Format {
	case FormatCSV:
		return len(exported), writeCSV(w, exported)
	default:
		return len(exported), writeJSON(w, exported)
	}
}

func writeJSON(w io.Writer, entries []ExportEntry) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func writeCSV(w io.Writer, entries []ExportEntry) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"service", "username", "type", "secret", "created_at", "updated_at"}); err != nil {
		return err
	}

	for _, e := range entries {
		if err := cw.Write([]string{
			e.Service,
			e.Username,
			string(e.Type),
			e.Secret,
			e.CreatedAt.Format(time.RFC3339),
			e.UpdatedAt.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
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
	case FormatCSV:
		var err error
		entries, err = readCSV(r)
		if err != nil {
			return ImportResult{}, fmt.Errorf("failed to read CSV: %w", err)
		}
	default:
		var err error
		entries, err = readJSON(r)
		if err != nil {
			return ImportResult{}, fmt.Errorf("failed to read JSON: %w", err)
		}
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

		if err := m.StorePasswordString(e.Service, e.Username, e.Secret, e.Type); err != nil {
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
