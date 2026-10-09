package password

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// ExportEntry is an entry with its decrypted secret, used for export and
// import. Everything about the entry round-trips: its settings (a TOTP
// entry's code settings decide which codes are right) and its times.
type ExportEntry struct {
	CreatedAt time.Time      `json:"created_at,omitzero"`
	UpdatedAt time.Time      `json:"updated_at,omitzero"`
	Service   string         `json:"service"`
	Username  string         `json:"username,omitempty"`
	Type      EntryType      `json:"type"`
	Secret    string         `json:"secret"`
	Folder    string         `json:"folder,omitempty"`
	URL       string         `json:"url,omitempty"`
	Notes     string         `json:"notes,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Fields    []ExportField  `json:"fields,omitempty"`
	Settings  vault.Settings `json:"settings,omitzero"`
}

// ExportField is a custom field as an export holds it, secret or not.
type ExportField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Secret bool   `json:"secret,omitempty"`
}

// exportDetails reads e's details for an export: from e when they're all
// readable, or opened from the store when there are notes or secret
// values.
func (m *Manager) exportDetails(e *vault.Entry, ee *ExportEntry) error {
	d := vault.Details{URL: e.URL, Fields: e.Fields}
	if e.HasNotes || slices.ContainsFunc(e.Fields, func(f vault.Field) bool { return f.Secret }) {
		var err error
		if d, err = m.store.Details(e.Key, "all, to export"); err != nil {
			return fmt.Errorf("failed to decrypt the details of %s: %w", e.Key, err)
		}
		defer d.Zero()
	}
	ee.URL, ee.Notes = d.URL, string(d.Notes)
	for _, f := range d.Fields {
		ee.Fields = append(ee.Fields, ExportField{Name: f.Name, Value: string(f.Value), Secret: f.Secret})
	}
	return nil
}

// importDetails is ee's details as the store takes them; the caller zeroes
// them.
func importDetails(ee *ExportEntry) vault.Details {
	d := vault.Details{URL: ee.URL}
	if ee.Notes != "" {
		d.Notes = []byte(ee.Notes)
	}
	for _, f := range ee.Fields {
		d.Fields = append(d.Fields, vault.Field{Name: f.Name, Value: []byte(f.Value), Secret: f.Secret})
	}
	return d
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
	// Folder, when FolderSet, keeps the entries in it or a folder under
	// it ("" keeps those in none); Tags keeps those with all of them.
	Folder    string
	Tags      []string
	FolderSet bool
	// KDF is the Argon2id settings an encrypted export's password is
	// stretched with; zero means kdf.Default().
	KDF kdf.Params
}

// Export decrypts entries and streams them to w, one at a time, so only
// one plaintext record is live in memory at a time. Returns the number of
// entries successfully written; a partial count + error is possible if a
// decrypt or write fails mid-stream (prior entries remain in the writer).
func (m *Manager) Export(w io.Writer, opts *ExportOptions) (int, error) {
	entries, err := m.store.List(&vault.Filter{Kind: opts.EntryType, Folder: opts.Folder, FolderSet: opts.FolderSet, Tags: opts.Tags})
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
func (m *Manager) exportJSON(w io.Writer, entries []vault.Entry) (int, error) {
	if _, err := io.WriteString(w, "["); err != nil {
		return 0, err
	}
	count := 0
	for i := range entries {
		e := &entries[i]
		secretBytes, err := m.store.Get(e.Key)
		if err != nil {
			return count, fmt.Errorf("failed to decrypt %s: %w", e.Key, err)
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
			Type:      e.Kind,
			Secret:    string(secretBytes),
			Folder:    e.Folder,
			Tags:      e.Tags,
			Settings:  e.Settings,
			CreatedAt: e.CreatedAt,
			UpdatedAt: e.UpdatedAt,
		}
		// Source buffer can go immediately; the Secret string copy is
		// ephemeral per iteration and out of scope after this block.
		secure.SecureZeroBytes(secretBytes)
		if err := m.exportDetails(e, &ee); err != nil {
			return count, err
		}

		b, err := json.MarshalIndent(ee, "  ", "  ") //nolint:gosec // plaintext export writes secrets by design; --format encrypted is the protected alternative
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

// exportCSV writes entries as CSV, one row at a time. The settings column
// holds an entry's settings as JSON, empty when it has none; the tags
// column, its tags joined by ";", which a tag can't contain; the fields
// column, its custom fields as JSON, as the JSON export has them.
func (m *Manager) exportCSV(w io.Writer, entries []vault.Entry) (int, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"service", "username", "type", "secret", "created_at", "updated_at", "settings", "folder", "tags", "url", "notes", "fields"}); err != nil {
		return 0, err
	}

	count := 0
	for i := range entries {
		e := &entries[i]
		settings := ""
		if !e.Settings.IsZero() {
			b, err := json.Marshal(e.Settings)
			if err != nil {
				cw.Flush()
				return count, fmt.Errorf("encode the settings of %s: %w", e.Key, err)
			}
			settings = string(b)
		}
		var ee ExportEntry
		if err := m.exportDetails(e, &ee); err != nil {
			cw.Flush()
			return count, err
		}
		fields := ""
		if len(ee.Fields) > 0 {
			b, err := json.Marshal(ee.Fields)
			if err != nil {
				cw.Flush()
				return count, fmt.Errorf("encode the fields of %s: %w", e.Key, err)
			}
			fields = string(b)
		}
		secretBytes, err := m.store.Get(e.Key)
		if err != nil {
			cw.Flush()
			return count, fmt.Errorf("failed to decrypt %s: %w", e.Key, err)
		}

		writeErr := cw.Write([]string{
			e.Service,
			e.Username,
			string(e.Kind),
			string(secretBytes),
			e.CreatedAt.Format(time.RFC3339),
			e.UpdatedAt.Format(time.RFC3339),
			settings,
			e.Folder,
			strings.Join(e.Tags, ";"),
			ee.URL,
			ee.Notes,
			fields,
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

	for i := range entries {
		e := &entries[i]
		if e.Service == "" {
			result.Errors = append(result.Errors, "entry with empty service name, skipping")
			continue
		}
		if e.Secret == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: empty secret", importName(e)))
			continue
		}
		if !e.Type.Valid() {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid entry type %q", importName(e), e.Type))
			continue
		}

		// Existence probe: only ErrNotFound means "safe to create".
		// Any other error is ambiguous — fail this entry rather than
		// risk an upsert that silently overwrites real data.
		k := key(e.Service, e.Username, e.Type)
		if err := k.Validate(); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", importName(e), err))
			continue
		}
		err := m.store.Exists(k)
		var exists bool
		switch {
		case err == nil:
			exists = true
		case errors.Is(err, vault.ErrNotFound):
			exists = false
		default:
			result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to check existence: %v", importName(e), err))
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
				result.Errors = append(result.Errors, fmt.Sprintf("%s: already exists (use --on-conflict to resolve)", importName(e)))
				continue
			}
		}

		// The details are checked first, so an entry that can't have them
		// isn't imported without them.
		details := importDetails(e)
		if err := details.Check(k.Kind); err != nil {
			details.Zero()
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", importName(e), err))
			continue
		}
		// The entry keeps its settings, folder, tags, times, and details,
		// written together; a zero time means now. An entry it replaces
		// gets the file's details, none included.
		secret := []byte(e.Secret)
		err = m.store.SaveWithDetails(&vault.Entry{Key: k, Settings: e.Settings, Folder: e.Folder, Tags: e.Tags, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt}, secret, &details)
		secure.SecureZeroBytes(secret)
		details.Zero()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", importName(e), err))
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
		if i, ok := idx["settings"]; ok && i < len(record) && record[i] != "" {
			if err := json.Unmarshal([]byte(record[i]), &e.Settings); err != nil {
				return nil, fmt.Errorf("the settings of %s/%s aren't valid JSON: %w", e.Service, e.Username, err)
			}
		}

		if i, ok := idx["folder"]; ok && i < len(record) {
			e.Folder = record[i]
		}
		if i, ok := idx["url"]; ok && i < len(record) {
			e.URL = record[i]
		}
		if i, ok := idx["notes"]; ok && i < len(record) {
			e.Notes = record[i]
		}
		if i, ok := idx["fields"]; ok && i < len(record) && record[i] != "" {
			if err := json.Unmarshal([]byte(record[i]), &e.Fields); err != nil {
				return nil, fmt.Errorf("the fields of %s/%s aren't valid JSON: %w", e.Service, e.Username, err)
			}
		}
		if i, ok := idx["tags"]; ok && i < len(record) {
			// Spaces around a tag and empty ones, as hand editing leaves.
			for t := range strings.SplitSeq(record[i], ";") {
				if t = strings.TrimSpace(t); t != "" {
					e.Tags = append(e.Tags, t)
				}
			}
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// importName names an imported entry in a report the way --list does,
// quoted so a stray space shows: "github", or "github" ("alice").
func importName(e *ExportEntry) string {
	if e.Username == "" {
		return fmt.Sprintf("%q", e.Service)
	}
	return fmt.Sprintf("%q (%q)", e.Service, e.Username)
}
