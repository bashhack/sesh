package bitwarden

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// IsOrganizationCSV reports whether b looks like an organization's CSV
// export, which has collections where a personal vault's has folders.
func IsOrganizationCSV(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimPrefix(b, []byte("\ufeff")), []byte("collections,type,name,"))
}

// parseCSV reads Bitwarden's CSV export of a personal vault, as Bitwarden
// writes it (libs/tools/export-vault-core, buildCsvExport and
// buildCommonCipher) and reads it back (libs/importer, BitwardenCsvImporter):
// logins and secure notes only, with no dates or password history. Its
// custom fields are "name: value" lines (see csvFields). Its URIs are
// joined by commas, unquoted (JavaScript's Array.toString).
func parseCSV(b []byte) (Export, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b, []byte("\ufeff"))))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return Export{}, fmt.Errorf("this Bitwarden CSV export can't be read: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	for _, need := range []string{"type", "name"} {
		if _, ok := col[need]; !ok {
			return Export{}, fmt.Errorf("this isn't a Bitwarden CSV export: it has no %q column", need)
		}
	}
	exp := Export{Items: []Item{}}
	folderIDs := map[string]string{}
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Export{}, fmt.Errorf("this Bitwarden CSV export can't be read: %w", err)
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(row) {
				return row[i]
			}
			return ""
		}
		it := Item{Name: get("name"), Notes: get("notes"), Fields: csvFields(get("fields"))}
		it.Favorite = get("favorite") != "" && get("favorite") != "0"
		if n, err := strconv.Atoi(get("reprompt")); err == nil {
			it.Reprompt = n
		}
		if s := get("archivedDate"); s != "" {
			if at, err := time.Parse(time.RFC3339, s); err == nil {
				it.ArchivedDate = &at
			}
		}
		if f := get("folder"); f != "" {
			id, ok := folderIDs[f]
			if !ok {
				id = "csv-folder-" + strconv.Itoa(len(folderIDs)+1)
				folderIDs[f] = id
				exp.Folders = append(exp.Folders, Folder{ID: id, Name: f})
			}
			it.FolderID = id
		}
		// A type Bitwarden doesn't know is read as a login, as it reads it.
		if strings.EqualFold(get("type"), "note") {
			it.Type = TypeSecureNote
		} else {
			it.Type = TypeLogin
			it.Login = &Login{Username: get("login_username"), Password: get("login_password"), TOTP: get("login_totp"), URIs: csvURIs(get("login_uri"))}
		}
		exp.Items = append(exp.Items, it)
	}
	return exp, nil
}

// csvFields reads a CSV export's custom fields: "name: value" lines.
//   - The CSV doesn't say which were hidden: each is kept as a hidden
//     one, so nothing private ends up stored readable.
//   - A line is split at its first ": " (Bitwarden's reader takes the
//     last): field names are stored readable, so a ": " in a value stays
//     in the value, kept secret; one in a name moves the rest of the name
//     there.
//   - A field with no value (a linked one, or an empty one) is written
//     "undefined", or "null" by older clients: it comes in empty, which
//     the summary says isn't kept.
//   - A line with no ": " goes on the value before it, as Bitwarden
//     writes each field on one line and a value's line break as it is.
func csvFields(s string) []Field {
	var out []Field
	for line := range strings.SplitSeq(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		name, value, ok := strings.Cut(line, ": ")
		switch {
		case !ok && len(out) > 0:
			out[len(out)-1].Value += "\n" + line
			continue
		case !ok:
			continue
		}
		if value == "undefined" || value == "null" {
			value = ""
		}
		out = append(out, Field{Name: name, Value: value, Type: FieldHidden})
	}
	return out
}

// csvURIs reads a CSV export's URIs, joined by commas: a URI with a
// comma in it comes in as two.
func csvURIs(s string) []URI {
	var out []URI
	for c := range strings.SplitSeq(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, URI{URI: c})
		}
	}
	return out
}
