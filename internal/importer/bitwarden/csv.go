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
// custom fields are "name: value" lines, split at the last ": ", and
// don't say which were hidden: each is kept as a hidden one, so nothing
// private ends up stored readable. A linked one is written as the word
// "undefined". Its URIs are one CSV row of their own.
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
	for line := 2; ; line++ {
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
			uris, err := csvURIs(get("login_uri"))
			if err != nil {
				return Export{}, fmt.Errorf("line %d of this Bitwarden CSV export: its URIs can't be read: %w", line, err)
			}
			it.Login = &Login{Username: get("login_username"), Password: get("login_password"), TOTP: get("login_totp"), URIs: uris}
		}
		exp.Items = append(exp.Items, it)
	}
	return exp, nil
}

// csvFields reads a CSV export's custom fields: "name: value" lines.
func csvFields(s string) []Field {
	var out []Field
	for line := range strings.SplitSeq(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		name, value, ok := strings.CutLast(line, ": ")
		if strings.TrimSpace(line) == "" || !ok {
			continue
		}
		f := Field{Name: name, Value: value, Type: FieldHidden}
		if f.Value == "undefined" {
			// A linked field: it has no value of its own.
			f.Type, f.Value = FieldLinked, ""
		}
		out = append(out, f)
	}
	return out
}

// csvURIs reads a CSV export's URIs: one CSV row, a URI a cell.
func csvURIs(s string) ([]URI, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	cells, err := csv.NewReader(strings.NewReader(s)).Read()
	if err != nil {
		return nil, err
	}
	var out []URI
	for _, c := range cells {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, URI{URI: c})
		}
	}
	return out, nil
}
