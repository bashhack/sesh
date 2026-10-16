// Package seshexport reads sesh's own password-encrypted exports, for
// sesh import.
package seshexport

import (
	"fmt"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/password"
)

// Entries are the export's entries as sesh import brings them in: each
// with its secret, details, folder, tags, settings and times. One sesh
// can't hold is skipped, saying why.
func Entries(list []password.ExportEntry) []*importer.Entry {
	out := make([]*importer.Entry, 0, len(list))
	for i := range list {
		ee := &list[i]
		name := ee.Service
		if ee.Username != "" {
			name += " (" + ee.Username + ")"
		}
		e := &importer.Entry{
			Key: ee.Key(), Name: name, Folder: ee.Folder, Tags: ee.Tags,
			Settings: ee.Settings, WholeSettings: true, Created: ee.CreatedAt, Updated: ee.UpdatedAt,
		}
		switch {
		case ee.Service == "":
			e.Skip = "it has no name"
		case ee.Secret == "":
			e.Skip = "it has no secret"
		case !ee.Type.Valid():
			e.Skip = fmt.Sprintf("its kind, %q, isn't one sesh has", ee.Type)
		default:
			secret, err := ee.SecretBytes()
			if err != nil {
				e.Skip = err.Error()
				break
			}
			e.Secret = secret
			e.Details = ee.Details()
		}
		out = append(out, importer.Checked(e))
	}
	return out
}
