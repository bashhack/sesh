// Package seshexport reads sesh's own password-encrypted exports, for
// sesh import.
package seshexport

import (
	"fmt"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Entries are the export's entries as sesh import brings them in: each
// with its secret, details, earlier secrets, folder, tags, settings and
// times. One sesh can't hold is skipped, saying why.
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
			earlier, err := ee.Earlier()
			if err != nil {
				secure.SecureZeroBytes(secret)
				e.Skip = err.Error()
				break
			}
			// An earlier version's file name is held to the rule a file's
			// name is: one sesh refuses is left out, its content kept.
			for i := range earlier {
				if earlier[i].FileName != "" && vault.CheckFileName(earlier[i].FileName) != nil {
					earlier[i].FileName = ""
					e.Changes = append(e.Changes, "an earlier version's file name, which isn't one sesh takes, left out")
				}
			}
			e.Secret = secret
			e.Earlier = earlier
			e.Details = ee.Details()
		}
		out = append(out, importer.Checked(e))
	}
	return out
}
