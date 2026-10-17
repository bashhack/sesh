// Package lpauth reads LastPass Authenticator's account export: a JSON
// file, made in the app's Settings, under Transfer accounts. It holds each
// account's TOTP key unencrypted, with its name and code settings.
//
// The format is as Bitwarden's open-source importers read it
// (bitwarden/android LastPassJsonExport, bitwarden/ios LastpassImporter),
// checked against a real export.
package lpauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Export is the export file.
type Export struct {
	DeviceName string    `json:"deviceName"`
	Accounts   []Account `json:"accounts"`
	Folders    []Folder  `json:"folders"`
	Version    int       `json:"version"`
}

// Account is one account in the app. IssuerName and UserName are as the
// app shows them; the Original ones as the account was added, before any
// renaming in the app.
type Account struct {
	FolderData         *FolderData `json:"folderData"`
	IssuerName         string      `json:"issuerName"`
	OriginalIssuerName string      `json:"originalIssuerName"`
	UserName           string      `json:"userName"`
	OriginalUserName   string      `json:"originalUserName"`
	Secret             string      `json:"secret"`
	Algorithm          string      `json:"algorithm"`
	CreationTimestamp  int64       `json:"creationTimestamp"` // Unix seconds
	Digits             int         `json:"digits"`
	TimeStep           int         `json:"timeStep"`
	IsFavorite         bool        `json:"isFavorite"`
}

// FolderData is the folder an account is in.
type FolderData struct {
	FolderID FolderID `json:"folderId"`
}

// FolderID is a folder's id: a number, or (in Bitwarden's Android model of
// the export) a number in a string. One that's neither is -1, no folder,
// so it costs the account its folder, not the import.
type FolderID int

// UnmarshalJSON reads a number, or a number in a string (json.Number
// takes both).
func (f *FolderID) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		if i, err := n.Int64(); err == nil {
			*f = FolderID(i)
			return nil
		}
	}
	*f = -1
	return nil
}

// Folder is a folder in the app. Favorites and Other Accounts are the
// app's own.
type Folder struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// IsExport says whether b is a LastPass Authenticator export: a JSON
// object whose accounts list has at least one account, each with a secret
// and a timeStep. The keys aren't read into strings to tell.
func IsExport(b []byte) bool {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' || !bytes.Contains(b, []byte(`"accounts"`)) || !bytes.Contains(b, []byte(`"timeStep"`)) {
		return false
	}
	var probe struct {
		Accounts []struct {
			Secret   *json.RawMessage `json:"secret"`
			TimeStep *json.RawMessage `json:"timeStep"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(b, &probe); err != nil || len(probe.Accounts) == 0 {
		return false
	}
	for _, a := range probe.Accounts {
		if a.Secret == nil || a.TimeStep == nil {
			return false
		}
	}
	return true
}

// Parse reads an export.
func Parse(b []byte) (Export, error) {
	var e Export
	if err := json.Unmarshal(b, &e); err != nil {
		return Export{}, fmt.Errorf("this isn't a LastPass Authenticator export (JSON): %w", err)
	}
	if e.Accounts == nil {
		return Export{}, errors.New("this isn't a LastPass Authenticator export: it has no accounts list")
	}
	return e, nil
}

// builtinFolders are the app's own folders, which aren't folders in sesh:
// Other Accounts (id 0) and Favorites (id 1), by id or, in case, by name.
var builtinFolders = map[string]bool{"Favorites": true, "Other Accounts": true}

// builtin says whether f is one of the app's own folders.
func builtin(f Folder) bool {
	return f.ID == 0 || f.ID == 1 || builtinFolders[f.Name]
}

// Entries are the export's accounts as TOTP entries: named by the issuer
// and account as the app shows them (or as they were added, when those
// are empty), the issuer alone, or the account alone when there's no
// issuer; with their code settings and when they were added; in a folder
// of the user's own, if they're in one; and tagged favorite if they are.
// The same account twice is skipped; two with one name and different
// keys get " (2)".
func Entries(e *Export) []*importer.Entry {
	// The app's folders are flat, so a "/" in one's name, which in sesh
	// would mean a folder inside a folder, becomes "-".
	folders := map[FolderID]string{}
	folderChanges := map[FolderID]string{}
	for _, f := range e.Folders {
		if builtin(f) {
			continue
		}
		fitted := importer.FitFolder(strings.ReplaceAll(f.Name, "/", "-"))
		folders[FolderID(f.ID)] = fitted
		switch {
		case fitted == "":
			folderChanges[FolderID(f.ID)] = fmt.Sprintf("folder %q not kept: nothing of it fits sesh's rules", f.Name)
		case fitted != f.Name:
			folderChanges[FolderID(f.ID)] = fmt.Sprintf("folder %q is %q in sesh", f.Name, fitted)
		}
	}
	names := importer.NewNames()
	seen := map[vault.Key]map[string]bool{} // each key's secrets, normalized
	var out []*importer.Entry
	for i := range e.Accounts {
		a := &e.Accounts[i]
		k, params, secret, skip := a.entry()
		ent := &importer.Entry{Key: k, Name: a.label(), Skip: skip, Settings: vault.Settings{TOTP: params}}
		if skip == "" && seen[k][secret] {
			ent.Skip = "the same account twice"
		}
		if ent.Skip == "" {
			if seen[k] == nil {
				seen[k] = map[string]bool{}
			}
			seen[k][secret] = true
			ent.Secret = []byte(secret)
			ent.Changes = a.nameChanges(k)
			if a.CreationTimestamp > 0 {
				ent.Created = time.Unix(a.CreationTimestamp, 0)
			}
			if a.FolderData != nil {
				ent.Folder = folders[a.FolderData.FolderID]
				if c := folderChanges[a.FolderData.FolderID]; c != "" {
					ent.Changes = append(ent.Changes, c)
				}
			}
			if a.IsFavorite {
				ent.Tags = []string{"favorite"}
			}
			importer.Place([]*importer.Entry{ent}, names)
		}
		out = append(out, ent)
	}
	return out
}

// names is the account's issuer and account name, as the app shows them,
// or as they were added when those are empty.
func (a *Account) names() (issuer, user string) {
	issuer, user = strings.TrimSpace(a.IssuerName), strings.TrimSpace(a.UserName)
	if issuer == "" {
		issuer = strings.TrimSpace(a.OriginalIssuerName)
	}
	if user == "" {
		user = strings.TrimSpace(a.OriginalUserName)
	}
	return issuer, user
}

// nameChanges says how k's names differ from the account's, when fitting
// them to sesh's rules changed them.
func (a *Account) nameChanges(k vault.Key) []string {
	issuer, user := a.names()
	if issuer == "" {
		issuer, user = user, ""
	}
	var out []string
	if k.Service != issuer {
		out = append(out, fmt.Sprintf("named %q in sesh", k.Service))
	}
	if k.Username != user {
		out = append(out, fmt.Sprintf("username %q in sesh", k.Username))
	}
	return out
}

// label is how the summary names the account: "issuer: account".
func (a *Account) label() string {
	issuer, user := a.names()
	switch {
	case issuer == "":
		return user
	case user == "":
		return issuer
	}
	return issuer + ": " + user
}

// entry is the account's key in sesh, its code settings, its secret
// normalized, or why it can't be imported.
func (a *Account) entry() (k vault.Key, params totp.Params, secret, skip string) {
	switch strings.ToUpper(a.Algorithm) {
	case "SHA1", "":
	case "SHA256", "SHA512":
		params.Algorithm = strings.ToUpper(a.Algorithm)
	default:
		return k, params, "", "uses " + a.Algorithm + ", which sesh doesn't support"
	}
	switch {
	case a.Digits == 0 || a.Digits == 6:
	case a.Digits >= 7 && a.Digits <= 8:
		params.Digits = a.Digits
	default:
		return k, totp.Params{}, "", fmt.Sprintf("makes %d-digit codes, which sesh doesn't", a.Digits)
	}
	switch {
	case a.TimeStep == 0 || a.TimeStep == 30:
	case a.TimeStep > 0 && a.TimeStep <= totp.MaxTOTPPeriodSeconds:
		params.Period = a.TimeStep
	default:
		return k, totp.Params{}, "", fmt.Sprintf("a new code every %d seconds, which sesh doesn't make", a.TimeStep)
	}
	issuer, user := a.names()
	service, user := importer.FitName(issuer), importer.FitName(user)
	if service == "" {
		service, user = user, ""
	}
	if service == "" {
		return k, totp.Params{}, "", "has no name"
	}
	params.Issuer = issuer
	k = vault.Key{Kind: vault.KindTOTP, Service: service, Username: user}
	if err := k.Validate(); err != nil {
		return vault.Key{}, totp.Params{}, "", err.Error()
	}
	// The reason never quotes the key: the summary is shown on screen.
	secret, err := totp.ValidateAndNormalizeSecret(a.Secret)
	switch {
	case err != nil && strings.Contains(err.Error(), "too short"):
		return vault.Key{}, totp.Params{}, "", "the key is too short to be safe"
	case err != nil:
		return vault.Key{}, totp.Params{}, "", "the key isn't a valid base32 key"
	}
	return k, params, secret, ""
}
