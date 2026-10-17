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
	FolderID int `json:"folderId"`
}

// Folder is a folder in the app. Favorites and Other Accounts are the
// app's own.
type Folder struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// IsExport says whether b is a LastPass Authenticator export: JSON with
// accounts that have a secret and a timeStep.
func IsExport(b []byte) bool {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' || !bytes.Contains(b, []byte(`"accounts"`)) || !bytes.Contains(b, []byte(`"timeStep"`)) {
		return false
	}
	_, err := Parse(b)
	return err == nil
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

// builtinFolders are the app's own folders, which aren't folders in sesh.
var builtinFolders = map[string]bool{"Favorites": true, "Other Accounts": true}

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
	folders := map[int]string{}
	for _, f := range e.Folders {
		if !builtinFolders[f.Name] {
			folders[f.ID] = importer.FitFolder(strings.ReplaceAll(f.Name, "/", "-"))
		}
	}
	names := importer.NewNames()
	seen := map[vault.Key]string{} // each key's secret, as given
	var out []*importer.Entry
	for i := range e.Accounts {
		a := &e.Accounts[i]
		k, params, secret, skip := a.entry()
		ent := &importer.Entry{Key: k, Name: a.label(), Skip: skip, Settings: vault.Settings{TOTP: params}}
		if skip == "" && seen[k] == a.Secret {
			ent.Skip = "the same account twice"
		}
		if ent.Skip == "" {
			seen[k] = a.Secret
			ent.Secret = []byte(secret)
			if a.CreationTimestamp > 0 {
				ent.Created = time.Unix(a.CreationTimestamp, 0)
			}
			if a.FolderData != nil {
				ent.Folder = folders[a.FolderData.FolderID]
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
	secret, err := totp.ValidateAndNormalizeSecret(a.Secret)
	if err != nil {
		return vault.Key{}, totp.Params{}, "", "the secret can't be used: " + err.Error()
	}
	return k, params, secret, ""
}
