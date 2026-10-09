// Package bitwarden reads Bitwarden's JSON exports: the plain one, and the
// one protected by a password of its own. The format follows Bitwarden's
// own code (github.com/bitwarden/clients, libs/tools/export-vault-core and
// libs/common/src/models/export), and is tested against exports made by
// Bitwarden's CLI.
package bitwarden

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Item types, as Bitwarden numbers them (cipher-type.ts).
const (
	TypeLogin          = 1
	TypeSecureNote     = 2
	TypeCard           = 3
	TypeIdentity       = 4
	TypeSSHKey         = 5
	TypeBankAccount    = 6
	TypeDriversLicense = 7
	TypePassport       = 8
)

// Custom field types (field-type.enum.ts).
const (
	FieldText    = 0
	FieldHidden  = 1
	FieldBoolean = 2
	FieldLinked  = 3
)

// Export is a Bitwarden export's folders and items.
type Export struct {
	Folders []Folder `json:"folders"`
	Items   []Item   `json:"items"`
}

// Folder is a folder; nesting is written into its name with "/".
type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Item is one item. Bitwarden leaves out what's empty, so every part may be
// missing.
type Item struct {
	CreationDate    time.Time         `json:"creationDate"`
	RevisionDate    time.Time         `json:"revisionDate"`
	Login           *Login            `json:"login"`
	Card            *Card             `json:"card"`
	Identity        *Identity         `json:"identity"`
	SSHKey          *SSHKey           `json:"sshKey"`
	ID              string            `json:"id"`
	FolderID        string            `json:"folderId"`
	Name            string            `json:"name"`
	Notes           string            `json:"notes"`
	Fields          []Field           `json:"fields"`
	PasswordHistory []json.RawMessage `json:"passwordHistory"`
	Type            int               `json:"type"`
	Reprompt        int               `json:"reprompt"`
	Favorite        bool              `json:"favorite"`
}

// Login is a login item's own part.
type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// TOTP is a base32 key, an otpauth:// URI, or a steam:// key.
	TOTP             string            `json:"totp"`
	URIs             []URI             `json:"uris"`
	Fido2Credentials []json.RawMessage `json:"fido2Credentials"`
}

// URI is one of a login's web addresses.
type URI struct {
	URI string `json:"uri"`
}

// Field is a custom field; a linked one has no value.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"`
}

// Card is a card item's own part.
type Card struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

// Identity is an identity item's own part.
type Identity struct {
	Title          string `json:"title"`
	FirstName      string `json:"firstName"`
	MiddleName     string `json:"middleName"`
	LastName       string `json:"lastName"`
	Address1       string `json:"address1"`
	Address2       string `json:"address2"`
	Address3       string `json:"address3"`
	City           string `json:"city"`
	State          string `json:"state"`
	PostalCode     string `json:"postalCode"`
	Country        string `json:"country"`
	Company        string `json:"company"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	SSN            string `json:"ssn"`
	Username       string `json:"username"`
	PassportNumber string `json:"passportNumber"`
	LicenseNumber  string `json:"licenseNumber"`
}

// SSHKey is an SSH key item's own part.
type SSHKey struct {
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

// envelope is the outside of any export, to tell which kind it is.
type envelope struct {
	Encrypted         *bool             `json:"encrypted"`
	Salt              string            `json:"salt"`
	Validation        string            `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string            `json:"data"`
	Collections       []json.RawMessage `json:"collections"`
	KDFType           int               `json:"kdfType"`
	KDFIterations     int               `json:"kdfIterations"`
	KDFMemory         int               `json:"kdfMemory"`
	KDFParallelism    int               `json:"kdfParallelism"`
	PasswordProtected bool              `json:"passwordProtected"`
}

// ErrAccountRestricted is an export only the Bitwarden account that made it
// can open.
var ErrAccountRestricted = errors.New("this Bitwarden export is account restricted: only the Bitwarden account that made it can open it. Export again with a password of its own (Export vault, then File password protected), or as plain JSON")

// IsExport reports whether b looks like a Bitwarden JSON export.
func IsExport(b []byte) bool {
	var e struct {
		PP    *bool           `json:"passwordProtected"`
		Data  string          `json:"data"`
		Items json.RawMessage `json:"items"`
	}
	return json.Unmarshal(b, &e) == nil && (e.Items != nil || (e.PP != nil && e.Data != ""))
}

// Parse reads a Bitwarden JSON export. A password-protected one is opened
// with the password password returns, asked only then.
func Parse(b []byte, password func() ([]byte, error)) (Export, error) {
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return Export{}, fmt.Errorf("this isn't a Bitwarden JSON export: %w", err)
	}
	if env.Encrypted != nil && *env.Encrypted {
		if !env.PasswordProtected {
			return Export{}, ErrAccountRestricted
		}
		pw, err := password()
		if err != nil {
			return Export{}, err
		}
		plain, err := decrypt(&env, pw)
		if err != nil {
			return Export{}, err
		}
		b = plain
	}
	if env.Collections != nil {
		return Export{}, errors.New("this is an organization's Bitwarden export; sesh imports a personal vault's export (Export vault, from your own vault)")
	}
	var exp Export
	if err := json.Unmarshal(b, &exp); err != nil {
		return Export{}, fmt.Errorf("this isn't a Bitwarden JSON export: %w", err)
	}
	if exp.Items == nil {
		return Export{}, errors.New("this isn't a Bitwarden JSON export: it has no items list")
	}
	return exp, nil
}
