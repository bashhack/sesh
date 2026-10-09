package bitwarden

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Entries is the sesh entries an export's items become, in order:
//   - a login is a password entry, with its URL, notes and custom fields,
//     and its TOTP key a TOTP entry beside it;
//   - a secure note is a secure note;
//   - a card, identity, or SSH key is a secure note, its notes (or a line
//     saying what it is) the note, its numbers and keys secret fields and
//     the rest plain ones.
//
// Folders and field names are fitted to sesh's rules, a favorite gets the
// tag "favorite", and two items with one name get " (2)" on the second.
// What can't come across, or changed on the way, is said in each entry.
func Entries(exp *Export) []*importer.Entry {
	folders := map[string]string{}
	folderChanges := map[string]string{}
	for _, f := range exp.Folders {
		fitted := importer.FitFolder(f.Name)
		folders[f.ID] = fitted
		if fitted != strings.Trim(f.Name, "/") {
			folderChanges[f.ID] = fmt.Sprintf("folder %q is %q in sesh", f.Name, fitted)
		}
	}
	var out []*importer.Entry
	taken := map[vault.Key]bool{}
	for i := range exp.Items {
		it := &exp.Items[i]
		base := &importer.Entry{
			Name:    it.Name,
			Folder:  folders[it.FolderID],
			Created: it.CreationDate,
			Updated: it.RevisionDate,
		}
		if c, ok := folderChanges[it.FolderID]; ok {
			base.Changes = append(base.Changes, c)
		}
		if it.Favorite {
			base.Tags = []string{"favorite"}
		}
		if it.Reprompt != 0 {
			base.Changes = append(base.Changes, "Bitwarden asked for the master password again to show it; sesh doesn't")
		}
		for _, e := range itemEntries(it, base) {
			if e.Skip == "" {
				e.Key = unique(e.Key, taken, e)
			}
			out = append(out, e)
		}
	}
	return out
}

// itemEntries is what one item becomes.
func itemEntries(it *Item, base *importer.Entry) []*importer.Entry {
	service := importer.FitName(it.Name)
	skip := func(why string) []*importer.Entry {
		base.Skip = why
		return []*importer.Entry{base}
	}
	if service == "" {
		return skip("it has no name")
	}
	if service != it.Name {
		base.Changes = append(base.Changes, fmt.Sprintf("named %q in sesh", service))
	}
	fields, fieldChanges := customFields(it.Fields)
	if it.Type == TypeLogin {
		return loginEntries(it, base, service, fields, fieldChanges)
	}
	base.Changes = append(base.Changes, fieldChanges...)

	switch it.Type {
	case TypeSecureNote:
		note := it.Notes
		if note == "" {
			note = it.Name
		}
		return []*importer.Entry{noteEntry(base, service, note, fields)}
	case TypeCard:
		if it.Card == nil {
			return skip("a card with no card details")
		}
		c := it.Card
		note := it.Notes
		if note == "" {
			note = strings.TrimSpace(c.Brand + " card")
			if len(c.Number) >= 4 {
				note += " ending " + c.Number[len(c.Number)-4:]
			}
		}
		expiry := ""
		if c.ExpMonth != "" || c.ExpYear != "" {
			expiry = strings.Trim(c.ExpMonth+"/"+c.ExpYear, "/")
		}
		own := keep([]vault.Field{
			secret("number", c.Number), secret("code", c.Code),
			plain("cardholder-name", c.CardholderName), plain("brand", c.Brand), plain("expiry", expiry),
		})
		return []*importer.Entry{noteEntry(base, service, note, append(own, fields...))}
	case TypeIdentity:
		if it.Identity == nil {
			return skip("an identity with no details")
		}
		d := it.Identity
		note := it.Notes
		if note == "" {
			note = "Identity: " + strings.Join(strings.Fields(strings.Join([]string{d.Title, d.FirstName, d.MiddleName, d.LastName}, " ")), " ")
		}
		address := strings.Join(slices.DeleteFunc([]string{d.Address1, d.Address2, d.Address3}, func(s string) bool { return s == "" }), ", ")
		own := keep([]vault.Field{
			secret("ssn", d.SSN), secret("passport-number", d.PassportNumber), secret("license-number", d.LicenseNumber),
			plain("title", d.Title), plain("first-name", d.FirstName), plain("middle-name", d.MiddleName), plain("last-name", d.LastName),
			plain("address", address), plain("city", d.City), plain("state", d.State), plain("postal-code", d.PostalCode),
			plain("country", d.Country), plain("company", d.Company), plain("email", d.Email), plain("phone", d.Phone),
			plain("username", d.Username),
		})
		return []*importer.Entry{noteEntry(base, service, note, append(own, fields...))}
	case TypeSSHKey:
		if it.SSHKey == nil || it.SSHKey.PrivateKey == "" {
			return skip("an SSH key with no private key")
		}
		k := it.SSHKey
		note := it.Notes
		if note == "" {
			note = strings.TrimSpace("SSH key " + k.KeyFingerprint)
		}
		own := keep([]vault.Field{
			secret("private-key", k.PrivateKey), plain("public-key", k.PublicKey), plain("fingerprint", k.KeyFingerprint),
		})
		return []*importer.Entry{noteEntry(base, service, note, append(own, fields...))}
	case TypeBankAccount, TypeDriversLicense, TypePassport:
		return skip(fmt.Sprintf("a %s, which sesh can't import yet: no Bitwarden export of one has been available to test against", typeName(it.Type)))
	}
	return skip(fmt.Sprintf("an item of a kind sesh doesn't know (type %d)", it.Type))
}

// loginEntries is a login's password entry and its TOTP entry.
// What changed about the details (detailChanges, and passwords and
// passkeys not kept) is said on the entry that holds them.
func loginEntries(it *Item, base *importer.Entry, service string, fields []vault.Field, detailChanges []string) []*importer.Entry {
	l := it.Login
	if l == nil {
		l = &Login{}
	}
	user := importer.FitName(l.Username)
	if user != l.Username {
		base.Changes = append(base.Changes, fmt.Sprintf("username %q in sesh", user))
	}
	if n := len(it.PasswordHistory); n > 0 {
		detailChanges = append(detailChanges, plural(n, "old password", "old passwords")+" not kept: sesh keeps no history yet")
	}
	if len(l.Fido2Credentials) > 0 {
		detailChanges = append(detailChanges, "its passkey not kept: sesh doesn't hold passkeys")
	}
	details := vault.Details{Notes: []byte(it.Notes), Fields: fields}
	for i, u := range l.URIs {
		if i == 0 {
			details.URL = u.URI
			continue
		}
		details.Fields = append(details.Fields, vault.Field{Name: fmt.Sprintf("url-%d", i+1), Value: []byte(u.URI)})
	}
	if len(details.Notes) == 0 {
		details.Notes = nil
	}

	var out []*importer.Entry
	if l.Password != "" {
		e := *base
		e.Changes = append(slices.Clone(base.Changes), detailChanges...)
		e.Key = vault.Key{Kind: vault.KindPassword, Service: service, Username: user}
		e.Secret = []byte(l.Password)
		e.Details = details
		out = append(out, checked(&e))
	}
	if l.TOTP != "" {
		e := *base
		e.Changes = slices.Clone(base.Changes)
		e.Key = vault.Key{Kind: vault.KindTOTP, Service: service, Username: user}
		if len(out) == 0 {
			e.Details = details // nowhere else to keep them
			e.Changes = append(e.Changes, detailChanges...)
		}
		secret, params, why := totpKey(l.TOTP)
		if why != "" {
			e.Skip = "its TOTP key: " + why
		} else {
			e.Secret, e.Settings = []byte(secret), vault.Settings{TOTP: params}
			checked(&e)
		}
		out = append(out, &e)
	}
	if len(out) == 0 {
		base.Changes = append(base.Changes, detailChanges...)
		base.Skip = "a login with no password or TOTP key"
		if len(l.Fido2Credentials) > 0 {
			base.Skip = "a login with only a passkey, which sesh doesn't hold"
		}
		return []*importer.Entry{base}
	}
	return out
}

// totpKey reads a login's TOTP key, as Bitwarden does (bitwarden-vault
// totp.rs): an otpauth:// URI, a steam:// key, or a bare base32 key.
func totpKey(s string) (secret string, params totp.Params, why string) {
	switch lower := strings.ToLower(strings.TrimSpace(s)); {
	case strings.HasPrefix(lower, "steam://"):
		return "", params, "a Steam code, which sesh doesn't make"
	case strings.HasPrefix(lower, "otpauth://"):
		info, err := qrcode.ExtractTOTPFullInfo(strings.TrimSpace(s))
		if err != nil {
			return "", params, err.Error()
		}
		secret = info.Secret
		params = totp.Params{Issuer: info.Issuer, Algorithm: info.Algorithm, Digits: info.Digits, Period: info.Period}
		if params.Algorithm == "SHA1" {
			params.Algorithm = ""
		}
		if params.Digits == 6 {
			params.Digits = 0
		}
		if params.Period == 30 {
			params.Period = 0
		}
	default:
		secret = s
	}
	normalized, err := totp.ValidateAndNormalizeSecret(secret)
	if err != nil {
		return "", params, err.Error()
	}
	return normalized, params, ""
}

// noteEntry is a secure note holding note, with fields.
func noteEntry(base *importer.Entry, service, note string, fields []vault.Field) *importer.Entry {
	base.Key = vault.Key{Kind: vault.KindNote, Service: service}
	base.Secret = []byte(note)
	base.Details = vault.Details{Fields: fields}
	return checked(base)
}

// checked marks e skipped when its name or details break sesh's rules,
// and returns it.
func checked(e *importer.Entry) *importer.Entry {
	if err := e.Key.Validate(); err != nil {
		e.Skip = err.Error()
		return e
	}
	if err := e.Details.Check(e.Key.Kind); err != nil {
		e.Skip = err.Error()
	}
	return e
}

// customFields is an item's custom fields as sesh's: hidden ones secret,
// text and boolean ones plain (a text one of several lines secret, as only
// those can be), linked ones left out, and names fitted and made unique.
// It also says what changed.
func customFields(in []Field) ([]vault.Field, []string) {
	var out []vault.Field
	var changes []string
	used := map[string]bool{}
	for _, f := range in {
		if f.Type == FieldLinked {
			changes = append(changes, fmt.Sprintf("field %q not kept: it only points at another value", f.Name))
			continue
		}
		if f.Value == "" {
			continue
		}
		name := importer.FitFieldName(f.Name)
		for n := 2; used[strings.ToLower(name)]; n++ {
			name = fmt.Sprintf("%s-%d", importer.FitFieldName(f.Name), n)
		}
		used[strings.ToLower(name)] = true
		if name != f.Name {
			changes = append(changes, fmt.Sprintf("field %q is %q in sesh", f.Name, name))
		}
		secretField := f.Type == FieldHidden
		if !secretField && strings.ContainsFunc(f.Value, unicode.IsControl) {
			secretField = true
			changes = append(changes, fmt.Sprintf("field %q is secret in sesh: it has several lines", f.Name))
		}
		out = append(out, vault.Field{Name: name, Value: []byte(f.Value), Secret: secretField})
	}
	if len(out) > vault.MaxFields {
		changes = append(changes, fmt.Sprintf("%d fields not kept: sesh holds %d", len(out)-vault.MaxFields, vault.MaxFields))
		out = out[:vault.MaxFields]
	}
	return out, changes
}

// unique is k, or k with " (2)", " (3)" ... added to its service when
// another entry of this import has it.
func unique(k vault.Key, taken map[vault.Key]bool, e *importer.Entry) vault.Key {
	if !taken[k] {
		taken[k] = true
		return k
	}
	for n := 2; ; n++ {
		c := k
		c.Service = fmt.Sprintf("%s (%d)", k.Service, n)
		if !taken[c] {
			taken[c] = true
			e.Changes = append(e.Changes, fmt.Sprintf("named %q in sesh: another item has its name", c.Service))
			return c
		}
	}
}

func secret(name, v string) vault.Field {
	return vault.Field{Name: name, Value: []byte(v), Secret: true}
}
func plain(name, v string) vault.Field { return vault.Field{Name: name, Value: []byte(v)} }

// keep is fields without the empty ones.
func keep(fields []vault.Field) []vault.Field {
	return slices.DeleteFunc(fields, func(f vault.Field) bool { return len(f.Value) == 0 })
}

func typeName(t int) string {
	switch t {
	case TypeBankAccount:
		return "bank account"
	case TypeDriversLicense:
		return "driver's licence"
	case TypePassport:
		return "passport"
	}
	return fmt.Sprintf("type %d item", t)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
