package bitwarden

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// What a Bitwarden item can have that sesh doesn't keep, as the summary
// adds it up.
const (
	lostHistory  = "old passwords (sesh keeps no history yet)"
	lostPasskey  = "passkeys (sesh doesn't hold them)"
	lostReprompt = "items set to ask for the master password again (sesh doesn't ask)"
)

// Entries is the sesh entries an export's items become, in order:
//   - a login is a password entry, with its URL, notes and custom fields,
//     and its TOTP key a TOTP entry beside it; one with neither a password
//     nor a TOTP key is a secure note, so nothing in it is lost;
//   - a secure note is a secure note;
//   - a card, identity, or SSH key is a secure note, its notes (or a line
//     saying what it is) the note, its numbers and keys secret fields and
//     the rest plain ones;
//   - bank accounts, driver's licences, and passports are skipped.
//
// Folders and field names are fitted to sesh's rules, and a favorite gets
// the tag "favorite". An item whose name another has gets " (2)" on all
// its entries together. What changed on the way is said in each entry.
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
	names := importer.NewNames()
	for i := range exp.Items {
		it := &exp.Items[i]
		base := &importer.Entry{
			Name:    it.Name,
			Folder:  folders[it.FolderID],
			Created: it.CreationDate,
			Updated: it.RevisionDate,
			Lost:    map[string]int{},
		}
		if c, ok := folderChanges[it.FolderID]; ok {
			base.Changes = append(base.Changes, c)
		}
		if it.Favorite {
			base.Tags = []string{"favorite"}
		}
		if it.Reprompt != 0 {
			base.Lost[lostReprompt]++
		}
		if it.ArchivedDate != nil {
			base.Changes = append(base.Changes, "archived in Bitwarden; an ordinary entry in sesh")
		}
		entries := itemEntries(it, base)
		importer.Place(entries, names)
		out = append(out, entries...)
	}
	return out
}

// itemEntries is what one item becomes.
func itemEntries(it *Item, base *importer.Entry) []*importer.Entry {
	service := importer.FitName(it.Name)
	if service == "" {
		base.Skip = "it has no name"
		return []*importer.Entry{base}
	}
	if service != it.Name {
		base.Changes = append(base.Changes, fmt.Sprintf("named %q in sesh", service))
	}
	var fs importer.FieldSet
	switch it.Type {
	case TypeLogin:
		return loginEntries(it, base, service)
	case TypeSecureNote:
		note := it.Notes
		if note == "" {
			note = it.Name
		}
		addCustom(&fs, it.Fields)
		return []*importer.Entry{importer.NoteEntry(base, service, note, &fs)}
	case TypeCard:
		if it.Card == nil {
			break
		}
		c := it.Card
		note := it.Notes
		if note == "" {
			note = strings.TrimSpace(c.Brand + " card")
			if len(c.Number) >= 4 {
				note += " ending " + c.Number[len(c.Number)-4:]
			}
		}
		fs.Add("number", c.Number, true)
		fs.Add("code", c.Code, true)
		fs.Add("cardholder-name", c.CardholderName, false)
		fs.Add("brand", c.Brand, false)
		fs.Add("expiry", strings.Trim(c.ExpMonth+"/"+c.ExpYear, "/"), false)
		addCustom(&fs, it.Fields)
		return []*importer.Entry{importer.NoteEntry(base, service, note, &fs)}
	case TypeIdentity:
		if it.Identity == nil {
			break
		}
		d := it.Identity
		note := it.Notes
		if note == "" {
			note = "Identity"
			if name := strings.Join(strings.Fields(strings.Join([]string{d.Title, d.FirstName, d.MiddleName, d.LastName}, " ")), " "); name != "" {
				note += ": " + name
			}
		}
		address := strings.Join(slices.DeleteFunc([]string{d.Address1, d.Address2, d.Address3}, func(s string) bool { return s == "" }), ", ")
		for _, f := range []struct {
			name, value string
			secret      bool
		}{
			{"ssn", d.SSN, true}, {"passport-number", d.PassportNumber, true}, {"license-number", d.LicenseNumber, true},
			{"title", d.Title, false}, {"first-name", d.FirstName, false}, {"middle-name", d.MiddleName, false},
			{"last-name", d.LastName, false}, {"address", address, false}, {"city", d.City, false},
			{"state", d.State, false}, {"postal-code", d.PostalCode, false}, {"country", d.Country, false},
			{"company", d.Company, false}, {"email", d.Email, false}, {"phone", d.Phone, false},
			{"username", d.Username, false},
		} {
			fs.Add(f.name, f.value, f.secret)
		}
		addCustom(&fs, it.Fields)
		return []*importer.Entry{importer.NoteEntry(base, service, note, &fs)}
	case TypeSSHKey:
		if it.SSHKey == nil || it.SSHKey.PrivateKey == "" {
			break
		}
		k := it.SSHKey
		note := it.Notes
		if note == "" {
			note = strings.TrimSpace("SSH key " + k.KeyFingerprint)
		}
		fs.Add("private-key", k.PrivateKey, true)
		fs.Add("public-key", k.PublicKey, false)
		fs.Add("fingerprint", k.KeyFingerprint, false)
		addCustom(&fs, it.Fields)
		return []*importer.Entry{importer.NoteEntry(base, service, note, &fs)}
	case TypeBankAccount, TypeDriversLicense, TypePassport:
		base.Skip = fmt.Sprintf("a %s, which sesh can't import yet: no Bitwarden export of one has been available to test against", typeName(it.Type))
		return []*importer.Entry{base}
	default:
		base.Skip = fmt.Sprintf("an item of a kind sesh doesn't know (type %d)", it.Type)
		return []*importer.Entry{base}
	}
	base.Skip = fmt.Sprintf("a %s with none of its details", typeName(it.Type))
	return []*importer.Entry{base}
}

// loginEntries is a login's password entry and TOTP entry, or a secure
// note when it has neither a password nor a TOTP key. What changed about
// the details is said on the entry that holds them.
func loginEntries(it *Item, base *importer.Entry, service string) []*importer.Entry {
	l := it.Login
	if l == nil {
		l = &Login{}
	}
	user := importer.FitName(l.Username)
	if user != l.Username {
		base.Changes = append(base.Changes, fmt.Sprintf("username %q in sesh", user))
	}
	if n := len(it.PasswordHistory); n > 0 {
		base.Lost[lostHistory] += n
	}
	if n := len(l.Fido2Credentials); n > 0 {
		base.Lost[lostPasskey] += n
	}
	var fs importer.FieldSet
	addCustom(&fs, it.Fields)
	firstURL := ""
	for i, u := range l.URIs {
		if i == 0 {
			firstURL = u.URI
			continue
		}
		fs.Add(fmt.Sprintf("url-%d", i+1), u.URI, false)
	}
	details := vault.Details{URL: firstURL, Fields: fs.Fields}
	if it.Notes != "" {
		details.Notes = []byte(it.Notes)
	}

	var out []*importer.Entry
	if l.Password != "" {
		e := *base
		e.Changes = append(slices.Clone(base.Changes), fs.Changes...)
		e.Key = vault.Key{Kind: vault.KindPassword, Service: service, Username: user}
		e.Secret = []byte(l.Password)
		e.Details = details
		out = append(out, importer.Checked(&e))
	}
	if l.TOTP != "" {
		e := *base
		e.Changes = slices.Clone(base.Changes)
		e.Key = vault.Key{Kind: vault.KindTOTP, Service: service, Username: user}
		if len(out) == 0 {
			e.Details = details // nowhere else to keep them
			e.Changes = append(e.Changes, fs.Changes...)
		} else {
			e.Lost = nil // counted once, on the password entry
		}
		secret, params, why := totpKey(l.TOTP)
		if why != "" {
			e.Skip = "its TOTP key: " + why
		} else {
			e.Secret, e.Settings = []byte(secret), vault.Settings{TOTP: params}
			importer.Checked(&e)
		}
		out = append(out, &e)
	}
	if len(out) > 0 {
		return out
	}
	// Neither a password nor a TOTP key: kept as a secure note.
	note := it.Notes
	if note == "" {
		note = "Login with no password"
	}
	var nfs importer.FieldSet
	nfs.Add("username", l.Username, false)
	addCustom(&nfs, it.Fields)
	for i, u := range l.URIs {
		if i > 0 {
			nfs.Add(fmt.Sprintf("url-%d", i+1), u.URI, false)
		}
	}
	base.Changes = append(base.Changes, "a secure note in sesh: the login has no password or TOTP key")
	e := importer.NoteEntry(base, service, note, &nfs)
	e.Details.URL = firstURL
	return []*importer.Entry{importer.Checked(e)}
}

// totpKey reads a login's TOTP key as Bitwarden does (bitwarden-vault
// totp.rs): an otpauth:// address, read in any case, with or without a
// label, each setting by its last value and one that isn't a number left
// at its default; a steam:// key; or a bare base32 key, whose spaces and
// dashes are left out. sesh refuses what it can't make codes for. A
// reason never repeats the key.
func totpKey(s string) (secret string, params totp.Params, why string) {
	s = strings.TrimSpace(s)
	switch lower := strings.ToLower(s); {
	case strings.HasPrefix(lower, "steam://"):
		return "", params, "a Steam code, which sesh doesn't make"
	case strings.HasPrefix(lower, "otpauth://"):
		rest, query, _ := strings.Cut(s[len("otpauth://"):], "?")
		host, label, _ := strings.Cut(rest, "/")
		switch strings.ToLower(host) {
		case "totp":
		case "hotp":
			return "", params, "a counter-based (HOTP) code, which sesh doesn't make"
		default:
			return "", params, "it doesn't read as an otpauth:// address"
		}
		// ParseQuery keeps what reads when some of it doesn't.
		values, _ := url.ParseQuery(query) //nolint:errcheck // see above
		q := map[string]string{}
		for k, v := range values {
			q[strings.ToLower(k)] = v[len(v)-1]
		}
		secret = q["secret"]
		if secret == "" {
			return "", params, "it has no key"
		}
		switch alg := strings.ToUpper(q["algorithm"]); alg {
		case "", "SHA1":
		case "SHA256", "SHA512":
			params.Algorithm = alg
		default:
			return "", params, "it uses " + alg + ", which sesh doesn't support"
		}
		if n, err := strconv.ParseUint(q["digits"], 10, 32); err == nil && n != 6 {
			if n < 6 || n > 8 {
				return "", params, fmt.Sprintf("it makes %d-digit codes, which sesh doesn't make", min(n, 10))
			}
			params.Digits = int(n)
		}
		if n, err := strconv.ParseUint(q["period"], 10, 32); err == nil && n != 30 {
			if n > totp.MaxTOTPPeriodSeconds {
				return "", params, fmt.Sprintf("it makes a new code every %d seconds, longer than sesh allows", n)
			}
			params.Period = max(int(n), 1)
		}
		params.Issuer = q["issuer"]
		if params.Issuer == "" {
			if l, err := url.PathUnescape(label); err == nil {
				if issuer, _, ok := strings.Cut(l, ":"); ok {
					params.Issuer = strings.TrimSpace(issuer)
				}
			}
		}
	default:
		secret = strings.NewReplacer(" ", "", "-", "").Replace(s)
	}
	normalized, err := totp.ValidateAndNormalizeSecret(secret)
	switch {
	case err != nil && strings.Contains(err.Error(), "too short"):
		return "", params, "the key is too short to be safe"
	case err != nil:
		return "", params, "the key isn't a valid base32 key"
	}
	return normalized, params, ""
}

// addCustom adds an item's custom fields: hidden ones secret, text and
// boolean ones plain, linked ones left out.
func addCustom(fs *importer.FieldSet, in []Field) {
	for _, f := range in {
		if f.Type == FieldLinked {
			fs.Changes = append(fs.Changes, fmt.Sprintf("field %q not kept: it only points at another value", f.Name))
			continue
		}
		fs.Custom(f.Name, f.Value, f.Type == FieldHidden)
	}
}

func typeName(t int) string {
	switch t {
	case TypeCard:
		return "card"
	case TypeIdentity:
		return "identity"
	case TypeSSHKey:
		return "SSH key"
	case TypeBankAccount:
		return "bank account"
	case TypeDriversLicense:
		return "driver's licence"
	case TypePassport:
		return "passport"
	}
	return fmt.Sprintf("type %d item", t)
}
