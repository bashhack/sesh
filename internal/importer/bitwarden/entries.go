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
	taken := map[vault.Key]bool{}
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
		place(entries, taken)
		out = append(out, entries...)
	}
	return out
}

// place gives an item's entries their keys: as they are, or with " (2)",
// " (3)" ... added to the service name of all of them together when
// another item's entry has one already. It checks them again after.
func place(entries []*importer.Entry, taken map[vault.Key]bool) {
	var live []*importer.Entry
	for _, e := range entries {
		if e.Skip == "" {
			live = append(live, e)
		}
	}
	for n := 1; ; n++ {
		keys := make([]vault.Key, len(live))
		free := true
		for i, e := range live {
			keys[i] = numbered(e.Key, n)
			free = free && !taken[keys[i]]
		}
		if !free {
			continue
		}
		for i, e := range live {
			if n > 1 {
				e.Changes = append(e.Changes, fmt.Sprintf("named %q in sesh: another item has its name", keys[i].Service))
			}
			e.Key = keys[i]
			taken[keys[i]] = true
			checked(e)
		}
		return
	}
}

// numbered is k with " (n)" added to its service name, cut to fit, for n
// above 1.
func numbered(k vault.Key, n int) vault.Key {
	if n == 1 {
		return k
	}
	suffix := fmt.Sprintf(" (%d)", n)
	r := []rune(k.Service)
	if limit := vault.MaxNameLength - len([]rune(suffix)); len(r) > limit {
		r = r[:limit]
	}
	k.Service = strings.TrimSpace(string(r)) + suffix
	return k
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
	var fs fieldSet
	switch it.Type {
	case TypeLogin:
		return loginEntries(it, base, service)
	case TypeSecureNote:
		note := it.Notes
		if note == "" {
			note = it.Name
		}
		fs.addCustom(it.Fields)
		return []*importer.Entry{noteEntry(base, service, note, &fs)}
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
		fs.add("number", c.Number, true)
		fs.add("code", c.Code, true)
		fs.add("cardholder-name", c.CardholderName, false)
		fs.add("brand", c.Brand, false)
		fs.add("expiry", strings.Trim(c.ExpMonth+"/"+c.ExpYear, "/"), false)
		fs.addCustom(it.Fields)
		return []*importer.Entry{noteEntry(base, service, note, &fs)}
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
			fs.add(f.name, f.value, f.secret)
		}
		fs.addCustom(it.Fields)
		return []*importer.Entry{noteEntry(base, service, note, &fs)}
	case TypeSSHKey:
		if it.SSHKey == nil || it.SSHKey.PrivateKey == "" {
			break
		}
		k := it.SSHKey
		note := it.Notes
		if note == "" {
			note = strings.TrimSpace("SSH key " + k.KeyFingerprint)
		}
		fs.add("private-key", k.PrivateKey, true)
		fs.add("public-key", k.PublicKey, false)
		fs.add("fingerprint", k.KeyFingerprint, false)
		fs.addCustom(it.Fields)
		return []*importer.Entry{noteEntry(base, service, note, &fs)}
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
	var fs fieldSet
	fs.addCustom(it.Fields)
	url := ""
	for i, u := range l.URIs {
		if i == 0 {
			url = u.URI
			continue
		}
		fs.add(fmt.Sprintf("url-%d", i+1), u.URI, false)
	}
	details := vault.Details{URL: url, Fields: fs.fields}
	if it.Notes != "" {
		details.Notes = []byte(it.Notes)
	}

	var out []*importer.Entry
	if l.Password != "" {
		e := *base
		e.Changes = append(slices.Clone(base.Changes), fs.changes...)
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
			e.Changes = append(e.Changes, fs.changes...)
		} else {
			e.Lost = nil // counted once, on the password entry
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
	if len(out) > 0 {
		return out
	}
	// Neither a password nor a TOTP key: kept as a secure note.
	note := it.Notes
	if note == "" {
		note = "Login with no password"
	}
	var nfs fieldSet
	nfs.add("username", l.Username, false)
	nfs.addCustom(it.Fields)
	for i, u := range l.URIs {
		if i > 0 {
			nfs.add(fmt.Sprintf("url-%d", i+1), u.URI, false)
		}
	}
	base.Changes = append(base.Changes, "a secure note in sesh: the login has no password or TOTP key")
	e := noteEntry(base, service, note, &nfs)
	e.Details.URL = url
	return []*importer.Entry{checked(e)}
}

// totpKey reads a login's TOTP key: an otpauth://totp/ address (in any
// case), a steam:// key, or a bare base32 key, whose spaces and dashes
// are left out. Bitwarden takes the same three forms (bitwarden-vault
// totp.rs); sesh refuses what it can't make codes for. A reason never
// repeats the key.
func totpKey(s string) (secret string, params totp.Params, why string) {
	s = strings.TrimSpace(s)
	switch lower := strings.ToLower(s); {
	case strings.HasPrefix(lower, "steam://"):
		return "", params, "a Steam code, which sesh doesn't make"
	case strings.HasPrefix(lower, "otpauth://"):
		host, path, _ := strings.Cut(s[len("otpauth://"):], "/")
		switch strings.ToLower(host) {
		case "totp":
		case "hotp":
			return "", params, "a counter-based (HOTP) code, which sesh doesn't make"
		default:
			return "", params, "it doesn't read as an otpauth:// address"
		}
		info, err := qrcode.ExtractTOTPFullInfo("otpauth://totp/" + path)
		if err != nil {
			return "", params, "it doesn't read as an otpauth:// address"
		}
		switch alg := strings.ToUpper(info.Algorithm); alg {
		case "", "SHA1":
		case "SHA256", "SHA512":
			params.Algorithm = alg
		default:
			return "", params, "it uses " + alg + ", which sesh doesn't support"
		}
		if info.Digits != 0 && info.Digits != 6 {
			params.Digits = info.Digits
		}
		if info.Period != 0 && info.Period != 30 {
			params.Period = info.Period
		}
		params.Issuer = info.Issuer
		secret = info.Secret
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

// noteEntry makes base a secure note holding note, with fs's fields.
func noteEntry(base *importer.Entry, service, note string, fs *fieldSet) *importer.Entry {
	base.Key = vault.Key{Kind: vault.KindNote, Service: service}
	base.Secret = []byte(note)
	base.Details = vault.Details{Fields: fs.fields}
	base.Changes = append(base.Changes, fs.changes...)
	return checked(base)
}

// checked marks e skipped when its name, folder, tags or details break
// sesh's rules, and returns it.
func checked(e *importer.Entry) *importer.Entry {
	if e.Skip != "" {
		return e
	}
	err := e.Key.Validate()
	if err == nil {
		err = vault.CheckFolder(e.Folder)
	}
	for _, t := range e.Tags {
		if err == nil {
			err = vault.CheckTag(t)
		}
	}
	if err == nil {
		err = e.Details.Check(e.Key.Kind)
	}
	if err != nil {
		e.Skip = err.Error()
	}
	return e
}

// fieldSet gathers an entry's fields as sesh holds them: names fitted and
// unique (ignoring case), at most vault.MaxFields, saying what changed.
type fieldSet struct {
	used    map[string]bool
	fields  []vault.Field
	changes []string
	dropped int
}

// add adds a field sesh names, unless its value is empty.
func (s *fieldSet) add(name, value string, secret bool) {
	if value == "" {
		return
	}
	s.put(importer.FitFieldName(name), value, secret, "")
}

// addCustom adds an item's custom fields: hidden ones secret, text and
// boolean ones plain (a value with a line break or tab secret, as only
// those can hold one), linked ones left out.
func (s *fieldSet) addCustom(in []Field) {
	for _, f := range in {
		switch {
		case f.Type == FieldLinked:
			s.changes = append(s.changes, fmt.Sprintf("field %q not kept: it only points at another value", f.Name))
			continue
		case f.Value == "":
			s.changes = append(s.changes, fmt.Sprintf("field %q not kept: it has no value", f.Name))
			continue
		}
		secret := f.Type == FieldHidden
		if !secret && strings.ContainsFunc(f.Value, unicode.IsControl) {
			secret = true
			s.changes = append(s.changes, fmt.Sprintf("field %q is secret in sesh: it has a line break or tab", f.Name))
		}
		s.put(importer.FitFieldName(f.Name), f.Value, secret, f.Name)
	}
}

// put adds a field named name, made unique; from is the source's name for
// it, said when it changed ("" for a field sesh names).
func (s *fieldSet) put(name, value string, secret bool, from string) {
	if s.used == nil {
		s.used = map[string]bool{}
	}
	if len(s.fields) == vault.MaxFields {
		s.dropped++
		if s.dropped == 1 {
			s.changes = append(s.changes, "") // the count goes here
		}
		for i := len(s.changes) - 1; i >= 0; i-- {
			if s.changes[i] == "" || strings.HasSuffix(s.changes[i], fmt.Sprintf("sesh holds %d", vault.MaxFields)) {
				s.changes[i] = fmt.Sprintf("%d fields not kept: sesh holds %d", s.dropped, vault.MaxFields)
				break
			}
		}
		return
	}
	base := name
	for n := 2; s.used[strings.ToLower(name)]; n++ {
		name = fmt.Sprintf("%s-%d", base, n)
	}
	s.used[strings.ToLower(name)] = true
	if from != "" && name != from {
		s.changes = append(s.changes, fmt.Sprintf("field %q is %q in sesh", from, name))
	}
	s.fields = append(s.fields, vault.Field{Name: name, Value: []byte(value), Secret: secret})
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
