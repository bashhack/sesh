package keepass

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// What a KeePass entry can have that sesh doesn't keep, as the summary
// adds it up.
const (
	lostHistory    = "earlier versions of entries (sesh keeps no history yet)"
	lostAttachment = "attachments (sesh doesn't hold files)"
)

// The fields every entry has, which aren't custom ones.
var standardFields = []string{"Title", "UserName", "Password", "URL", "Notes", "otp"}

// reference is a field reference to another entry, as KeePassXC finds one
// (Entry.cpp placeholderType, EntryAttributes.cpp matchReference):
// {REF:<field>@<search>:<text>}, "{REF:" as written, the rest in any case.
var reference = regexp.MustCompile(`\{REF:(?i:([TUPANI])@([TUPANIO])):([^}]+)\}`)

// maxResolvedLength is the longest a value may grow to with references
// filled in, so ones that each repeat another can't make it huge.
const maxResolvedLength = 1 << 16

// noRecycleBin is the UUID of no group, all zero bytes.
const noRecycleBin = "AAAAAAAAAAAAAAAAAAAAAA=="

// Entries is the sesh entries an export's entries become, in order:
//   - an entry with a password is a password entry, with its URL, notes
//     and custom fields, and its TOTP key (KeePassXC's otp field) a TOTP
//     entry beside it; one with neither is a secure note, so nothing in it
//     is lost;
//   - a protected field is secret, others plain;
//   - an entry in the recycle bin is skipped.
//
// Groups below the database's own are the folder, fitted to sesh's rules;
// tags are fitted too. An entry whose name another has gets " (2)" on all
// its entries together. What changed on the way is said in each entry.
func Entries(exp *Export) []*importer.Entry {
	w := walker{bin: exp.Meta.RecycleBinUUID, taken: map[vault.Key]bool{}, now: time.Now(), byUUID: map[string]*Entry{}, refs: map[refKey]resolved{}}
	if w.bin == noRecycleBin {
		w.bin = ""
	}
	root := &exp.Root.Group
	w.index(root)
	w.group(root, nil, false)
	return w.out
}

// Count is how many entries and groups the export has, the database's own
// group and the recycle bin left out.
func Count(exp *Export) (entries, groups int) {
	var walk func(g *Group)
	walk = func(g *Group) {
		entries += len(g.Entries)
		for i := range g.Groups {
			if g.Groups[i].UUID != exp.Meta.RecycleBinUUID {
				groups++
				walk(&g.Groups[i])
			}
		}
	}
	walk(&exp.Root.Group)
	return entries, groups
}

type walker struct {
	now    time.Time
	taken  map[vault.Key]bool
	byUUID map[string]*Entry // by its UUID in hex, upper case
	refs   map[refKey]resolved
	bin    string
	out    []*importer.Entry
}

// index records every entry in g and its groups by UUID, for references.
func (w *walker) index(g *Group) {
	for i := range g.Entries {
		if raw, err := base64.StdEncoding.DecodeString(g.Entries[i].UUID); err == nil && len(raw) == 16 {
			w.byUUID[strings.ToUpper(hex.EncodeToString(raw))] = &g.Entries[i]
		}
	}
	for i := range g.Groups {
		w.index(&g.Groups[i])
	}
}

// refKey is a field of an entry that a reference names.
type refKey struct {
	entry *Entry
	field string
}

// resolved is a referenced field's value, filled in: whether it could be,
// and whether it holds a password or protected value.
type resolved struct {
	value      string
	ok, secret bool
}

// resolve fills in s's references to other entries, as KeePassXC does when
// it uses a value (Entry.cpp resolveReferencePlaceholderRecursive). Only a
// reference by UUID is followed, which is what KeePassXC's Clone makes;
// one that loops or grows too long can't be. (KeePassXC also stops ten
// deep; sesh follows a longer chain, so that the result doesn't depend on
// the order of entries, as remembering each field's value would make it.) It reports whether every one could be followed, and whether
// any filled in a password or protected value. path is the fields being
// filled in on the way here.
func (w *walker) resolve(s string, path []refKey) (value string, ok, secret bool) {
	if !strings.Contains(s, "{REF:") {
		return s, true, false
	}
	ok = true
	value = reference.ReplaceAllStringFunc(s, func(m string) string {
		g := reference.FindStringSubmatch(m)
		target := w.byUUID[strings.ToUpper(g[3])]
		if !strings.EqualFold(g[2], "I") || target == nil {
			ok = false
			return m
		}
		field := map[string]string{"T": "Title", "U": "UserName", "P": "Password", "A": "URL", "N": "Notes"}[strings.ToUpper(g[1])]
		if field == "" { // I, the entry's UUID
			return strings.ToUpper(g[3])
		}
		k := refKey{target, field}
		if slices.Contains(path, k) {
			ok = false
			return m
		}
		r, done := w.refs[k]
		if !done {
			raw, protected := target.field(field)
			r.value, r.ok, r.secret = w.resolve(raw, append(slices.Clone(path), k))
			r.secret = r.secret || protected || field == "Password"
			w.refs[k] = r
		}
		ok = ok && r.ok
		secret = secret || r.secret
		return r.value
	})
	if len(value) > maxResolvedLength {
		return s, false, secret
	}
	return value, ok, secret
}

// group adds g's entries, then its groups'. path is g's place below the
// database's own group, and inBin whether it's in the recycle bin.
func (w *walker) group(g *Group, path []string, inBin bool) {
	inBin = inBin || (w.bin != "" && g.UUID == w.bin)
	folder := strings.Join(path, "/")
	fitted := folderPath(path)
	for i := range g.Entries {
		e := &g.Entries[i]
		title, _ := e.Field("Title")
		base := &importer.Entry{
			Name:    title,
			Folder:  fitted,
			Created: e.Times.CreationTime.Time,
			Updated: e.Times.LastModificationTime.Time,
			Lost:    map[string]int{},
		}
		if inBin {
			base.Skip = "in KeePass's recycle bin"
			w.out = append(w.out, base)
			continue
		}
		if fitted != folder {
			base.Changes = append(base.Changes, fmt.Sprintf("folder %q is %q in sesh", folder, fitted))
		}
		entries := w.entry(e, base)
		importer.Place(entries, w.taken)
		w.out = append(w.out, entries...)
	}
	for i := range g.Groups {
		w.group(&g.Groups[i], append(slices.Clone(path), g.Groups[i].Name), inBin)
	}
}

// folderPath is a group path as a sesh folder: a "/" in a group's name
// becomes "-", as it isn't nesting.
func folderPath(path []string) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = strings.ReplaceAll(p, "/", "-")
	}
	return importer.FitFolder(strings.Join(parts, "/"))
}

// entry is what one entry becomes.
func (w *walker) entry(e *Entry, base *importer.Entry) []*importer.Entry {
	// Every value with its references filled in. One that can't be
	// followed costs the entry in its title, username or password, which
	// would be wrong in sesh; elsewhere it's kept as written, and said.
	// A value filled in from a password or protected field stays secret:
	// a custom field is made secret, notes are anyway, and the title,
	// username and URL, which sesh shows, aren't filled in.
	values := map[string]string{}
	var followed, unfollowed []string
	madeSecret := map[string]bool{}
	for _, str := range e.Strings {
		v, ok, secret := w.resolve(str.Value.Text, nil)
		switch {
		case !ok:
			unfollowed = append(unfollowed, str.Key)
			v = str.Value.Text
		case v == str.Value.Text:
		case secret && (str.Key == "Title" || str.Key == "UserName"):
			base.Skip = fmt.Sprintf("its %s refers to a protected value of another entry, which sesh would show", fieldWord(str.Key))
			return []*importer.Entry{base}
		case secret && str.Key == "URL":
			base.Changes = append(base.Changes, "URL refers to a protected value of another entry; kept as written")
			v = str.Value.Text
		default:
			followed = append(followed, str.Key)
			madeSecret[str.Key] = secret && !slices.Contains(standardFields, str.Key)
		}
		values[str.Key] = v
	}
	for _, key := range []string{"Title", "UserName", "Password"} {
		if slices.Contains(unfollowed, key) {
			base.Skip = fmt.Sprintf("its %s refers to another entry in a way sesh can't follow", fieldWord(key))
			return []*importer.Entry{base}
		}
	}
	if len(followed) > 0 {
		words := make([]string, len(followed))
		for i, k := range followed {
			words[i] = fieldWord(k)
		}
		they := "they refer"
		if len(words) == 1 {
			they = "it refers"
		}
		base.Changes = append(base.Changes, fmt.Sprintf("%s taken from the entry %s to", joinWords(words), they))
	}
	for _, k := range unfollowed {
		if k == "Notes" {
			base.Changes = append(base.Changes, "notes refer to another entry in a way sesh can't follow; kept as written")
		} else {
			base.Changes = append(base.Changes, fmt.Sprintf("%s refers to another entry in a way sesh can't follow; kept as written", fieldWord(k)))
		}
	}

	title := values["Title"]
	service := importer.FitName(title)
	if service == "" {
		base.Skip = "it has no title"
		return []*importer.Entry{base}
	}
	if service != title {
		base.Changes = append(base.Changes, fmt.Sprintf("named %q in sesh", service))
	}
	username := values["UserName"]
	user := importer.FitName(username)
	if user != username {
		base.Changes = append(base.Changes, fmt.Sprintf("username %q in sesh", user))
	}
	for tag := range strings.FieldsFuncSeq(e.Tags, func(r rune) bool { return r == ',' || r == ';' || r == '\t' }) {
		tag = strings.TrimSpace(tag)
		fitted := importer.FitTag(tag)
		switch {
		case fitted == "":
			base.Changes = append(base.Changes, fmt.Sprintf("tag %q not kept: nothing of it fits sesh's rules", tag))
			continue
		case fitted != tag:
			base.Changes = append(base.Changes, fmt.Sprintf("tag %q is %q in sesh", tag, fitted))
		}
		if !slices.Contains(base.Tags, fitted) {
			base.Tags = append(base.Tags, fitted)
		}
	}
	// KeePassXC shows an expiry in local time (EntryModel.cpp).
	if strings.EqualFold(e.Times.Expires, "True") && !e.Times.ExpiryTime.IsZero() {
		when := e.Times.ExpiryTime.Local().Format("2006-01-02")
		if e.Times.ExpiryTime.Before(w.now) {
			base.Changes = append(base.Changes, "expired in KeePass on "+when)
		} else {
			base.Changes = append(base.Changes, "expires in KeePass on "+when)
		}
	}
	if n := len(e.History.Entries); n > 0 {
		base.Lost[lostHistory] += n
	}
	if n := len(e.Binaries); n > 0 {
		base.Lost[lostAttachment] += n
	}

	// Custom fields, leaving out what holds a TOTP or HOTP key.
	type custom struct {
		key, value string
		secret     bool
	}
	var customs []custom
	oldTOTP, hotp := false, false
	for _, str := range e.Strings {
		switch {
		case slices.Contains(standardFields, str.Key):
		case str.Key == "TOTP Seed", str.Key == "TOTP Settings", strings.HasPrefix(str.Key, "TimeOtp-"):
			oldTOTP = true
		case strings.HasPrefix(str.Key, "HmacOtp-"):
			hotp = true
		default:
			secret := strings.EqualFold(str.Value.ProtectInMemory, "True")
			if madeSecret[str.Key] && !secret {
				secret = true
				base.Changes = append(base.Changes, fmt.Sprintf("field %q is secret in sesh: it refers to a protected value of another entry", str.Key))
			}
			customs = append(customs, custom{str.Key, values[str.Key], secret})
		}
	}
	otp := values["otp"]
	if otp != "" && !strings.HasPrefix(strings.ToLower(otp), "otpauth://") {
		oldTOTP = true // KeeOtp's key=…&size=… in the otp field
		otp = ""
	}
	if oldTOTP && otp == "" {
		base.Changes = append(base.Changes, "its TOTP is in an older layout sesh doesn't read: add it with sesh --service totp --setup")
	}
	if hotp {
		base.Changes = append(base.Changes, "its counter-based (HOTP) key isn't kept: sesh doesn't make counter-based codes")
	}
	urlText, notes := values["URL"], values["Notes"]

	var out []*importer.Entry
	if password := values["Password"]; password != "" {
		var fs importer.FieldSet
		for _, c := range customs {
			fs.Custom(c.key, c.value, c.secret)
		}
		details := vault.Details{URL: urlText, Fields: fs.Fields}
		if notes != "" {
			details.Notes = []byte(notes)
		}
		p := *base
		p.Changes = append(slices.Clone(base.Changes), fs.Changes...)
		p.Key = vault.Key{Kind: vault.KindPassword, Service: service, Username: user}
		p.Secret = []byte(password)
		p.Details = details
		out = append(out, importer.Checked(&p))
	}
	if otp != "" {
		t := *base
		t.Changes = slices.Clone(base.Changes)
		t.Key = vault.Key{Kind: vault.KindTOTP, Service: service, Username: user}
		if len(out) == 0 {
			// Nowhere else to keep the details.
			var fs importer.FieldSet
			for _, c := range customs {
				fs.Custom(c.key, c.value, c.secret)
			}
			t.Details = vault.Details{URL: urlText, Fields: fs.Fields}
			if notes != "" {
				t.Details.Notes = []byte(notes)
			}
			t.Changes = append(t.Changes, fs.Changes...)
		} else {
			t.Lost = nil // counted once, on the password entry
		}
		secret, params, why := totpKey(otp)
		if why != "" {
			t.Skip = "its TOTP key: " + why
		} else {
			t.Secret, t.Settings = []byte(secret), vault.Settings{TOTP: params}
			importer.Checked(&t)
		}
		out = append(out, &t)
	}
	if len(out) > 0 {
		return out
	}
	// Neither a password nor a TOTP key: kept as a secure note.
	note := notes
	if note == "" {
		note = "Entry with no password"
	}
	var fs importer.FieldSet
	fs.Add("username", username, false)
	for _, c := range customs {
		fs.Custom(c.key, c.value, c.secret)
	}
	base.Changes = append(base.Changes, "a secure note in sesh: the entry has no password or TOTP key")
	n := importer.NoteEntry(base, service, note, &fs)
	n.Details.URL = urlText
	return []*importer.Entry{importer.Checked(n)}
}

// fieldWord names one of an entry's fields in a message.
func fieldWord(key string) string {
	switch key {
	case "Title":
		return "title"
	case "UserName":
		return "username"
	case "Password":
		return "password"
	case "URL":
		return "URL"
	case "Notes":
		return "notes"
	}
	return fmt.Sprintf("field %q", key)
}

// joinWords is words as a list in a sentence: "a", "a and b", "a, b and c".
func joinWords(words []string) string {
	if len(words) == 1 {
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// totpKey reads KeePassXC's otp field, an otpauth:// address, as its
// Totp::parseSettings does: secret, digits, period, algorithm and encoder
// from the query, by exact name, the first of each. sesh refuses what it
// can't make codes for, including what KeePassXC would read as SHA-1. A
// reason never repeats the key.
func totpKey(s string) (secret string, params totp.Params, why string) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") {
		return "", params, "it doesn't read as an otpauth:// address"
	}
	switch strings.ToLower(u.Host) {
	case "totp":
	case "hotp":
		return "", params, "a counter-based (HOTP) code, which sesh doesn't make"
	default:
		return "", params, "it doesn't read as an otpauth:// address"
	}
	q := u.Query()
	if q.Get("encoder") == "steam" {
		return "", params, "a Steam code, which sesh doesn't make"
	}
	switch alg := strings.ToUpper(q.Get("algorithm")); alg {
	case "", "SHA1", "HMAC-SHA-1":
	case "SHA256", "HMAC-SHA-256":
		params.Algorithm = "SHA256"
	case "SHA512", "HMAC-SHA-512":
		params.Algorithm = "SHA512"
	default:
		return "", params, "it uses " + alg + ", which sesh doesn't support"
	}
	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		switch {
		case err != nil:
			return "", params, "its digits setting isn't a number"
		case n < 6 || n > 8:
			return "", params, fmt.Sprintf("it makes %d-digit codes, which sesh doesn't make", n)
		case n != 6:
			params.Digits = n
		}
	}
	if p := q.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", params, "its period setting isn't a number"
		}
		// KeePassXC keeps a period within 1 second and a day.
		if n = min(max(n, 1), totp.MaxTOTPPeriodSeconds); n != 30 {
			params.Period = n
		}
	}
	params.Issuer = q.Get("issuer")
	if params.Issuer == "" {
		if issuer, _, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":"); ok {
			params.Issuer = strings.TrimSpace(issuer)
		}
	}
	normalized, err := totp.ValidateAndNormalizeSecret(q.Get("secret"))
	switch {
	case q.Get("secret") == "":
		return "", params, "it has no key"
	case err != nil && strings.Contains(err.Error(), "too short"):
		return "", params, "the key is too short to be safe"
	case err != nil:
		return "", params, "the key isn't a valid base32 key"
	}
	return normalized, params, ""
}
