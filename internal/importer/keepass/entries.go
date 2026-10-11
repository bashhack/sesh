package keepass

import (
	"fmt"
	"net/url"
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
	w := walker{bin: exp.Meta.RecycleBinUUID, taken: map[vault.Key]bool{}, now: time.Now()}
	if w.bin == noRecycleBin {
		w.bin = ""
	}
	root := &exp.Root.Group
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
	now   time.Time
	taken map[vault.Key]bool
	bin   string
	out   []*importer.Entry
}

// group adds g's entries, then its groups'. path is g's place below the
// database's own group, and inBin whether it's in the recycle bin.
func (w *walker) group(g *Group, path []string, inBin bool) {
	inBin = inBin || (w.bin != "" && g.UUID == w.bin)
	folder := strings.Join(path, "/")
	fitted := importer.FitFolder(folder)
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

// entry is what one entry becomes.
func (w *walker) entry(e *Entry, base *importer.Entry) []*importer.Entry {
	title, _ := e.Field("Title")
	service := importer.FitName(title)
	if service == "" {
		base.Skip = "it has no title"
		return []*importer.Entry{base}
	}
	if service != title {
		base.Changes = append(base.Changes, fmt.Sprintf("named %q in sesh", service))
	}
	username, _ := e.Field("UserName")
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
	if strings.EqualFold(e.Times.Expires, "True") && !e.Times.ExpiryTime.IsZero() {
		when := e.Times.ExpiryTime.Format("2006-01-02")
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

	var fs importer.FieldSet
	oldTOTP := false
	for _, s := range e.Strings {
		switch {
		case slices.Contains(standardFields, s.Key):
		case s.Key == "TOTP Seed", s.Key == "TOTP Settings", strings.HasPrefix(s.Key, "TimeOtp-"):
			oldTOTP = true
		default:
			fs.Custom(s.Key, s.Value.Text, strings.EqualFold(s.Value.ProtectInMemory, "True"))
		}
	}
	otp, _ := e.Field("otp")
	if otp != "" && !strings.HasPrefix(strings.ToLower(otp), "otpauth://") {
		oldTOTP = true // KeeOtp's key=…&size=… in the otp field
		otp = ""
	}
	if oldTOTP && otp == "" {
		base.Changes = append(base.Changes, "its TOTP is in an older layout sesh doesn't read: add it with sesh --service totp --setup")
	}
	urlText, _ := e.Field("URL")
	notes, _ := e.Field("Notes")
	details := vault.Details{URL: urlText, Fields: fs.Fields}
	if notes != "" {
		details.Notes = []byte(notes)
	}

	var out []*importer.Entry
	if password, _ := e.Field("Password"); password != "" {
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
			t.Details = details // nowhere else to keep them
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
	var nfs importer.FieldSet
	nfs.Add("username", username, false)
	for _, f := range fs.Fields {
		nfs.Custom(f.Name, string(f.Value), f.Secret)
	}
	nfs.Changes = append(slices.Clone(fs.Changes), nfs.Changes...)
	base.Changes = append(base.Changes, "a secure note in sesh: the entry has no password or TOTP key")
	n := importer.NoteEntry(base, service, note, &nfs)
	n.Details.URL = urlText
	return []*importer.Entry{importer.Checked(n)}
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
