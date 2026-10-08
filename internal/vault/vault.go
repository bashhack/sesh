// Package vault defines sesh's entries, each a kind, a service name, an
// optional username, an encrypted secret, and settings, and the Store
// interface that holds them.
package vault

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bashhack/sesh/internal/totp"
)

// Kind is what an entry holds.
type Kind string

// The kinds of entry.
const (
	KindPassword Kind = "password"
	KindAPIKey   Kind = "api_key"
	KindTOTP     Kind = "totp"
	KindNote     Kind = "secure_note"
)

// Kinds are all the kinds, in the order they're listed to users.
var Kinds = []Kind{KindPassword, KindAPIKey, KindTOTP, KindNote}

// Valid reports whether k is one of the kinds.
func (k Kind) Valid() bool {
	return slices.Contains(Kinds, k)
}

// ErrNotFound is returned for an entry the store doesn't hold.
var ErrNotFound = errors.New("entry not found")

// Key names an entry: kind, service name, and username are unique together.
// The username is optional.
type Key struct {
	Kind     Kind
	Service  string
	Username string
}

// String is the key's text form, kind/service or kind/service/username:
// the ID that --list shows and --delete takes, and what the audit log
// records.
func (k Key) String() string {
	s := string(k.Kind) + "/" + k.Service
	if k.Username != "" {
		s += "/" + k.Username
	}
	return s
}

// Less orders keys by kind, then service name, then username.
func (k Key) Less(o Key) bool {
	if k.Kind != o.Kind {
		return k.Kind < o.Kind
	}
	if k.Service != o.Service {
		return k.Service < o.Service
	}
	return k.Username < o.Username
}

// ParseKey reads a key's text form, as String writes it.
func ParseKey(s string) (Key, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return Key{}, fmt.Errorf("entry ID %q: want kind/service or kind/service/username", s)
	}
	k := Key{Kind: Kind(parts[0]), Service: parts[1]}
	if len(parts) == 3 {
		k.Username = parts[2]
	}
	if err := k.Validate(); err != nil {
		return Key{}, fmt.Errorf("entry ID %q: %w", s, err)
	}
	return k, nil
}

// MaxNameLength is the most characters a service name or username can have.
const MaxNameLength = 256

// Validate checks that k can name an entry: a known kind, a service name,
// and a service name and username that pass CheckName.
func (k Key) Validate() error {
	if !k.Kind.Valid() {
		return fmt.Errorf("unknown kind %q", k.Kind)
	}
	if k.Service == "" {
		return errors.New("the service name is empty")
	}
	if err := CheckName("service name", k.Service); err != nil {
		return err
	}
	return CheckName("username", k.Username)
}

// CheckName refuses a name, called what in errors, that would break an
// entry's ID or be hard to tell apart from another: a "/" (which the ID
// uses as a separator), a control character, text that isn't valid UTF-8,
// a text-direction control anywhere, a space or an invisible character at
// either end, an invisible character inside, or more than MaxNameLength
// characters.
func CheckName(what, v string) error {
	if strings.Contains(v, "/") {
		return fmt.Errorf("the %s %q contains \"/\"", what, v)
	}
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return fmt.Errorf("the %s %q contains a control character", what, v)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("the %s %q isn't valid text", what, v)
	}
	if strings.IndexFunc(v, isDirectionControl) >= 0 {
		return fmt.Errorf("the %s %q contains a text-direction control character", what, v)
	}
	if v != "" {
		first, _ := utf8.DecodeRuneInString(v)
		last, _ := utf8.DecodeLastRuneInString(v)
		if unicode.IsSpace(first) || unicode.IsSpace(last) {
			return fmt.Errorf("the %s %q starts or ends with a space", what, v)
		}
		if isInvisible(first) || isInvisible(last) {
			return fmt.Errorf("the %s %q starts or ends with an invisible character", what, v)
		}
	}
	if hasHiddenRune(v) {
		return fmt.Errorf("the %s %q contains an invisible character", what, v)
	}
	if n := utf8.RuneCountInString(v); n > MaxNameLength {
		return fmt.Errorf("the %s is %d characters long; the most is %d", what, n, MaxNameLength)
	}
	return nil
}

// MaxTagLength is the most characters a tag can have.
const MaxTagLength = 64

// MaxFolderLength is the most characters a folder can have, "/"s included.
const MaxFolderLength = 256

// CheckTag refuses a tag that breaks the label rules (see checkLabel) or
// has more than MaxTagLength characters.
func CheckTag(t string) error {
	if err := checkLabel(t); err != nil {
		return fmt.Errorf("the tag %q %w", t, err)
	}
	if n := utf8.RuneCountInString(t); n > MaxTagLength {
		return fmt.Errorf("the tag is %d characters long; the most is %d", n, MaxTagLength)
	}
	return nil
}

// CheckFolder refuses a folder that isn't parts joined by "/", each made as
// a tag is, or has more than MaxFolderLength characters. "" is no folder.
func CheckFolder(f string) error {
	if f == "" {
		return nil
	}
	if n := utf8.RuneCountInString(f); n > MaxFolderLength {
		return fmt.Errorf("the folder is %d characters long; the most is %d", n, MaxFolderLength)
	}
	for part := range strings.SplitSeq(f, "/") {
		if part == "" {
			return fmt.Errorf("the folder %q has an empty part: \"/\" separates folders, so it can't come first, last, or twice in a row", f)
		}
		if strings.Trim(part, ".") == "" {
			return fmt.Errorf("the folder %q has a part that's only dots, which reads like a path", f)
		}
		if err := checkLabel(part); err != nil {
			return fmt.Errorf("the folder %q %w", f, err)
		}
		if n := utf8.RuneCountInString(part); n > MaxTagLength {
			return fmt.Errorf("the folder %q: a part is %d characters long; the most is %d", f, n, MaxTagLength)
		}
	}
	return nil
}

// checkLabel refuses an empty tag or folder part, one starting with "-"
// (which a command would read as a flag), or one holding anything but
// letters (with their accent and vowel marks), digits, "-", "_" and ".".
func checkLabel(v string) error {
	if v == "" {
		return errors.New("is empty")
	}
	if strings.HasPrefix(v, "-") {
		return errors.New(`can't start with "-"`)
	}
	for i, r := range v {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' ||
			// A mark belongs to the character before it: "é" can be
			// written as "e" and an accent.
			(i > 0 && unicode.In(r, unicode.Mn, unicode.Mc))
		if !ok || isInvisible(r) {
			return fmt.Errorf("contains %s: use letters, digits, \"-\", \"_\" and \".\"", quoteRune(r))
		}
	}
	if hasHiddenRune(v) {
		return errors.New("contains an invisible character")
	}
	return nil
}

// quoteRune quotes r for an error, escaped when it wouldn't show on its
// own, such as a blank letter or an accent.
func quoteRune(r rune) string {
	if r == ' ' || (unicode.IsGraphic(r) && !isInvisible(r) && !unicode.In(r, unicode.Mn, unicode.Mc, unicode.Me) && !unicode.IsSpace(r)) {
		return fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf("%+q", r)
}

// Filing is where an entry being stored is filed. The zero Filing leaves
// an entry where it is.
type Filing struct {
	// Folder, when FolderSet, is the folder the entry moves to ("" for
	// none).
	Folder string
	// Tags are added to the entry's tags.
	Tags      []string
	FolderSet bool
}

// IsZero reports whether f changes nothing.
func (f Filing) IsZero() bool {
	return !f.FolderSet && len(f.Tags) == 0
}

// Check refuses a folder or tag no entry can have.
func (f Filing) Check() error {
	if err := CheckFolder(f.Folder); err != nil {
		return err
	}
	for _, t := range f.Tags {
		if err := CheckTag(t); err != nil {
			return err
		}
	}
	return nil
}

// Apply files e as f says.
func (f Filing) Apply(e *Entry) {
	if f.FolderSet {
		e.Folder = f.Folder
	}
	e.Tags = NormalizeTags(append(slices.Clone(e.Tags), f.Tags...))
}

// NormalizeTags returns tags sorted, each once.
func NormalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := slices.Clone(tags)
	slices.Sort(out)
	return slices.Compact(out)
}

// isDirectionControl reports whether r changes the direction text is shown
// in, which can make a name display as another.
func isDirectionControl(r rune) bool {
	return r == 0x061C || r == 0x200E || r == 0x200F ||
		(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// isInvisible reports whether r shows as nothing at the edge of a name: a
// format character (such as a zero-width space or soft hyphen), a filler or
// blank that Unicode counts as a letter or symbol, or a mark that attaches
// to nothing visible (the combining grapheme joiner, Khmer inherent vowels,
// Mongolian variation selectors).
func isInvisible(r rune) bool {
	switch {
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, r == 0x2800,
		r == 0x034F, r == 0x17B4, r == 0x17B5, r >= 0x180B && r <= 0x180F:
		return true
	}
	return unicode.Is(unicode.Cf, r) && !isTag(r)
}

// isTag reports whether r is a Unicode tag character, which flag emoji
// such as Scotland's are spelled with.
func isTag(r rune) bool {
	return r >= 0xE0020 && r <= 0xE007F
}

// hasHiddenRune reports whether v holds a character that's invisible where
// it stands: a format character other than the zero-width joiner and
// non-joiner (which emoji and some scripts need), a line or paragraph
// separator, the combining grapheme joiner, a tag character outside a flag
// emoji (🏴 followed by tags up to the cancel tag), or a variation selector
// that doesn't follow a symbol or a keycap's digit, # or *.
func hasHiddenRune(v string) bool {
	rs := []rune(v)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1F3F4:
			j := i + 1
			for j < len(rs) && isTag(rs[j]) && rs[j] != 0xE007F {
				j++
			}
			if j > i+1 && j < len(rs) && rs[j] == 0xE007F {
				i = j // a whole flag
			}
		case isTag(r):
			return true
		case isVariationSelector(r):
			if i == 0 || !takesVariationSelector(rs[i-1]) {
				return true
			}
		case r == 0x200C, r == 0x200D:
		case r == 0x034F, unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return true
		}
	}
	return false
}

// isVariationSelector reports whether r picks how the character before it
// is drawn, such as emoji or text style, or a Han character's variant.
func isVariationSelector(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// takesVariationSelector reports whether a variation selector after r
// changes how r looks: after a symbol, a keycap's digit, # or *, the emoji
// whose base isn't a symbol (‼ ⁉ ℹ 〰 〽), or a Han or Myanmar letter. After
// any other letter it shows nothing.
func takesVariationSelector(r rune) bool {
	switch {
	case unicode.IsSymbol(r), strings.ContainsRune("0123456789#*\u203c\u2049\u2139\u3030\u303d", r):
		return true
	}
	return unicode.Is(unicode.Han, r) || unicode.Is(unicode.Myanmar, r)
}

// AWSKey is the entry holding an AWS profile's MFA secret: the TOTP entry
// for service "aws", with the profile ("default" if none) as its username.
// Its settings name the MFA device.
func AWSKey(profile string) Key {
	if profile == "" {
		profile = "default"
	}
	return Key{Kind: KindTOTP, Service: "aws", Username: profile}
}

// Settings are an entry's non-secret options.
type Settings struct {
	// AWSMFADevice is the MFA device (its ARN) the AWS provider sends
	// codes from this entry for.
	AWSMFADevice string `json:"aws_mfa_device,omitempty"`
	// TOTP is a TOTP entry's code settings; zero means the usual ones
	// (SHA1, 6 digits, 30 seconds).
	TOTP totp.Params `json:"totp,omitzero"`
}

// IsZero reports whether s sets nothing.
func (s Settings) IsZero() bool {
	return s == Settings{}
}

// Entry is an entry without its secret.
type Entry struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Key
	// Folder is the folder the entry is in, "" for none; folders nest with
	// "/". It files the entry; it isn't part of its ID.
	Folder string
	// Tags are the entry's tags, sorted, each once.
	Tags []string
	// URL is the entry's web address, "" for none.
	URL string
	// Fields are the entry's custom fields, in order; a secret one's
	// value is left out (see Store.Details).
	Fields   []Field
	Settings Settings
	// HasNotes reports whether the entry has notes (see Store.Details).
	HasNotes bool
}

// Filter narrows List; an empty field matches every entry.
type Filter struct {
	Kind    Kind
	Service string
	// Folder, when FolderSet, keeps the entries in that folder or one under
	// it; "" keeps those in no folder.
	Folder string
	// Tags keeps the entries that have every one of them.
	Tags      []string
	FolderSet bool
}

// Matches reports whether f lets e through.
func (f *Filter) Matches(e *Entry) bool {
	if (f.Kind != "" && e.Kind != f.Kind) || (f.Service != "" && e.Service != f.Service) {
		return false
	}
	if f.FolderSet && !InFolder(e.Folder, f.Folder) {
		return false
	}
	for _, t := range f.Tags {
		if !slices.Contains(e.Tags, t) {
			return false
		}
	}
	return true
}

// InFolder reports whether an entry filed in folder is in want or a folder
// under it; want "" means in no folder.
func InFolder(folder, want string) bool {
	if want == "" {
		return folder == ""
	}
	return folder == want || strings.HasPrefix(folder, want+"/")
}

// Store holds entries. Every method returns an error wrapping ErrNotFound
// for an entry it doesn't hold.
type Store interface {
	// Get returns the entry's secret, which the caller zeroes.
	Get(k Key) ([]byte, error)
	// Put creates the entry or replaces its secret, keeping its settings,
	// folder, tags, details, and creation time.
	Put(k Key, secret []byte) error
	// Save creates or replaces the entry's secret, settings, folder, tags,
	// and times (a zero time means now), keeping its details (see
	// SetDetails). Import and key changes use it.
	Save(e *Entry, secret []byte) error
	// SaveWithDetails is Save, also replacing the entry's details with d
	// (none, when d is zero), all in one write; d must pass Details.Check.
	SaveWithDetails(e *Entry, secret []byte, d *Details) error
	// Details returns the entry's URL, notes, and custom fields, secret
	// values included, which the caller zeroes (Details.Zero).
	Details(k Key) (Details, error)
	// SetDetails replaces the entry's URL, notes, and custom fields, after
	// Details.Check.
	SetDetails(k Key, d *Details) error
	// SetSettings replaces the entry's settings.
	SetSettings(k Key, s Settings) error
	// Lookup returns the entry without its secret.
	Lookup(k Key) (Entry, error)
	// Exists returns nil when the store holds the entry. It reads nothing
	// else of it, so an entry whose settings or times are damaged can
	// still be found to delete or replace.
	Exists(k Key) error
	// List returns the entries f matches, ordered by Key.Less.
	List(f *Filter) ([]Entry, error)
	// Delete removes the entry.
	Delete(k Key) error
	// DeleteMany removes every entry keys name, or none: when one is
	// missing it returns an error wrapping ErrNotFound and removes nothing.
	// A key named twice is removed once.
	DeleteMany(keys []Key) error
}
