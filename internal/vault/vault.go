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

// MaxNameLength is the most characters a new entry's service name or
// username can have.
const MaxNameLength = 256

// Validate checks that k can name an entry at all: a known kind, a service
// name, and names without "/" (which the text form uses) or control
// characters. Every entry the vault holds passes it, so it's all that
// opening, copying, and deleting an entry need.
func (k Key) Validate() error {
	if !k.Kind.Valid() {
		return fmt.Errorf("unknown kind %q", k.Kind)
	}
	if k.Service == "" {
		return errors.New("the service name is empty")
	}
	for _, f := range []struct{ name, v string }{{"service name", k.Service}, {"username", k.Username}} {
		if strings.Contains(f.v, "/") {
			return fmt.Errorf("the %s %q contains \"/\"", f.name, f.v)
		}
		if strings.IndexFunc(f.v, unicode.IsControl) >= 0 {
			return fmt.Errorf("the %s %q contains a control character", f.name, f.v)
		}
	}
	return nil
}

// ValidateNew is Validate plus CheckNewName's rules, for naming a new
// entry. Entries saved before those rules only need Validate, so they still
// open, copy, and delete.
func (k Key) ValidateNew() error {
	if err := k.Validate(); err != nil {
		return err
	}
	if err := CheckNewName("service name", k.Service); err != nil {
		return err
	}
	return CheckNewName("username", k.Username)
}

// CheckNewName refuses a name, called what in errors, that would be hard to
// tell apart from another: text that isn't valid UTF-8, a text-direction
// control anywhere, a space or an invisible character at either end, an
// invisible character inside, or more than MaxNameLength characters.
func CheckNewName(what, v string) error {
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
	if strings.IndexFunc(v, isHiddenInside) >= 0 {
		return fmt.Errorf("the %s %q contains an invisible character", what, v)
	}
	if n := utf8.RuneCountInString(v); n > MaxNameLength {
		return fmt.Errorf("the %s is %d characters long; the most is %d", what, n, MaxNameLength)
	}
	return nil
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
	return unicode.Is(unicode.Cf, r)
}

// isHiddenInside reports whether r is invisible inside a name: a format
// character other than the zero-width joiner and non-joiner (which emoji
// and some scripts need), or a line or paragraph separator.
func isHiddenInside(r rune) bool {
	if r == 0x200C || r == 0x200D {
		return false
	}
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
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
	Settings Settings
}

// Filter narrows List; an empty field matches every entry.
type Filter struct {
	Kind    Kind
	Service string
}

// Matches reports whether f lets e through.
func (f Filter) Matches(e *Entry) bool {
	return (f.Kind == "" || e.Kind == f.Kind) && (f.Service == "" || e.Service == f.Service)
}

// Store holds entries. Every method returns an error wrapping ErrNotFound
// for an entry it doesn't hold.
type Store interface {
	// Get returns the entry's secret, which the caller zeroes.
	Get(k Key) ([]byte, error)
	// Put creates the entry or replaces its secret, keeping its settings
	// and creation time.
	Put(k Key, secret []byte) error
	// Save creates or replaces the whole entry: secret, settings, and its
	// times (a zero time means now). Import and key changes use it.
	Save(e *Entry, secret []byte) error
	// SetSettings replaces the entry's settings.
	SetSettings(k Key, s Settings) error
	// Lookup returns the entry without its secret.
	Lookup(k Key) (Entry, error)
	// List returns the entries f matches, ordered by Key.Less.
	List(f Filter) ([]Entry, error)
	// Delete removes the entry.
	Delete(k Key) error
}
