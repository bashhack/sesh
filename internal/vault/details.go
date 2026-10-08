package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bashhack/sesh/internal/secure"
)

// MaxURLLength is the most characters an entry's URL can have.
const MaxURLLength = 2048

// MaxFields is the most custom fields an entry can have.
const MaxFields = 50

// MaxFieldNameLength is the most characters a field's name can have.
const MaxFieldNameLength = 64

// MaxDetailsSize is the most bytes an entry's notes and field values can
// take together, the same as its secret.
const MaxDetailsSize = 1 << 20

// ReservedFieldNames are the names `get --field` uses for the entry's own
// parts, so no custom field can have them.
var ReservedFieldNames = []string{"password", "secret", "url", "notes"}

// Field is a custom field of an entry. A secret one's value is encrypted
// with the entry's notes; a plain one's is stored as text.
type Field struct {
	Name string
	// Value is the field's value; in an Entry, a secret field's is nil.
	Value  []byte
	Secret bool
}

// Details are an entry's URL, notes, and custom fields, with the values of
// its secret ones.
type Details struct {
	URL    string
	Notes  []byte
	Fields []Field
}

// IsZero reports whether d holds nothing.
func (d *Details) IsZero() bool {
	return d.URL == "" && len(d.Notes) == 0 && len(d.Fields) == 0
}

// Zero overwrites d's notes and secret values.
func (d *Details) Zero() {
	secure.SecureZeroBytes(d.Notes)
	for _, f := range d.Fields {
		if f.Secret {
			secure.SecureZeroBytes(f.Value)
		}
	}
}

// Field returns the field named name, in any case, if d has one.
func (d *Details) Field(name string) (Field, bool) {
	i := slices.IndexFunc(d.Fields, func(f Field) bool { return strings.EqualFold(f.Name, name) })
	if i < 0 {
		return Field{}, false
	}
	return d.Fields[i], true
}

// Check refuses details an entry of kind can't have:
//   - notes on a secure note, whose secret is the note;
//   - a URL or plain value that isn't one line of valid text, or a URL
//     longer than MaxURLLength;
//   - notes or a secret value that isn't valid text, or has a control
//     character other than a tab or line break (they may hold several
//     lines);
//   - a field name that breaks the tag rules, is reserved, is used twice
//     (in any case), or is longer than MaxFieldNameLength;
//   - an empty value, more than MaxFields fields, or notes and values
//     together over MaxDetailsSize.
func (d *Details) Check(kind Kind) error {
	if kind == KindNote && len(d.Notes) > 0 {
		return errors.New("a secure note can't have notes: its secret is the note")
	}
	if err := checkText("notes", d.Notes); err != nil {
		return err
	}
	if err := checkLine("URL", d.URL); err != nil {
		return err
	}
	if n := utf8.RuneCountInString(d.URL); n > MaxURLLength {
		return fmt.Errorf("the URL is %d characters long; the most is %d", n, MaxURLLength)
	}
	if len(d.Fields) > MaxFields {
		return fmt.Errorf("an entry can have at most %d fields, not %d", MaxFields, len(d.Fields))
	}
	size := len(d.Notes)
	seen := make(map[string]string, len(d.Fields))
	for _, f := range d.Fields {
		if err := CheckFieldName(f.Name); err != nil {
			return err
		}
		if first, ok := seen[strings.ToLower(f.Name)]; ok {
			if first == f.Name {
				return fmt.Errorf("the field %q is there twice", f.Name)
			}
			return fmt.Errorf("the field %q is there twice (as %q)", f.Name, first)
		}
		seen[strings.ToLower(f.Name)] = f.Name
		if len(f.Value) == 0 {
			return fmt.Errorf("the field %q has no value", f.Name)
		}
		if f.Secret {
			if err := checkText(fmt.Sprintf("field %q", f.Name), f.Value); err != nil {
				return err
			}
		} else if err := checkLine(fmt.Sprintf("field %q", f.Name), string(f.Value)); err != nil {
			return err
		}
		size += len(f.Value)
	}
	if size > MaxDetailsSize {
		return fmt.Errorf("the notes and field values take %d bytes together; the most is %d", size, MaxDetailsSize)
	}
	return nil
}

// CheckFieldName refuses a field name that breaks the tag rules (letters,
// digits, "-", "_" and "."), is reserved, or is longer than
// MaxFieldNameLength.
func CheckFieldName(name string) error {
	if err := checkLabel(name); err != nil {
		return fmt.Errorf("the field name %q %w", name, err)
	}
	if n := utf8.RuneCountInString(name); n > MaxFieldNameLength {
		return fmt.Errorf("the field name is %d characters long; the most is %d", n, MaxFieldNameLength)
	}
	if slices.Contains(ReservedFieldNames, strings.ToLower(name)) {
		return fmt.Errorf("the field name %q is reserved for the entry's own %s", name, strings.ToLower(name))
	}
	return nil
}

// checkText refuses a value, called what in errors, that isn't valid text
// or has a control character other than a tab or a line break, which a
// terminal could take as a command when it's shown.
func checkText(what string, v []byte) error {
	isnt, has := "isn't", "contains"
	if what == "notes" {
		isnt, has = "aren't", "contain"
	}
	if !utf8.Valid(v) {
		return fmt.Errorf("the %s %s valid text", what, isnt)
	}
	if bytes.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' }) >= 0 {
		return fmt.Errorf("the %s %s a control character", what, has)
	}
	return nil
}

// checkLine refuses a value, called what in errors, that isn't valid text
// or has a control or text-direction character.
func checkLine(what, v string) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("the %s isn't valid text", what)
	}
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return fmt.Errorf("the %s contains a control character, such as a line break", what)
	}
	if strings.IndexFunc(v, isDirectionControl) >= 0 {
		return fmt.Errorf("the %s contains a text-direction control character", what)
	}
	return nil
}

// plainDetails is how the readable part of an entry's details is stored:
// the field names in order, which are secret, the plain values, and
// whether there are notes.
type plainDetails struct {
	Fields []plainField `json:"fields,omitempty"`
	Notes  bool         `json:"notes,omitempty"`
}

type plainField struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Secret bool   `json:"secret,omitempty"`
}

// EncodeDetails splits d into what's stored as it is, the URL and plain
// JSON ("" when there's nothing), and what's sealed: the notes and secret
// values, nil when there are none. The caller zeroes sealed.
func EncodeDetails(d *Details) (url, plain string, sealed []byte, err error) {
	var p plainDetails
	p.Notes = len(d.Notes) > 0
	var secrets []Field
	for _, f := range d.Fields {
		pf := plainField{Name: f.Name, Secret: f.Secret}
		if f.Secret {
			secrets = append(secrets, f)
		} else {
			pf.Value = string(f.Value)
		}
		p.Fields = append(p.Fields, pf)
	}
	if p.Notes || len(p.Fields) > 0 {
		b, err := json.Marshal(p)
		if err != nil {
			return "", "", nil, fmt.Errorf("encode details: %w", err)
		}
		plain = string(b)
	}
	if p.Notes || len(secrets) > 0 {
		sealed = sealedBytes(d.Notes, secrets)
	}
	return d.URL, plain, sealed, nil
}

// sealedBytes lays out the notes and secret values to be sealed: a version
// byte, the notes, the number of values, and each name and value, every
// one a 4-byte big-endian length and its bytes.
func sealedBytes(notes []byte, secrets []Field) []byte {
	size := 1 + 4 + len(notes) + 4
	for _, f := range secrets {
		size += 8 + len(f.Name) + len(f.Value)
	}
	b := make([]byte, 0, size)
	b = append(b, 1)
	b = appendPart(b, notes)
	b = binary.BigEndian.AppendUint32(b, uint32(len(secrets))) //nolint:gosec // at most MaxFields
	for _, f := range secrets {
		b = appendPart(b, []byte(f.Name))
		b = appendPart(b, f.Value)
	}
	return b
}

func appendPart(b, part []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(part))) //nolint:gosec // parts are at most MaxDetailsSize
	return append(b, part...)
}

// DecodeEntryDetails reads the stored URL and plain JSON into e: its URL,
// whether it has notes, and its fields, without secret values.
func DecodeEntryDetails(e *Entry, url, plain string) error {
	e.URL = url
	e.HasNotes, e.Fields = false, nil
	if plain == "" {
		return nil
	}
	var p plainDetails
	if err := json.Unmarshal([]byte(plain), &p); err != nil {
		return fmt.Errorf("read the details of %s: %w", e.Key, err)
	}
	e.HasNotes = p.Notes
	for _, f := range p.Fields {
		field := Field{Name: f.Name, Secret: f.Secret}
		if !f.Secret {
			field.Value = []byte(f.Value)
		}
		e.Fields = append(e.Fields, field)
	}
	return nil
}

// DecodeDetails puts the stored parts of an entry's details back
// together: e as DecodeEntryDetails read it, and the opened sealed bytes,
// nil when there are none. The secret values must be the ones e names;
// the result holds copies, which the caller zeroes.
func DecodeDetails(e *Entry, sealed []byte) (_ Details, err error) {
	d := Details{URL: e.URL}
	secrets := map[string][]byte{}
	// On failure, every secret read so far is zeroed: those in d, and
	// those still waiting in secrets.
	defer func() {
		if err != nil {
			d.Zero()
			for _, v := range secrets {
				secure.SecureZeroBytes(v)
			}
		}
	}()
	if sealed != nil {
		notes, values, err := parseSealed(sealed)
		if err != nil {
			return Details{}, fmt.Errorf("read the details of %s: %w", e.Key, err)
		}
		d.Notes, secrets = notes, values
	}
	if e.HasNotes != (len(d.Notes) > 0) {
		return Details{}, fmt.Errorf("read the details of %s: the notes don't match their record", e.Key)
	}
	for _, f := range e.Fields {
		field := Field{Name: f.Name, Secret: f.Secret}
		if f.Secret {
			v, ok := secrets[f.Name]
			if !ok {
				return Details{}, fmt.Errorf("read the details of %s: the secret field %q has no value", e.Key, f.Name)
			}
			field.Value = v
			delete(secrets, f.Name)
		} else {
			field.Value = slices.Clone(f.Value)
		}
		d.Fields = append(d.Fields, field)
	}
	if len(secrets) > 0 {
		return Details{}, fmt.Errorf("read the details of %s: there are secret values for fields it doesn't have", e.Key)
	}
	return d, nil
}

// parseSealed reads sealedBytes' layout, copying each part out.
func parseSealed(b []byte) (notes []byte, values map[string][]byte, err error) {
	if len(b) == 0 || b[0] != 1 {
		return nil, nil, errors.New("unknown layout")
	}
	b = b[1:]
	next := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		n := int64(binary.BigEndian.Uint32(b))
		if n > int64(len(b)-4) {
			return nil, false
		}
		part := slices.Clone(b[4 : 4+n])
		b = b[4+n:]
		return part, true
	}
	bad := errors.New("damaged")
	notes, ok := next()
	if !ok {
		return nil, nil, bad
	}
	if len(notes) == 0 {
		notes = nil
	}
	if len(b) < 4 {
		secure.SecureZeroBytes(notes)
		return nil, nil, bad
	}
	count := binary.BigEndian.Uint32(b)
	b = b[4:]
	values = map[string][]byte{}
	fail := func() ([]byte, map[string][]byte, error) {
		secure.SecureZeroBytes(notes)
		for _, v := range values {
			secure.SecureZeroBytes(v)
		}
		return nil, nil, bad
	}
	if count > MaxFields {
		return fail()
	}
	for range count {
		name, ok := next()
		if !ok {
			return fail()
		}
		value, ok := next()
		if !ok {
			return fail()
		}
		if _, ok := values[string(name)]; ok {
			secure.SecureZeroBytes(value)
			return fail()
		}
		values[string(name)] = value
	}
	if len(b) != 0 {
		return fail()
	}
	return notes, values, nil
}

// DetailsChange is a change to an entry's details: what it sets is
// changed, and the rest kept.
type DetailsChange struct {
	// URL, when not nil, is the new URL; "" removes it.
	URL *string
	// Notes are the new notes when SetNotes; none removes them. The caller
	// zeroes them.
	Notes []byte
	// Set are fields to add, or to put in place of the field of that name,
	// in any case; Remove names fields to take out, in any case.
	Set    []Field
	Remove []string
	// NotesBase, when HasNotesBase, are the notes the new ones were written
	// from, as in an editor: the change is refused if the entry's notes
	// are no longer those. The caller zeroes them.
	NotesBase    []byte
	SetNotes     bool
	HasNotesBase bool
}

// ErrNotesChanged is notes changed by another command while new ones were
// being written from them.
var ErrNotesChanged = errors.New("the notes were changed by another sesh command meanwhile; run this again")

// IsZero reports whether c changes nothing.
func (c *DetailsChange) IsZero() bool {
	return c.URL == nil && !c.SetNotes && len(c.Set) == 0 && len(c.Remove) == 0
}

// Apply makes c's change to d, and says what changed, as the audit log
// records it. A field to remove that d doesn't have is an error.
func (c *DetailsChange) Apply(d *Details) (string, error) {
	if c.HasNotesBase && !bytes.Equal(c.NotesBase, d.Notes) {
		return "", ErrNotesChanged
	}
	names := make([]string, len(d.Fields))
	for i, f := range d.Fields {
		names[i] = f.Name
	}
	var what []string
	if c.URL != nil && *c.URL != d.URL {
		what = append(what, changeWord("URL", d.URL != "", *c.URL != ""))
		d.URL = *c.URL
	}
	if c.SetNotes && !bytes.Equal(c.Notes, d.Notes) {
		what = append(what, changeWord("notes", len(d.Notes) > 0, len(c.Notes) > 0))
		secure.SecureZeroBytes(d.Notes)
		d.Notes = nil
		if len(c.Notes) > 0 {
			d.Notes = bytes.Clone(c.Notes)
		}
	}
	for _, f := range c.Set {
		f.Value = bytes.Clone(f.Value)
		i := slices.IndexFunc(d.Fields, func(g Field) bool { return strings.EqualFold(g.Name, f.Name) })
		if i < 0 {
			d.Fields = append(d.Fields, f)
			what = append(what, "field "+f.Name+" added")
			continue
		}
		old := d.Fields[i]
		if old.Secret && !f.Secret {
			return "", fmt.Errorf("%s is a secret field: set it with --secret-field %s, or remove it first to make it plain", old.Name, old.Name)
		}
		if old.Name == f.Name && old.Secret == f.Secret && bytes.Equal(old.Value, f.Value) {
			secure.SecureZeroBytes(f.Value)
			continue
		}
		if old.Secret {
			secure.SecureZeroBytes(old.Value)
		}
		d.Fields[i] = f
		what = append(what, "field "+f.Name+" changed")
	}
	for _, name := range c.Remove {
		i := slices.IndexFunc(d.Fields, func(g Field) bool { return strings.EqualFold(g.Name, name) })
		if i < 0 {
			return "", NoFieldToRemove(name, names)
		}
		what = append(what, "field "+d.Fields[i].Name+" removed")
		if d.Fields[i].Secret {
			secure.SecureZeroBytes(d.Fields[i].Value)
		}
		d.Fields = slices.Delete(d.Fields, i, i+1)
	}
	return strings.Join(what, ", "), nil
}

// NoFieldToRemove is the error for removing a field named name from an
// entry whose fields are names.
func NoFieldToRemove(name string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("there's no field %q to remove; it has no fields", name)
	}
	return fmt.Errorf("there's no field %q to remove; its fields: %s", name, strings.Join(names, ", "))
}

// changeWord says what happened to a part: added, changed, or removed.
func changeWord(part string, had, has bool) string {
	switch {
	case !had:
		return part + " added"
	case !has:
		return part + " removed"
	}
	return part + " changed"
}
