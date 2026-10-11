// Package keepass reads KeePass's XML export ("KeePass XML (2.x)"), as
// KeePassXC and KeePass 2 write it. The format follows KeePassXC's own
// code (github.com/keepassxreboot/keepassxc, src/format/KdbxXmlWriter.cpp
// and src/core/Totp.cpp, at 2.7.10), and is tested against exports made by
// the KeePassXC app and its command-line tool.
package keepass

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Export is a KeePass XML export's groups and entries.
type Export struct {
	Meta Meta `xml:"Meta"`
	Root struct {
		Group Group `xml:"Group"`
	} `xml:"Root"`
}

// Meta is the database's own settings that the import needs.
type Meta struct {
	Generator        string `xml:"Generator"`
	RecycleBinUUID   string `xml:"RecycleBinUUID"`
	RecycleBinEnable string `xml:"RecycleBinEnabled"`
}

// Group is a group, with its entries and the groups in it.
type Group struct {
	UUID    string  `xml:"UUID"`
	Name    string  `xml:"Name"`
	Entries []Entry `xml:"Entry"`
	Groups  []Group `xml:"Group"`
}

// Entry is one entry. Its standard fields (Title, UserName, Password, URL,
// Notes) and custom ones are all Strings.
type Entry struct {
	Times    Times    `xml:"Times"`
	UUID     string   `xml:"UUID"`
	Tags     string   `xml:"Tags"`
	Strings  []String `xml:"String"`
	Binaries []struct {
		Key string `xml:"Key"`
	} `xml:"Binary"`
	History struct {
		Entries []Entry `xml:"Entry"`
	} `xml:"History"`
}

// String is one of an entry's fields.
type String struct {
	Key   string `xml:"Key"`
	Value struct {
		Text string `xml:",chardata"`
		// Protected is set only inside a .kdbx file, where the value is
		// encrypted; ProtectInMemory marks a protected field in an export.
		Protected       string `xml:"Protected,attr"`
		ProtectInMemory string `xml:"ProtectInMemory,attr"`
	} `xml:"Value"`
}

// Times are an entry's times.
type Times struct {
	CreationTime         Time   `xml:"CreationTime"`
	LastModificationTime Time   `xml:"LastModificationTime"`
	ExpiryTime           Time   `xml:"ExpiryTime"`
	Expires              string `xml:"Expires"`
}

// Time is a time as an export writes it (KdbxXmlWriter::writeDateTime):
// ISO 8601 from a KDBX 3 database, or from a KDBX 4 one base64 of a
// little-endian int64 count of seconds since 0001-01-01 UTC.
type Time struct{ time.Time }

// secondsTo1970 is 0001-01-01 UTC in Unix time.
const secondsTo1970 = 62135596800

// UnmarshalText reads either form; an empty one is the zero time.
func (t *Time) UnmarshalText(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil
	}
	if p, err := time.Parse(time.RFC3339, s); err == nil {
		t.Time = p.UTC()
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 8 {
		return fmt.Errorf("a time doesn't read: %q", s)
	}
	secs := int64(binary.LittleEndian.Uint64(raw)) //nolint:gosec // a signed count, as KeePass writes it
	t.Time = time.Unix(secs-secondsTo1970, 0).UTC()
	return nil
}

// field is the value of an entry's field named key, and whether it's
// protected.
func (e *Entry) field(key string) (value string, protected bool) {
	for _, s := range e.Strings {
		if s.Key == key {
			return s.Value.Text, strings.EqualFold(s.Value.ProtectInMemory, "True")
		}
	}
	return "", false
}

// Field is the value of an entry's field named key, and whether it has it.
func (e *Entry) Field(key string) (string, bool) {
	for _, s := range e.Strings {
		if s.Key == key {
			return s.Value.Text, true
		}
	}
	return "", false
}

// The KDBX file's first bytes (KeePass2.h SIGNATURE_1, SIGNATURE_2).
var kdbxSignature = []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5}

// csvHeader is the first line of KeePassXC's CSV export (CsvExporter.cpp).
const csvHeader = `"Group","Title","Username","Password","URL","Notes","TOTP"`

// IsExport reports whether b looks like a KeePass XML export, a KeePass
// database, or KeePassXC's CSV export: the last two are recognised to be
// refused with what to do instead.
func IsExport(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\ufeff"))
	if bytes.HasPrefix(b, kdbxSignature) || bytes.HasPrefix(b, []byte(csvHeader)) {
		return true
	}
	head := b[:min(len(b), 512)]
	return bytes.Contains(head, []byte("<KeePassFile>"))
}

// Parse reads a KeePass XML export.
func Parse(b []byte) (Export, error) {
	trimmed := bytes.TrimPrefix(b, []byte("\ufeff"))
	switch {
	case bytes.HasPrefix(trimmed, kdbxSignature):
		return Export{}, errors.New(`this is a KeePass database (.kdbx), which sesh doesn't read: in KeePassXC, export it with Database > Export > XML File, and import that`)
	case bytes.HasPrefix(trimmed, []byte(csvHeader)):
		return Export{}, errors.New(`this is KeePassXC's CSV export, which sesh doesn't read: it leaves out custom fields and tags. Export with Database > Export > XML File instead`)
	}
	var exp Export
	if err := xml.Unmarshal(b, &exp); err != nil {
		return Export{}, fmt.Errorf("this isn't a KeePass XML export: %w", err)
	}
	if exp.Root.Group.UUID == "" && exp.Root.Group.Name == "" {
		return Export{}, errors.New("this isn't a KeePass XML export: it has no groups")
	}
	if protected(&exp.Root.Group) {
		return Export{}, errors.New("this KeePass XML holds encrypted values, as only a .kdbx file does inside: export the database as XML from KeePass or KeePassXC")
	}
	return exp, nil
}

// protected reports whether any value in g is encrypted, which an export
// never is.
func protected(g *Group) bool {
	for i := range g.Entries {
		for _, s := range g.Entries[i].Strings {
			if strings.EqualFold(s.Value.Protected, "True") {
				return true
			}
		}
	}
	for i := range g.Groups {
		if protected(&g.Groups[i]) {
			return true
		}
	}
	return false
}
