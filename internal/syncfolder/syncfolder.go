// Package syncfolder reads and writes a sync folder: the folder, carried
// between computers by any tool (iCloud Drive, Dropbox, Syncthing, a USB
// stick), through which computers keeping their own vaults share entries.
// It holds one file per entry, in entries/, named by the entry's uid, and
// encrypted whole with the vault's key: a file says nothing of the entry
// without it, not even its name.
//
// A file is a header, then the sealed record:
//
//	"SESHSYNC"  8 bytes
//	format      1 byte (1)
//	uid         16 bytes, the entry's
//	key ID      32 bytes, the vault key record's (database.UnlockID) it was sealed with
//	salt        16 bytes
//	sealed      the record as JSON, sealed with the vault's key
//
// The header is the sealing's associated data, so a file's uid and key ID
// can't be changed, nor its record moved to another entry's file, without
// it failing to open.
package syncfolder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/atomicfile"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Sealer seals and opens with the vault's key: sesh's agent, or the key
// unlocked in this process (database.CryptoOracle).
type Sealer interface {
	EncryptEntry(plaintext, aad []byte) (encryptedData, salt []byte, err error)
	DecryptEntry(encryptedData, salt, aad []byte) ([]byte, error)
}

const (
	magic      = "SESHSYNC"
	format     = 1
	saltLen    = 16
	headerLen  = len(magic) + 1 + 16 + 32
	aadTag     = "sesh-sync-v1"
	entriesDir = "entries"
	// Ext ends every entry file's name; sync tools' copies of a file
	// ("x (conflicted copy).sesh", "x.sync-conflict-….sesh", "x 2.sesh")
	// keep it.
	Ext = ".sesh"
	// MaxFileSize is the most an entry file may be: a secret of
	// database.MaxSecretSize with its earlier ones, as JSON, fits well
	// within it.
	MaxFileSize = 64 << 20
)

// ErrNewerFormat is a file written by a newer sesh, in a format this one
// doesn't read.
var ErrNewerFormat = errors.New("written by a newer sesh: update sesh to read it")

// Header is what a file says unencrypted: whose it is and the key it was
// sealed with.
type Header struct {
	UID   [16]byte
	KeyID [32]byte
}

// UIDString is the header's uid as entries.uid has it: 32 hex characters.
func (h *Header) UIDString() string { return hex.EncodeToString(h.UID[:]) }

// NewHeader is the header for the entry uid (as entries.uid has it), sealed
// with the key record keyID (database.UnlockID).
func NewHeader(uid, keyID string) (Header, error) {
	var h Header
	u, err := hex.DecodeString(uid)
	if err != nil || len(u) != len(h.UID) {
		return h, fmt.Errorf("uid %q isn't 16 bytes in hex", uid)
	}
	k, err := hex.DecodeString(keyID)
	if err != nil || len(k) != len(h.KeyID) {
		return h, fmt.Errorf("key ID %q isn't 32 bytes in hex", keyID)
	}
	copy(h.UID[:], u)
	copy(h.KeyID[:], k)
	return h, nil
}

// KeyIDString is the header's key ID as database.UnlockID gives it.
func (h *Header) KeyIDString() string { return hex.EncodeToString(h.KeyID[:]) }

func (h *Header) bytes() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, magic...)
	b = append(b, format)
	b = append(b, h.UID[:]...)
	return append(b, h.KeyID[:]...)
}

// aad is the sealing's associated data for header bytes hb.
func aad(hb []byte) []byte { return append([]byte(aadTag), hb...) }

// ParseHeader reads a file's header, without opening it.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	switch {
	case len(b) < len(magic) || string(b[:len(magic)]) != magic:
		return h, errors.New("not a sesh sync file")
	case len(b) <= len(magic):
		return h, errors.New("cut short")
	case b[len(magic)] > format:
		return h, ErrNewerFormat
	case b[len(magic)] != format:
		return h, fmt.Errorf("format %d isn't one sesh writes", b[len(magic)])
	case len(b) < headerLen+saltLen:
		return h, errors.New("cut short")
	}
	copy(h.UID[:], b[len(magic)+1:])
	copy(h.KeyID[:], b[len(magic)+1+len(h.UID):])
	return h, nil
}

// Record is an entry as it travels: everything a computer keeps of it,
// but its uid, which the header has. A record for an entry deleted for
// good (Purged) keeps nothing else but its version and computer.
type Record struct {
	Created time.Time `json:"created,omitzero"`
	Updated time.Time `json:"updated,omitzero"`
	// Deleted is when the entry went to the trash; zero for one that isn't
	// there.
	Deleted time.Time `json:"deleted,omitzero"`
	// Purged is when the entry was deleted for good; zero for one that
	// wasn't.
	Purged   time.Time  `json:"purged,omitzero"`
	Kind     vault.Kind `json:"kind,omitempty"`
	Service  string     `json:"service,omitempty"`
	Username string     `json:"username,omitempty"`
	// Computer is the name of the computer that made this version.
	Computer string         `json:"computer"`
	URL      string         `json:"url,omitempty"`
	Folder   string         `json:"folder,omitempty"`
	Secret   []byte         `json:"secret,omitempty"`
	Notes    []byte         `json:"notes,omitempty"`
	Fields   []Field        `json:"fields,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	History  []Earlier      `json:"history,omitempty"`
	Settings vault.Settings `json:"settings,omitzero"`
	// Version only goes up: each version written is above every one the
	// computer writing it has seen for the entry.
	Version uint64 `json:"version"`
}

// Field is one of an entry's custom fields, its value whether secret or
// not.
type Field struct {
	Name   string `json:"name"`
	Value  []byte `json:"value"`
	Secret bool   `json:"secret,omitempty"`
}

// Earlier is one of an entry's earlier secrets.
type Earlier struct {
	ReplacedAt time.Time `json:"replaced_at"`
	// FileName is a file entry's file's name, as it was then.
	FileName string `json:"file_name,omitempty"`
	Secret   []byte `json:"secret"`
}

// Wipe zeroes the record's secrets: its secret, notes, fields' values and
// earlier secrets.
func (r *Record) Wipe() {
	secure.SecureZeroBytes(r.Secret)
	secure.SecureZeroBytes(r.Notes)
	for i := range r.Fields {
		secure.SecureZeroBytes(r.Fields[i].Value)
	}
	for i := range r.History {
		secure.SecureZeroBytes(r.History[i].Secret)
	}
}

// Seal is the file for record r of the entry h names, sealed by s.
func Seal(s Sealer, h Header, r *Record) ([]byte, error) {
	plain, err := json.Marshal(r) //nolint:gosec // the record is sealed next, never written as it is
	if err != nil {
		return nil, fmt.Errorf("seal %s: %w", h.UIDString(), err)
	}
	defer secure.SecureZeroBytes(plain)
	hb := h.bytes()
	sealed, salt, err := s.EncryptEntry(plain, aad(hb))
	if err != nil {
		return nil, fmt.Errorf("seal %s: %w", h.UIDString(), err)
	}
	if len(salt) != saltLen {
		return nil, fmt.Errorf("seal %s: a salt of %d bytes, not %d", h.UIDString(), len(salt), saltLen)
	}
	out := make([]byte, 0, len(hb)+saltLen+len(sealed))
	out = append(append(append(out, hb...), salt...), sealed...)
	if len(out) > MaxFileSize {
		return nil, fmt.Errorf("seal %s: %d bytes, over the %d a sync file may be", h.UIDString(), len(out), MaxFileSize)
	}
	return out, nil
}

// Open opens the file b with s: its header, and its record. It fails for a
// file changed in any way since it was sealed, or sealed with another key.
func Open(s Sealer, b []byte) (Header, *Record, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return h, nil, err
	}
	plain, err := s.DecryptEntry(b[headerLen+saltLen:], b[headerLen:headerLen+saltLen], aad(b[:headerLen]))
	if err != nil {
		return h, nil, fmt.Errorf("open %s: %w", h.UIDString(), err)
	}
	defer secure.SecureZeroBytes(plain)
	r := new(Record)
	if err := json.Unmarshal(plain, r); err != nil {
		r.Wipe()
		return h, nil, fmt.Errorf("open %s: its record doesn't read: %w", h.UIDString(), err)
	}
	return h, r, nil
}

// Folder is a sync folder at a path.
type Folder struct{ dir string }

// New is the sync folder at dir.
func New(dir string) Folder { return Folder{dir: dir} }

// Dir is the folder's path.
func (f Folder) Dir() string { return f.dir }

func (f Folder) entries() string { return filepath.Join(f.dir, entriesDir) }

// Hash is a file's SHA-256, of its bytes as they are: sealed, so it says
// nothing of the record.
type Hash [sha256.Size]byte

// HashOf is b's Hash.
func HashOf(b []byte) Hash { return sha256.Sum256(b) }

// Write writes file b, sealed for the entry h names, as that entry's file:
// whole or not at all, readable only by this user, and returns its hash.
func (f Folder) Write(h Header, b []byte) (Hash, error) {
	if got, err := ParseHeader(b); err != nil || got != h {
		return Hash{}, fmt.Errorf("write %s: the file isn't sealed for it", h.UIDString())
	}
	if err := os.MkdirAll(f.entries(), 0o700); err != nil {
		return Hash{}, fmt.Errorf("write %s: %w", h.UIDString(), err)
	}
	if err := atomicfile.Write(filepath.Join(f.entries(), h.UIDString()+Ext), b, 0o600); err != nil {
		return Hash{}, fmt.Errorf("write %s: %w", h.UIDString(), err)
	}
	return HashOf(b), nil
}

// File is an entry file found in the folder.
type File struct {
	// Path is where it is; for a sync tool's copy, not the entry's own
	// file's name.
	Path string
	// Data is the file as it was read.
	Data []byte
	Header
	Hash Hash
}

// Problem is a file in the folder that can't be read, and why.
type Problem struct {
	Path string
	Why  string
}

// Contents is what a folder's entries/ holds.
type Contents struct {
	// Files are the entry files read, a sync tool's copies included: more
	// than one can be one entry's.
	Files []File
	// NotDownloaded are files iCloud Drive has yet to download: there,
	// but not read.
	NotDownloaded []string
	// Problems are entry files that can't be read.
	Problems []Problem
}

// Scan reads the folder's entry files: each file ending in Ext, a sync
// tool's copies too. Files whose names start with "." (temporary files,
// iCloud's placeholders) aren't read; a placeholder for an entry file is
// counted as not downloaded. A folder with no entries/ yet holds none.
func (f Folder) Scan() (*Contents, error) {
	des, err := os.ReadDir(f.entries())
	if errors.Is(err, os.ErrNotExist) {
		return &Contents{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the sync folder: %w", err)
	}
	c := &Contents{}
	for _, de := range des {
		name := de.Name()
		path := filepath.Join(f.entries(), name)
		if strings.HasPrefix(name, ".") {
			if strings.HasSuffix(name, Ext+".icloud") {
				c.NotDownloaded = append(c.NotDownloaded, path)
			}
			continue
		}
		if !strings.HasSuffix(name, Ext) {
			continue
		}
		file, why := readEntryFile(path)
		if why != "" {
			c.Problems = append(c.Problems, Problem{Path: path, Why: why})
			continue
		}
		c.Files = append(c.Files, file)
	}
	return c, nil
}

// readEntryFile reads the entry file at path, or says why it can't.
func readEntryFile(path string) (File, string) {
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return File{}, err.Error()
	case !fi.Mode().IsRegular():
		return File{}, "not a regular file"
	case fi.Size() > MaxFileSize:
		return File{}, fmt.Sprintf("%d bytes, over the %d a sync file may be", fi.Size(), MaxFileSize)
	}
	fh, err := os.Open(path) //nolint:gosec // a file in the sync folder
	if err != nil {
		return File{}, err.Error()
	}
	defer fh.Close() //nolint:errcheck // read only
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(fh, MaxFileSize+1)); err != nil {
		return File{}, err.Error()
	}
	if buf.Len() > MaxFileSize {
		return File{}, fmt.Sprintf("over the %d bytes a sync file may be", MaxFileSize)
	}
	b := buf.Bytes()
	h, err := ParseHeader(b)
	if err != nil {
		return File{}, err.Error()
	}
	return File{Path: path, Data: b, Header: h, Hash: HashOf(b)}, ""
}

// Remove removes path, an entry file Scan found: a sync tool's copy once
// what it holds is written to the entry's own file. Nothing outside the
// folder's entries/ is removed.
func (f Folder) Remove(path string) error {
	if filepath.Dir(filepath.Clean(path)) != filepath.Clean(f.entries()) || !strings.HasSuffix(path, Ext) {
		return fmt.Errorf("%s isn't an entry file of the sync folder %s", path, f.dir)
	}
	return os.Remove(path)
}
