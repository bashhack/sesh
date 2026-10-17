// Package syncfolder reads and writes a sync folder: the folder, carried
// between computers by any tool (iCloud Drive, Dropbox, Syncthing, a USB
// stick), through which computers keeping their own vaults share entries.
// It holds one file per entry, in entries/, named by the entry's uid, and
// encrypted whole with the vault's key: a file says nothing of the entry
// without it, not even its name.
//
// A file is a header, then the record as JSON in pieces of at most
// MaxPiece bytes, each sealed on its own, so no request to sesh's agent is
// larger than one piece:
//
//	"SESHSYNC"  8 bytes
//	format      1 byte (1)
//	uid         16 bytes, the entry's
//	key ID      32 bytes, the vault key record's (database.UnlockID) it was sealed with
//	then, for each piece:
//	salt        16 bytes
//	length      4 bytes, big-endian: the sealed piece's
//	sealed      the piece, sealed with the vault's key
//
// Each piece's associated data is the header, the piece's place, and
// whether it's the last, so a file's uid and key ID can't be changed, nor
// its pieces moved to another entry's file, reordered, repeated, dropped
// or added to, without it failing to open.
package syncfolder

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	// MaxPiece is the most of a record sealed in one piece: well within
	// what one request to the agent carries, encoded as it sends it.
	MaxPiece = 1 << 20
	// MaxFileSize is the most an entry file may be. An entry with large
	// files and a long history can be over it; it can't be synced until
	// its history is shorter.
	MaxFileSize = 64 << 20
	// pieceOverhead is what sealing adds to each piece: its salt and
	// length, and the sealing's nonce and tag.
	pieceOverhead = saltLen + 4 + 12 + 16
)

// ErrNewerFormat is a file written by a newer sesh, in a format this one
// doesn't read, or with more in its record than this one knows.
var ErrNewerFormat = errors.New("written by a newer sesh: update sesh to read it")

// Header is what a file says unencrypted: whose it is and the key it was
// sealed with.
type Header struct {
	UID   [16]byte
	KeyID [32]byte
}

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

// UIDString is the header's uid as entries.uid has it: 32 hex characters.
func (h *Header) UIDString() string { return hex.EncodeToString(h.UID[:]) }

// KeyIDString is the header's key ID as database.UnlockID gives it.
func (h *Header) KeyIDString() string { return hex.EncodeToString(h.KeyID[:]) }

func (h *Header) bytes() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, magic...)
	b = append(b, format)
	b = append(b, h.UID[:]...)
	return append(b, h.KeyID[:]...)
}

// pieceAAD is the associated data of piece i of a file with header bytes
// hb, last saying whether it's the file's last.
func pieceAAD(hb []byte, i uint32, last bool) []byte {
	b := append([]byte(aadTag), hb...)
	b = binary.BigEndian.AppendUint32(b, i)
	if last {
		return append(b, 1)
	}
	return append(b, 0)
}

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
	case len(b) < headerLen+saltLen+4:
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
	// Changed is when this version was made, by its computer's clock:
	// where two versions changed the same thing, the later's is kept.
	Changed time.Time `json:"changed,omitzero"`
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
	// Computer is the name of the computer whose change replaced it.
	Computer string `json:"computer,omitempty"`
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

// Seal is the file for record r of the entry h names, sealed by s. The
// JSON it's sealed from is zeroed after; encoding/json's own buffer, which
// it's copied from, isn't, as with every JSON sesh sends its agent.
func Seal(s Sealer, h Header, r *Record) ([]byte, error) {
	plain, err := json.Marshal(r) //nolint:gosec // the record is sealed next, never written as it is
	if err != nil {
		return nil, fmt.Errorf("seal %s: %w", h.UIDString(), err)
	}
	defer secure.SecureZeroBytes(plain)
	tooLarge := func(n int) error {
		return fmt.Errorf("seal %s: about %d bytes, over the %d a sync file may be", h.UIDString(), n, MaxFileSize)
	}
	// Checked first, so the sizes worked out from it are small.
	if len(plain) > MaxFileSize {
		return nil, tooLarge(len(plain))
	}
	pieces := max((len(plain)+MaxPiece-1)/MaxPiece, 1)
	size := headerLen + len(plain) + pieces*pieceOverhead
	if size > MaxFileSize {
		return nil, tooLarge(size)
	}
	hb := h.bytes()
	out := append(make([]byte, 0, size), hb...)
	for i := range pieces {
		piece := plain[i*MaxPiece : min((i+1)*MaxPiece, len(plain))]
		sealed, salt, err := s.EncryptEntry(piece, pieceAAD(hb, uint32(i), i == pieces-1)) //nolint:gosec // i < MaxFileSize/MaxPiece
		if err != nil {
			return nil, fmt.Errorf("seal %s: %w", h.UIDString(), err)
		}
		if len(salt) != saltLen {
			return nil, fmt.Errorf("seal %s: a salt of %d bytes, not %d", h.UIDString(), len(salt), saltLen)
		}
		out = append(out, salt...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(sealed))) //nolint:gosec // within MaxPiece and its overhead
		out = append(out, sealed...)
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
	// The record is no longer than its sealed pieces, so this holds it
	// without growing (and leaving copies behind).
	plain := make([]byte, 0, len(b)-headerLen)
	defer func() { secure.SecureZeroBytes(plain) }()
	rest := b[headerLen:]
	for i := uint32(0); len(rest) > 0 || i == 0; i++ {
		if len(rest) < saltLen+4 {
			return h, nil, fmt.Errorf("open %s: cut short", h.UIDString())
		}
		salt, n := rest[:saltLen], binary.BigEndian.Uint32(rest[saltLen:])
		rest = rest[saltLen+4:]
		if uint64(n) > uint64(len(rest)) {
			return h, nil, fmt.Errorf("open %s: cut short", h.UIDString())
		}
		sealed := rest[:n]
		rest = rest[n:]
		// The piece the file ends with must have been sealed as the last,
		// and every one before it as not.
		piece, err := s.DecryptEntry(sealed, salt, pieceAAD(b[:headerLen], i, len(rest) == 0))
		if err != nil {
			return h, nil, fmt.Errorf("open %s: %w", h.UIDString(), err)
		}
		plain = append(plain, piece...)
		secure.SecureZeroBytes(piece)
	}
	r := new(Record)
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		r.Wipe()
		if strings.Contains(err.Error(), "unknown field") {
			return h, nil, fmt.Errorf("open %s: %w", h.UIDString(), ErrNewerFormat)
		}
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

// entries is the folder's entries/: a real folder, only this user's, made
// if create is set; "" with no error when it isn't there and isn't made. A
// link there is refused, so nothing is read, written or removed outside
// the sync folder through it.
func (f Folder) entries(create bool) (string, error) {
	dir := filepath.Join(f.dir, entriesDir)
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist) && create:
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		return dir, nil
	case errors.Is(err, os.ErrNotExist):
		return "", nil
	case err != nil:
		return "", err
	case !fi.IsDir():
		return "", fmt.Errorf("%s isn't a folder (a link, or a file): sesh reads and writes only a real one", dir)
	case fi.Mode().Perm()&0o077 != 0:
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a folder: 0700 is only this user
			return "", fmt.Errorf("make %s readable only by you: %w", dir, err)
		}
	}
	return dir, nil
}

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
	dir, err := f.entries(true)
	if err != nil {
		return Hash{}, fmt.Errorf("write %s: %w", h.UIDString(), err)
	}
	if err := atomicfile.Write(filepath.Join(dir, h.UIDString()+Ext), b, 0o600); err != nil {
		return Hash{}, fmt.Errorf("write %s: %w", h.UIDString(), err)
	}
	return HashOf(b), nil
}

// File is an entry file found in the folder.
type File struct {
	// Path is where it is; for a sync tool's copy, not the entry's own
	// file's name.
	Path string
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
	// Files are the entry files found, a sync tool's copies included:
	// more than one can be one entry's.
	Files []File
	// NotDownloaded are entry files a sync tool has yet to download (on
	// macOS, iCloud Drive's or another's kept in the cloud): there, but
	// not read, since reading would wait on the network.
	NotDownloaded []string
	// Problems are entry files that can't be read.
	Problems []Problem
}

// isDataless says whether fi is a file whose data a sync tool keeps in the
// cloud until it's read (on macOS, SF_DATALESS); reading it would wait for
// the download.
var isDataless = func(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && dataless(st)
}

// Scan finds the folder's entry files: each file ending in Ext, a sync
// tool's copies too, with its header and hash; Read reads one. Files whose
// names start with "." (temporary files, older iCloud placeholders) aren't
// read; a placeholder for an entry file is counted as not downloaded, as
// is an entry file whose data is still in the cloud. A folder with no
// entries/ yet holds none.
func (f Folder) Scan() (*Contents, error) {
	dir, err := f.entries(false)
	if err != nil {
		return nil, fmt.Errorf("read the sync folder: %w", err)
	}
	c := &Contents{}
	if dir == "" {
		return c, nil
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read the sync folder: %w", err)
	}
	for _, de := range des {
		name := de.Name()
		path := filepath.Join(dir, name)
		if strings.HasPrefix(name, ".") {
			if strings.HasSuffix(name, Ext+".icloud") {
				c.NotDownloaded = append(c.NotDownloaded, path)
			}
			continue
		}
		if !strings.HasSuffix(name, Ext) {
			continue
		}
		file, err := scanFile(path)
		switch {
		case errors.Is(err, errNotDownloaded):
			c.NotDownloaded = append(c.NotDownloaded, path)
		case err != nil:
			c.Problems = append(c.Problems, Problem{Path: path, Why: err.Error()})
		default:
			c.Files = append(c.Files, file)
		}
	}
	return c, nil
}

var errNotDownloaded = errors.New("not downloaded")

// openFile opens the entry file at path to read it whole: a regular file,
// not through a link, not a pipe that would wait for a writer, not over
// MaxFileSize, and downloaded. The checks are of the file opened, so it
// can't be swapped for another between them.
func openFile(path string) (*os.File, int64, error) {
	if fi, err := os.Lstat(path); err == nil && isDataless(fi) {
		return nil, 0, errNotDownloaded
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // a file in the sync folder
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, 0, errors.New("a link")
		}
		return nil, 0, err
	}
	fi, err := fh.Stat()
	switch {
	case err != nil:
	case !fi.Mode().IsRegular():
		err = errors.New("not a regular file")
	case isDataless(fi):
		err = errNotDownloaded
	case fi.Size() > MaxFileSize:
		err = fmt.Errorf("%d bytes, over the %d a sync file may be", fi.Size(), MaxFileSize)
	}
	if err != nil {
		_ = fh.Close() //nolint:errcheck // not read
		return nil, 0, err
	}
	return fh, fi.Size(), nil
}

// readAll reads fh, size bytes, whole: a file that's grown or shrunk since
// it was opened is refused as changed.
func readAll(fh *os.File, size int64) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(fh, b); err != nil {
		return nil, errors.New("changed while it was read")
	}
	if n, _ := fh.Read(make([]byte, 1)); n != 0 { //nolint:errcheck // only whether there's more
		return nil, errors.New("changed while it was read")
	}
	return b, nil
}

// scanFile reads the entry file at path for its header and hash.
func scanFile(path string) (File, error) {
	fh, size, err := openFile(path)
	if err != nil {
		return File{}, err
	}
	defer fh.Close() //nolint:errcheck // read only
	b, err := readAll(fh, size)
	if err != nil {
		return File{}, err
	}
	h, err := ParseHeader(b)
	if err != nil {
		return File{}, err
	}
	return File{Path: path, Header: h, Hash: HashOf(b)}, nil
}

// Read reads file, one Scan found, as it was then: one changed since is
// refused, to be scanned again.
func (f Folder) Read(file *File) ([]byte, error) {
	fh, size, err := openFile(file.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file.Path, err)
	}
	defer fh.Close() //nolint:errcheck // read only
	b, err := readAll(fh, size)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file.Path, err)
	}
	if HashOf(b) != file.Hash {
		return nil, fmt.Errorf("read %s: changed since the folder was read", file.Path)
	}
	return b, nil
}

// Remove removes path, an entry file Scan found: a sync tool's copy once
// what it holds is written to the entry's own file. Nothing outside the
// folder's entries/ is removed.
func (f Folder) Remove(path string) error {
	dir, err := f.entries(false)
	if err != nil {
		return err
	}
	if dir == "" || filepath.Dir(filepath.Clean(path)) != dir || !strings.HasSuffix(path, Ext) {
		return fmt.Errorf("%s isn't an entry file of the sync folder %s", path, f.dir)
	}
	return os.Remove(path)
}
