package syncfolder

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bashhack/sesh/internal/atomicfile"
	"github.com/bashhack/sesh/internal/kdf"
)

// InfoFile is the sync folder's own file, beside entries/.
const InfoFile = "sesh-sync.json"

// infoFormat is the format of InfoFile this sesh writes and reads.
const infoFormat = 1

// maxInfoSize is the most InfoFile may be: a few hundred bytes are enough.
const maxInfoSize = 64 << 10

// ErrNoInfo is a folder that isn't a sync folder: it has no InfoFile.
var ErrNoInfo = errors.New("not a sesh sync folder (it has no " + InfoFile + ")")

// Info is what a sync folder says of itself: its ID, and the key record of
// the vaults that sync through it (what turns the master password into
// their key, as each vault's vault_key row has it). None of it is secret:
// without the master password it opens nothing.
type Info struct {
	FolderID string    `json:"folder_id"`
	Key      KeyRecord `json:"key"`
	Format   int       `json:"format"`
}

// KeyRecord is a vault's key record: the salt and Argon2id settings its
// master password is derived with, and the verify blob that tells the
// right password from a wrong one.
type KeyRecord struct {
	Salt   []byte     `json:"salt"`
	Verify []byte     `json:"verify"`
	Params kdf.Params `json:"params"`
}

// NewInfo is the Info for a new sync folder of the vaults with key record
// key.
func NewInfo(key KeyRecord) (*Info, error) {
	id := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return nil, err
	}
	return &Info{Format: infoFormat, FolderID: hex.EncodeToString(id), Key: key}, nil
}

func (f Folder) infoPath() string { return filepath.Join(f.dir, InfoFile) }

// ReadInfo reads the folder's InfoFile: ErrNoInfo when there's none.
func (f Folder) ReadInfo() (*Info, error) {
	fh, size, err := openFile(f.infoPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNoInfo
	case errors.Is(err, errNotDownloaded):
		return nil, fmt.Errorf("%s isn't downloaded yet: open the folder so the sync tool downloads it, then try again", f.infoPath())
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", f.infoPath(), err)
	}
	defer fh.Close() //nolint:errcheck // read only
	if size > maxInfoSize {
		return nil, fmt.Errorf("read %s: %d bytes, not a sync folder's", f.infoPath(), size)
	}
	b, err := readAll(fh, size)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.infoPath(), err)
	}
	var probe struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("read %s: it doesn't read: %w", f.infoPath(), err)
	}
	if probe.Format > infoFormat {
		return nil, fmt.Errorf("read %s: %w", f.infoPath(), ErrNewerFormat)
	}
	var info Info
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("read %s: it doesn't read: %w", f.infoPath(), err)
	}
	switch {
	case info.Format != infoFormat:
		return nil, fmt.Errorf("read %s: format %d isn't one sesh writes", f.infoPath(), info.Format)
	case info.FolderID == "", len(info.Key.Salt) == 0, len(info.Key.Verify) == 0:
		return nil, fmt.Errorf("read %s: it's missing what a sync folder has", f.infoPath())
	}
	// Settings read from a file anyone with the folder can change are held
	// to the bounds an unlock holds a vault's to, so they can't make a
	// computer derive with absurd ones.
	if err := info.Key.Params.CheckBounds(); err != nil {
		return nil, fmt.Errorf("read %s: %w", f.infoPath(), err)
	}
	return &info, nil
}

// WriteInfo writes info as the folder's InfoFile, whole or not at all,
// readable only by this user, making the folder if it isn't there.
func (f Folder) WriteInfo(info *Info) error {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("make %s: %w", f.dir, err)
	}
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(f.infoPath(), append(b, '\n'), 0o600)
}
