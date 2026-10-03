package touchid

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileName is the Touch ID unlock file, kept next to the vault.
const FileName = "touchid.key"

// fileVersion is the format written today.
const fileVersion = 1

// File is what unlocks one vault with Touch ID on this Mac: the Secure
// Enclave key's blob and public key, and the vault key wrapped to it.
// Nothing in it opens the vault without this Mac's Secure Enclave and an
// enrolled finger.
type File struct {
	CreatedAt time.Time `json:"created_at"`
	// UnlockID is the vault's unlock id; the wrap is bound to it.
	UnlockID     string `json:"unlock_id"`
	KeyBlob      []byte `json:"key_blob"`
	PublicKey    []byte `json:"public_key"`
	EphemeralPub []byte `json:"ephemeral_pub"`
	Ciphertext   []byte `json:"ciphertext"`
	Version      int    `json:"version"`
}

// NewFile assembles the file for a vault from a new Secure Enclave key and
// the vault key wrapped to it.
func NewFile(unlockID string, keyBlob, publicKey []byte, w Wrapped) *File {
	return &File{
		Version:      fileVersion,
		UnlockID:     unlockID,
		KeyBlob:      keyBlob,
		PublicKey:    publicKey,
		EphemeralPub: w.EphemeralPub,
		Ciphertext:   w.Ciphertext,
		CreatedAt:    time.Now().UTC(),
	}
}

// Wrapped returns the file's wrapped vault key.
func (f *File) Wrapped() Wrapped {
	return Wrapped{EphemeralPub: f.EphemeralPub, Ciphertext: f.Ciphertext}
}

// ReadFile reads the Touch ID file in dir. A missing file is an error
// matching os.ErrNotExist.
func ReadFile(dir string) (*File, error) {
	path := filepath.Join(dir, FileName)
	body, err := os.ReadFile(path) //nolint:gosec // the vault's own directory
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("read %s: unsupported version %d", path, f.Version)
	}
	if f.UnlockID == "" || len(f.KeyBlob) == 0 || len(f.PublicKey) == 0 || len(f.EphemeralPub) == 0 || len(f.Ciphertext) == 0 {
		return nil, fmt.Errorf("read %s: incomplete", path)
	}
	return &f, nil
}

// Write stores f in dir, owner-only, replacing any earlier file atomically.
func (f *File) Write(dir string) error {
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".touchid.key.*")
	if err != nil {
		return fmt.Errorf("write %s: %w", FileName, err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(append(body, '\n'))
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(dir, FileName))
	}
	if werr != nil {
		if rerr := os.Remove(name); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return fmt.Errorf("write %s: %w (cleanup: %v)", FileName, werr, rerr)
		}
		return fmt.Errorf("write %s: %w", FileName, werr)
	}
	return nil
}

// Remove deletes the Touch ID file in dir. A missing file is fine.
func Remove(dir string) error {
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
