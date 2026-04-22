package database

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bashhack/sesh/internal/secure"
)

const (
	sidecarFileName = "passwords.key"
	sidecarVersion  = 1
	verifyPlaintext = "sesh-verify"
)

// sidecarData is the on-disk format for the master password's KDF salt,
// params, and verification blob. Nothing secret — the salt and params are
// public (same model as bcrypt), and the verify blob is a known constant
// encrypted with the derived key so we can check the password before
// touching any real data.
type sidecarData struct {
	Salt      string         `json:"salt"`      // base64
	Algorithm string         `json:"algorithm"` // "argon2id"
	Verify    string         `json:"verify"`    // base64, AES-256-GCM(derived_key, "sesh-verify")
	Params    Argon2idParams `json:"params"`
	Version   int            `json:"version"`
}

// PasswordPromptFunc is called to obtain the master password from the user.
// Implementations should not echo the input.
type PasswordPromptFunc func(prompt string) ([]byte, error)

// MasterPasswordSource derives the encryption key from a user-supplied
// passphrase via Argon2id. The KDF salt and a verification blob are stored
// in a sidecar file alongside the DB — no keychain involvement.
type MasterPasswordSource struct {
	promptFunc PasswordPromptFunc
	dataDir    string
}

// NewMasterPasswordSource creates a MasterPasswordSource that stores its
// sidecar in dataDir (typically the same directory as the SQLite DB).
func NewMasterPasswordSource(dataDir string, prompt PasswordPromptFunc) *MasterPasswordSource {
	return &MasterPasswordSource{
		dataDir:    dataDir,
		promptFunc: prompt,
	}
}

func (s *MasterPasswordSource) sidecarPath() string {
	return filepath.Join(s.dataDir, sidecarFileName)
}

// GetEncryptionKey prompts for the master password and derives the
// encryption key. On first run (no sidecar), it prompts twice for
// confirmation and creates the sidecar. On subsequent runs, it verifies the
// password against the stored verification blob.
func (s *MasterPasswordSource) GetEncryptionKey() ([]byte, error) {
	path := s.sidecarPath()
	_, err := os.Stat(path)

	if os.IsNotExist(err) {
		return s.initialize()
	}
	if err != nil {
		return nil, fmt.Errorf("check sidecar file: %w", err)
	}

	return s.unlock()
}

// StoreEncryptionKey is a no-op for the master password source — the key is
// derived from the password, not stored directly.
func (s *MasterPasswordSource) StoreEncryptionKey(_ []byte) error {
	return nil
}

func (s *MasterPasswordSource) RequiresUserInput() bool { return true }
func (s *MasterPasswordSource) Name() string            { return "master-password" }

// initialize handles the first-run case: prompt for password twice, generate
// salt, derive key, write sidecar.
func (s *MasterPasswordSource) initialize() ([]byte, error) {
	pw, err := s.promptFunc("Create master password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	defer secure.SecureZeroBytes(pw)

	if len(pw) < 8 {
		return nil, fmt.Errorf("master password must be at least 8 characters")
	}

	confirm, err := s.promptFunc("Confirm master password: ")
	if err != nil {
		return nil, fmt.Errorf("read confirmation: %w", err)
	}
	defer secure.SecureZeroBytes(confirm)

	if !bytes.Equal(pw, confirm) {
		return nil, fmt.Errorf("passwords do not match")
	}

	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, err
	}

	params := DefaultArgon2idParams()
	key := DeriveKey(pw, salt, params)

	verifyBlob, err := Encrypt(key, []byte(verifyPlaintext))
	if err != nil {
		secure.SecureZeroBytes(key)
		return nil, fmt.Errorf("create verify blob: %w", err)
	}

	data := sidecarData{
		Version:   sidecarVersion,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Algorithm: "argon2id",
		Params:    params,
		Verify:    base64.StdEncoding.EncodeToString(verifyBlob),
	}

	if err := s.writeSidecar(data); err != nil {
		secure.SecureZeroBytes(key)
		return nil, err
	}

	return key, nil
}

// unlock handles the normal case: read sidecar, prompt for password, verify, return key.
func (s *MasterPasswordSource) unlock() ([]byte, error) {
	data, err := s.readSidecar()
	if err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(data.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	verifyBlob, err := base64.StdEncoding.DecodeString(data.Verify)
	if err != nil {
		return nil, fmt.Errorf("decode verify blob: %w", err)
	}

	pw, err := s.promptFunc("Master password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	defer secure.SecureZeroBytes(pw)

	key := DeriveKey(pw, salt, data.Params)

	plaintext, err := Decrypt(key, verifyBlob)
	if err != nil {
		secure.SecureZeroBytes(key)
		return nil, fmt.Errorf("wrong master password")
	}

	if string(plaintext) != verifyPlaintext {
		secure.SecureZeroBytes(key)
		return nil, fmt.Errorf("wrong master password (verify mismatch)")
	}

	return key, nil
}

func (s *MasterPasswordSource) writeSidecar(data sidecarData) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sidecar: %w", err)
	}

	// Write to a temp file then rename so a crash mid-write leaves the
	// old sidecar intact (or no sidecar at all on first run). Rename is
	// atomic on POSIX and close-to-atomic on Windows.
	path := s.sidecarPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write sidecar: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		if rmErr := os.Remove(tmp); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("replace sidecar: %w (cleanup of %s also failed: %v)", err, tmp, rmErr)
		}
		return fmt.Errorf("replace sidecar: %w", err)
	}
	return nil
}

func (s *MasterPasswordSource) readSidecar() (sidecarData, error) {
	path := s.sidecarPath()
	b, err := os.ReadFile(path) //nolint:gosec // path is <dataDir>/passwords.key; dataDir is caller-controlled via NewMasterPasswordSource
	if err != nil {
		return sidecarData{}, fmt.Errorf("read sidecar: %w", err)
	}

	var data sidecarData
	if err := json.Unmarshal(b, &data); err != nil {
		return sidecarData{}, fmt.Errorf("parse sidecar: %w", err)
	}

	if data.Version != sidecarVersion {
		return sidecarData{}, fmt.Errorf("unsupported sidecar version %d (expected %d)", data.Version, sidecarVersion)
	}
	if data.Algorithm != "argon2id" {
		return sidecarData{}, fmt.Errorf("unsupported sidecar algorithm %q", data.Algorithm)
	}
	if err := validateArgon2idBounds(data.Params); err != nil {
		return sidecarData{}, err
	}

	return data, nil
}

// validateArgon2idBounds bounds-checks Argon2id parameters read from disk.
// A corrupted or malicious sidecar could otherwise trigger a memory DoS.
func validateArgon2idBounds(p Argon2idParams) error {
	const (
		maxMemoryKiB = 1 << 20 // 1 GiB
		maxTime      = 10
		maxThreads   = 16
	)
	if p.Memory == 0 || p.Memory > maxMemoryKiB {
		return fmt.Errorf("sidecar memory param out of range: %d KiB (max %d)", p.Memory, maxMemoryKiB)
	}
	if p.Time == 0 || p.Time > maxTime {
		return fmt.Errorf("sidecar time param out of range: %d (max %d)", p.Time, maxTime)
	}
	if p.Threads == 0 || p.Threads > maxThreads {
		return fmt.Errorf("sidecar threads param out of range: %d (max %d)", p.Threads, maxThreads)
	}
	if p.KeyLen != 32 {
		return fmt.Errorf("sidecar key_len must be 32, got %d", p.KeyLen)
	}
	return nil
}
