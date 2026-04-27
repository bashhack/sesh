package database

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sync/singleflight"

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
	// sf collapses concurrent slow-path Gets into a single Argon2id
	// derivation. Without it, N goroutines arriving with an empty cache
	// would each fire ~64 MiB of Argon2id work in parallel.
	sf         singleflight.Group
	promptFunc PasswordPromptFunc
	dataDir    string
	// cachedKey holds the derived key after the first successful unlock.
	// Scoped to the process lifetime only — cleared when Close() is called
	// (or when the process exits). This avoids prompting the user on every
	// Get/Set operation within a single invocation.
	//
	// mu guards cachedKey so a concurrent Close() can't zero the underlying
	// memory while GetEncryptionKey is mid-clone.
	cachedKey []byte
	mu        sync.Mutex
}

// NewMasterPasswordSource creates a MasterPasswordSource that stores its
// sidecar in dataDir (typically the same directory as the SQLite DB).
func NewMasterPasswordSource(dataDir string, prompt PasswordPromptFunc) *MasterPasswordSource {
	return &MasterPasswordSource{
		dataDir:    dataDir,
		promptFunc: prompt,
	}
}

// Close zeroes and releases the cached key. Safe to call multiple times and
// safe to call concurrently with GetEncryptionKey.
func (s *MasterPasswordSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedKey != nil {
		secure.SecureZeroBytes(s.cachedKey)
		s.cachedKey = nil
	}
}

func (s *MasterPasswordSource) sidecarPath() string {
	return filepath.Join(s.dataDir, sidecarFileName)
}

// GetEncryptionKey prompts for the master password and derives the
// encryption key. On first run (no sidecar), it prompts twice for
// confirmation and creates the sidecar. On subsequent runs, it verifies the
// password against the stored verification blob. The derived key is cached
// for the lifetime of this source so repeated Get/Set operations within one
// invocation do not re-prompt.
//
// Per the KeySource contract the caller is free to zero the returned slice
// — the cache holds a private copy. Call Close() to clear the cached key
// when done.
func (s *MasterPasswordSource) GetEncryptionKey() ([]byte, error) {
	// Fast path: cache hit. Lock only to read the slot and clone.
	s.mu.Lock()
	if s.cachedKey != nil {
		clone := cloneKey(s.cachedKey)
		s.mu.Unlock()
		return clone, nil
	}
	s.mu.Unlock()

	// Slow path: collapse concurrent callers into a single acquireKey via
	// singleflight. Without this, N goroutines hitting an empty cache would
	// each run a full Argon2id derivation in parallel, multiplying CPU and
	// memory pressure (and exploding race-detector runtime).
	v, err, _ := s.sf.Do("acquire", func() (any, error) {
		// A waiter from this same in-flight group may already have
		// re-populated the cache; re-check before re-deriving.
		s.mu.Lock()
		if s.cachedKey != nil {
			clone := cloneKey(s.cachedKey)
			s.mu.Unlock()
			return clone, nil
		}
		s.mu.Unlock()

		key, err := s.acquireKey()
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.cachedKey = cloneKey(key)
		s.mu.Unlock()
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	// The shared value is read by every waiter; clone so each caller can
	// safely zero its own copy without affecting siblings or the cache.
	return cloneKey(v.([]byte)), nil
}

// acquireKey decides whether to initialize a new sidecar or unlock an
// existing one. First-run is serialized via flock so two concurrent sesh
// invocations can't each generate a different salt and orphan one
// process's derived key. Once the sidecar exists, unlock is salt-stable
// and lock-free.
func (s *MasterPasswordSource) acquireKey() ([]byte, error) {
	path := s.sidecarPath()
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return s.unlock()
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("check sidecar file: %w", err)
	}
	return s.initializeLocked()
}

// initializeLocked serializes concurrent first-run invocations with an
// advisory flock on <dataDir>/passwords.key.lock. The flock is auto-
// released when the holding process exits, so crashes don't leave stale
// locks. After acquiring the lock, the sidecar is re-checked — another
// process may have created it while this one was blocked.
func (s *MasterPasswordSource) initializeLocked() ([]byte, error) {
	if !filepath.IsAbs(s.dataDir) {
		return nil, fmt.Errorf("data dir must be an absolute path, got %q", s.dataDir)
	}
	sentinel := s.sidecarPath() + ".lock"
	lockFile, err := os.OpenFile(sentinel, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // sentinel is <abs-dataDir>/passwords.key.lock; abs check above
	if err != nil {
		return nil, fmt.Errorf("open sidecar lock: %w", err)
	}
	defer func() {
		if cerr := lockFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: release sidecar lock: %v\n", cerr)
		}
	}()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("acquire sidecar lock: %w", err)
	}

	switch _, err := os.Stat(s.sidecarPath()); {
	case err == nil:
		return s.unlock()
	case os.IsNotExist(err):
		return s.initialize()
	default:
		// A non-IsNotExist error here (permission denied, I/O) shouldn't
		// trigger a fresh init that could overwrite an existing-but-
		// unreadable sidecar.
		return nil, fmt.Errorf("re-check sidecar file: %w", err)
	}
}

func cloneKey(k []byte) []byte {
	cp := make([]byte, len(k))
	copy(cp, k)
	return cp
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
	if len(salt) < 16 {
		return nil, fmt.Errorf("sidecar salt too short: %d bytes (min 16)", len(salt))
	}

	verifyBlob, err := base64.StdEncoding.DecodeString(data.Verify)
	if err != nil {
		return nil, fmt.Errorf("decode verify blob: %w", err)
	}
	// AES-GCM minimum: 12-byte nonce + 16-byte tag = 28 bytes (plaintext is
	// extra). Short-circuit before prompting and burning ~200ms on Argon2id
	// for a sidecar that can't possibly verify.
	if len(verifyBlob) < 28 {
		return nil, fmt.Errorf("sidecar verify blob too short: %d bytes", len(verifyBlob))
	}

	pw, err := s.promptFunc("Master password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	defer secure.SecureZeroBytes(pw)

	key := DeriveKey(pw, salt, data.Params)

	// AES-GCM authentication is what guarantees "this plaintext was
	// produced by encryption under this key" — a successful Decrypt is
	// already proof of the right master password.
	if _, err := Decrypt(key, verifyBlob); err != nil {
		secure.SecureZeroBytes(key)
		return nil, fmt.Errorf("wrong master password")
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
