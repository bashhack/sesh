package database

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/bashhack/sesh/internal/secure"
)

// VerifyPlaintext is the known string sealed into the key record's verify
// blob. A successful open under the derived key proves the password.
const VerifyPlaintext = "sesh-verify"

// PasswordPromptFunc is called to obtain the master password from the user.
// Implementations should not echo the input.
type PasswordPromptFunc func(prompt string) ([]byte, error)

// MasterPasswordSource derives the encryption key from a user-supplied
// passphrase via Argon2id, with the salt and settings in the vault's key
// record (vault_key.go).
type MasterPasswordSource struct {
	// sf collapses concurrent slow-path Gets into a single Argon2id
	// derivation. Without it, N goroutines arriving with an empty cache
	// would each run a full Argon2id derivation, at the key record's
	// settings, in parallel.
	sf         singleflight.Group
	promptFunc PasswordPromptFunc
	// newPasswordCheck vets a new master password before it's confirmed;
	// nil accepts any of at least 8 characters. See WithNewPasswordCheck.
	newPasswordCheck func(pw []byte) error
	// dbPath is the vault whose key record this source reads, or creates.
	dbPath string
	// unlockID names the key record the key was checked against (see
	// UnlockID); "" until the first unlock. Guarded by mu.
	unlockID string
	// cachedKey holds the derived key after the first successful unlock.
	// Scoped to the process lifetime only — cleared when Close() is called
	// (or when the process exits). This avoids prompting the user on every
	// Get/Set operation within a single invocation.
	//
	// mu guards cachedKey + cacheEpoch so a concurrent Close() can't zero
	// the underlying memory while GetEncryptionKey is mid-clone. cacheEpoch
	// fences a slow Argon2id derivation that started before Close from
	// writing into the (now-cleared) cache after Close returns — the
	// derivation still returns its key to its caller, but the cache stays
	// clean past shutdown.
	cachedKey  []byte
	mu         sync.Mutex
	cacheEpoch uint64
	// maxAttempts is the number of password prompts allowed in the unlock
	// loop. Defaults to 1 (no retry); callers that know they're talking to
	// an interactive TTY set this higher via WithMaxAttempts.
	maxAttempts int
	// kdf is the Argon2id settings a new key record gets; an existing one
	// keeps its own.
	kdf Argon2idParams
}

// ErrTryAnotherPassword is what a new-password check returns to have a
// different master password asked for.
var ErrTryAnotherPassword = errors.New("choose a stronger master password")

// newPasswordTries is how many master passwords creation asks for when the
// check keeps turning them down.
const newPasswordTries = 3

// Option configures a MasterPasswordSource. Use with NewMasterPasswordSource.
type Option func(*MasterPasswordSource)

// WithMaxAttempts sets the maximum number of password prompts the unlock
// loop will issue before giving up. Values < 1 are clamped to 1. Only
// wrong-password failures are retried; key record and I/O errors fail
// immediately.
//
// The prompt callback must produce fresh user input on each invocation —
// a callback that returns a constant value (e.g., one backed by an env
// var) will derive the same wrong key N times and waste ~N × Argon2id
// cycles before failing. The CLI gates this via resolvePasswordPrompt in
// main.go, which only marks a prompt interactive when it actually reads
// fresh bytes; direct callers must apply the same discipline.
//
// Only affects unlock(); first-run create+confirm always runs once.
func WithMaxAttempts(n int) Option {
	return func(s *MasterPasswordSource) {
		if n < 1 {
			n = 1
		}
		s.maxAttempts = n
	}
}

// WithNewPasswordCheck vets each new master password (at first run, or when
// a rotation or recovery sets a new one) before it's confirmed. Returning
// ErrTryAnotherPassword asks for another, up to newPasswordTries times; any
// other error stops creation. Unlocking never runs it.
func WithNewPasswordCheck(check func(pw []byte) error) Option {
	return func(s *MasterPasswordSource) { s.newPasswordCheck = check }
}

// WithKDFParams sets the Argon2id settings a new key record gets (when the
// vault is created, or its master password changed); the default is
// kdf.Default(). Unlocking uses the settings the key record holds.
func WithKDFParams(p Argon2idParams) Option {
	return func(s *MasterPasswordSource) { s.kdf = p }
}

// newSourceParams is the settings a source's new key record gets unless
// WithKDFParams says otherwise. Tests make it cheap.
var newSourceParams = DefaultArgon2idParams

// NewMasterPasswordSource creates a MasterPasswordSource for the vault at
// dbPath, which must be absolute.
func NewMasterPasswordSource(dbPath string, prompt PasswordPromptFunc, opts ...Option) *MasterPasswordSource {
	s := &MasterPasswordSource{
		dbPath:      dbPath,
		promptFunc:  prompt,
		maxAttempts: 1,
		kdf:         newSourceParams(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Close zeroes and releases the cached key. Safe to call multiple times and
// safe to call concurrently with GetEncryptionKey. Bumping cacheEpoch fences
// any in-flight derivation from re-populating the cache after Close returns.
func (s *MasterPasswordSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheEpoch++
	if s.cachedKey != nil {
		secure.SecureZeroBytes(s.cachedKey)
		s.cachedKey = nil
	}
}

// GetEncryptionKey prompts for the master password and derives the
// encryption key. For a new vault it prompts twice for confirmation and
// creates the vault with its key record. Otherwise it checks the password
// against the key record's verify blob. The derived key is cached
// for the lifetime of this source so repeated Get/Set operations within one
// invocation do not re-prompt.
//
// Per the KeySource contract the caller is free to zero the returned slice
// — the cache holds a private copy. Call Close() to clear the cached key
// when done.
func (s *MasterPasswordSource) GetEncryptionKey() ([]byte, error) {
	// Fast path: cache hit. Lock only to read the slot and clone. Capture
	// the epoch so a Close that fires while we're in the slow path can
	// invalidate our cache write.
	s.mu.Lock()
	epoch := s.cacheEpoch
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
		// Only populate the cache if no Close ran while we were deriving.
		// If the epoch advanced, return the key to the caller but keep the
		// cache clean — preserves the "cache cleared after Close" guarantee.
		if s.cacheEpoch == epoch && s.cachedKey == nil {
			s.cachedKey = cloneKey(key)
		}
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

// acquireKey unlocks the vault, or creates it when there is none yet.
func (s *MasterPasswordSource) acquireKey() ([]byte, error) {
	if !filepath.IsAbs(s.dbPath) {
		return nil, fmt.Errorf("vault path must be absolute, got %q", s.dbPath)
	}
	m, err := ReadUnlockMaterial(s.dbPath)
	switch {
	case err == nil:
		return s.unlock(m)
	case !errors.Is(err, ErrNoVault):
		return nil, err
	}
	return s.create()
}

func cloneKey(k []byte) []byte {
	cp := make([]byte, len(k))
	copy(cp, k)
	return cp
}

// create asks for a new master password, derives the key from it and a
// new salt, and records the key record in a new vault. When another sesh
// recorded one first, the password typed here is tried against that one.
func (s *MasterPasswordSource) create() ([]byte, error) {
	pw, err := s.askNewPassword()
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(pw)
	key, rec, err := newKeyRecord(pw, s.kdf)
	if err != nil {
		return nil, err
	}
	salt, verify, params := rec.Salt, rec.Verify, rec.Params

	db, err := openDB(s.dbPath)
	if err != nil {
		secure.SecureZeroBytes(key)
		return nil, err
	}
	defer db.Close() //nolint:errcheck // only the key record was written, and that's committed
	recorded, err := writeKeyRecord(db, UnlockMaterial{Salt: salt, Verify: verify, Params: params})
	if err != nil || recorded {
		if err != nil {
			secure.SecureZeroBytes(key)
			return nil, err
		}
		s.checkedAgainst(verify)
		return key, nil
	}
	secure.SecureZeroBytes(key)

	// Another sesh created the vault while this one asked for a password.
	m, err := readKeyRecord(db, s.dbPath)
	if err != nil {
		return nil, err
	}
	key = DeriveKey(pw, m.Salt, m.Params)
	if _, err := Decrypt(key, m.Verify); err != nil {
		secure.SecureZeroBytes(key)
		return nil, errors.New("another sesh command created this vault at the same time, with a different master password; run this again and enter that one")
	}
	s.checkedAgainst(m.Verify)
	return key, nil
}

// NewKey asks for a new master password, and returns the key it gives
// with a new salt and the key record for it, for a password change. Nothing
// is written. The caller zeroes the key.
func (s *MasterPasswordSource) NewKey() ([]byte, UnlockMaterial, error) {
	pw, err := s.askNewPassword()
	if err != nil {
		return nil, UnlockMaterial{}, err
	}
	defer secure.SecureZeroBytes(pw)
	return newKeyRecord(pw, s.kdf)
}

// askNewPassword asks for a new master password and its confirmation. The
// caller zeroes it.
func (s *MasterPasswordSource) askNewPassword() ([]byte, error) {
	pw, err := s.newPassword()
	if err != nil {
		return nil, err
	}
	confirm, err := s.promptFunc("Confirm master password: ")
	if err != nil {
		secure.SecureZeroBytes(pw)
		return nil, fmt.Errorf("read confirmation: %w", err)
	}
	defer secure.SecureZeroBytes(confirm)
	if !bytes.Equal(pw, confirm) {
		secure.SecureZeroBytes(pw)
		return nil, fmt.Errorf("passwords do not match")
	}
	return pw, nil
}

// newKeyRecord derives a key from pw and a new salt with params, and the
// key record that opens with it. The caller zeroes the key.
func newKeyRecord(pw []byte, params Argon2idParams) ([]byte, UnlockMaterial, error) {
	if err := params.CheckBounds(); err != nil {
		return nil, UnlockMaterial{}, err
	}
	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, UnlockMaterial{}, err
	}
	key := DeriveKey(pw, salt, params)
	verify, err := Encrypt(key, []byte(VerifyPlaintext))
	if err != nil {
		secure.SecureZeroBytes(key)
		return nil, UnlockMaterial{}, fmt.Errorf("create verify blob: %w", err)
	}
	return key, UnlockMaterial{Salt: salt, Verify: verify, Params: params}, nil
}

// UnlockID is the id of the key record this source's key was checked
// against, unlocking first if it hasn't yet.
func (s *MasterPasswordSource) UnlockID() (string, error) {
	key, err := s.GetEncryptionKey()
	if err != nil {
		return "", err
	}
	secure.SecureZeroBytes(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlockID, nil
}

// checkedAgainst records that the key was checked against verify.
func (s *MasterPasswordSource) checkedAgainst(verify []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlockID = UnlockID(verify)
}

// unlock asks for the master password and checks it against the key
// record m, returning the key.
func (s *MasterPasswordSource) unlock(m UnlockMaterial) ([]byte, error) {
	attempts := max(s.maxAttempts, 1)

	for i := range attempts {
		// First attempt uses the bare prompt; later attempts prepend a
		// retry message so the prompt itself carries the "try again"
		// signal without coupling this package to a stderr writer.
		prompt := "Master password: "
		if i > 0 {
			prompt = fmt.Sprintf("Wrong password, try again (%d/%d). Master password: ", i+1, attempts)
		}

		pw, err := s.promptFunc(prompt)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}

		key := DeriveKey(pw, m.Salt, m.Params)
		secure.SecureZeroBytes(pw)

		// AES-GCM authentication is what guarantees "this plaintext was
		// produced by encryption under this key" — a successful Decrypt is
		// already proof of the right master password.
		if _, err := Decrypt(key, m.Verify); err == nil {
			s.checkedAgainst(m.Verify)
			return key, nil
		}
		secure.SecureZeroBytes(key)
	}

	if attempts == 1 {
		return nil, ErrWrongPassword
	}
	return nil, fmt.Errorf("%w (after %d attempts)", ErrWrongPassword, attempts)
}

// ErrWrongPassword means every master password attempt failed.
var ErrWrongPassword = errors.New("wrong master password")

const (
	// minSaltLen is the shortest KDF salt an unlock accepts.
	minSaltLen = 16
	// minVerifyLen is the AES-GCM minimum for the verify blob: 12-byte
	// nonce plus 16-byte tag (the plaintext is extra).
	minVerifyLen = 28
)

// ValidateUnlockMaterial checks the fields an unlock derives from. The
// master-password source and the agent both call it, so they accept
// exactly the same material.
func ValidateUnlockMaterial(salt, verify []byte, params Argon2idParams) error {
	if len(salt) < minSaltLen {
		return fmt.Errorf("salt too short: %d bytes (min %d)", len(salt), minSaltLen)
	}
	if len(verify) < minVerifyLen {
		return fmt.Errorf("verify blob too short: %d bytes (min %d)", len(verify), minVerifyLen)
	}
	return validateArgon2idBounds(params)
}

// validateArgon2idBounds bounds-checks Argon2id parameters read from a
// key record or an unlock request. A corrupted or hostile value could
// otherwise trigger a memory DoS.
func validateArgon2idBounds(p Argon2idParams) error { return p.CheckBounds() }

// newPassword asks for a new master password until one passes the length
// rule and the new-password check, which may ask for another a few times.
// The caller zeroes the result.
func (s *MasterPasswordSource) newPassword() ([]byte, error) {
	for try := 1; ; try++ {
		pw, err := s.promptFunc("Create master password: ")
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		if len(pw) < 8 {
			secure.SecureZeroBytes(pw)
			return nil, fmt.Errorf("master password must be at least 8 characters")
		}
		if s.newPasswordCheck == nil {
			return pw, nil
		}
		err = s.newPasswordCheck(pw)
		if err == nil {
			return pw, nil
		}
		secure.SecureZeroBytes(pw)
		if !errors.Is(err, ErrTryAnotherPassword) || try == newPasswordTries {
			return nil, err
		}
	}
}
