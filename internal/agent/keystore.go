package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
)

// deriveKey is the KDF Unlock runs. Tests replace it to observe how many
// derivations are in flight.
var deriveKey = database.DeriveKey

var (
	errWrongPassword  = errors.New("wrong master password")
	errNotUnlocked    = errors.New("agent is locked")
	errDecryptFailed  = errors.New("decrypt failed")
	errUnlockMismatch = errors.New("unlock mismatch")
	errBadRequest     = errors.New("bad request")
	errShutDown       = errors.New("agent is shutting down")
)

// keystore is the only place the derived master key lives in the agent
// process. Methods copy the key out of the lock before doing KDF or
// AES work, then zero the copy.
type keystore struct {
	lastActivity time.Time
	unlockID     string
	derivedKey   []byte
	mu           sync.Mutex
	// shutDown is set by shutdown and guarded by mu. Once set, no key is
	// ever installed again.
	shutDown bool
	// unlockMu is held across derive and install so two unlocks cannot
	// run Argon2id at once or overwrite each other's key.
	unlockMu sync.Mutex
}

// Unlock derives a key from password and caches it when the verify blob
// opens. password is zeroed before return. A cached key is zeroed first
// so a re-unlock replaces it completely.
func (k *keystore) Unlock(password, salt, verify []byte, params database.Argon2idParams) error {
	k.unlockMu.Lock()
	defer k.unlockMu.Unlock()
	defer secure.SecureZeroBytes(password)

	if k.isShutDown() {
		return errShutDown
	}

	if err := database.ValidateUnlockMaterial(salt, verify, params); err != nil {
		return fmt.Errorf("%w: %v", errBadRequest, err)
	}

	derived := deriveKey(password, salt, params)

	opened, err := database.Decrypt(derived, verify)
	if err != nil || !bytes.Equal(opened, []byte(database.VerifyPlaintext)) {
		secure.SecureZeroBytes(derived)
		secure.SecureZeroBytes(opened)
		return errWrongPassword
	}
	secure.SecureZeroBytes(opened)

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.shutDown {
		secure.SecureZeroBytes(derived)
		return errShutDown
	}
	if k.derivedKey != nil {
		secure.SecureZeroBytes(k.derivedKey)
	}
	k.derivedKey = derived
	k.unlockID = UnlockID(verify)
	k.lastActivity = time.Now()
	return nil
}

func (k *keystore) Decrypt(ciphertext, salt []byte, unlockID string) ([]byte, error) {
	keyCopy, err := k.copyKey(unlockID)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(keyCopy)

	plain, err := database.DecryptEntry(keyCopy, ciphertext, salt)
	if err != nil {
		return nil, errDecryptFailed
	}
	return plain, nil
}

func (k *keystore) Encrypt(plaintext []byte, unlockID string) ([]byte, []byte, error) {
	keyCopy, err := k.copyKey(unlockID)
	if err != nil {
		return nil, nil, err
	}
	defer secure.SecureZeroBytes(keyCopy)
	return database.EncryptEntry(keyCopy, plaintext)
}

// shutdown zeroes the cached master key and refuses every later unlock.
// It does not wait for an unlock in progress: that unlock discards its
// key when it finishes.
func (k *keystore) shutdown() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.shutDown = true
	if k.derivedKey != nil {
		secure.SecureZeroBytes(k.derivedKey)
		k.derivedKey = nil
	}
	k.unlockID = ""
	k.lastActivity = time.Time{}
}

func (k *keystore) Status() (unlocked bool, id string, last time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.derivedKey == nil {
		return false, "", time.Time{}
	}
	return true, k.unlockID, k.lastActivity
}

func (k *keystore) copyKey(wantID string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	// No cached key is not_unlocked, including when wantID is empty or
	// names a vault this process has never unlocked.
	if k.derivedKey == nil {
		return nil, errNotUnlocked
	}
	if wantID != k.unlockID {
		return nil, errUnlockMismatch
	}
	cp := make([]byte, len(k.derivedKey))
	copy(cp, k.derivedKey)
	k.lastActivity = time.Now()
	return cp, nil
}

// UnlockID is the hex SHA-256 of the verify blob a key was checked
// against. The blob itself is stored on disk, so the id is not a secret.
func UnlockID(verify []byte) string {
	sum := sha256.Sum256(verify)
	return hex.EncodeToString(sum[:])
}

func (k *keystore) isShutDown() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.shutDown
}
