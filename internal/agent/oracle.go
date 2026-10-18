package agent

import (
	"errors"
	"fmt"
	"sync"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
)

// Oracle encrypts and decrypts entries through an already-unlocked agent;
// the master key stays in the agent process. It is a
// database.CryptoOracle and not a database.KeySource, so it has no way to
// hand out the key. unlockID is the vault this oracle was built for;
// every request carries it so a later unlock of a different vault cannot
// seal this vault's entries.
type Oracle struct {
	conn     *Conn
	unlockID string
	mu       sync.Mutex
	closed   bool
}

// NewOracle wraps a connection to an agent that holds this vault's key.
// unlockID is the vault's id (UnlockID of its verify blob); the
// agent refuses requests once it holds a different key. The caller
// transfers ownership of conn.
func NewOracle(conn *Conn, unlockID string) *Oracle {
	return &Oracle{conn: conn, unlockID: unlockID}
}

// UnlockID is the id of the vault this oracle was built for.
func (o *Oracle) UnlockID() (string, error) { return o.unlockID, nil }

func (o *Oracle) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, nil, fmt.Errorf("agent oracle is closed")
	}
	ct, salt, err := Encrypt(o.conn, plaintext, aad, o.unlockID)
	return ct, salt, userFacing(err)
}

func (o *Oracle) DecryptEntry(encryptedData, salt, aad []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, fmt.Errorf("agent oracle is closed")
	}
	plain, err := Decrypt(o.conn, encryptedData, salt, aad, o.unlockID)
	return plain, userFacing(err)
}

// Check asks whether the agent still holds this oracle's vault key,
// without restarting its idle timer: an error Locked reports when it
// doesn't, or can't be reached.
func (o *Oracle) Check() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return fmt.Errorf("agent oracle is closed")
	}
	st, err := Status(o.conn)
	switch {
	case err != nil:
		return err
	case !st.Unlocked:
		return &ProtocolError{Code: ErrCodeNotUnlocked, Message: "agent is locked"}
	case st.UnlockID != o.unlockID:
		return &vaultChangedError{cause: &ProtocolError{Code: ErrCodeUnlockMismatch}}
	}
	return nil
}

// WrapKey wraps this oracle's vault key to the public key pub, for
// purpose, in the agent (see WrapKey).
func (o *Oracle) WrapKey(purpose string, pub []byte) (keywrap.Wrapped, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return keywrap.Wrapped{}, fmt.Errorf("agent oracle is closed")
	}
	w, err := WrapKey(o.conn, o.unlockID, purpose, pub)
	return w, userFacing(err)
}

// Touch tells the agent this oracle's vault is still in use, so its idle
// timer starts again.
func (o *Oracle) Touch() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return fmt.Errorf("agent oracle is closed")
	}
	return userFacing(Touch(o.conn, o.unlockID))
}

// vaultChangedError reports that the agent now holds another vault's
// key. Error() is written for the user; Unwrap keeps the ProtocolError
// reachable for callers that check the code.
type vaultChangedError struct{ cause error }

func (e *vaultChangedError) Error() string {
	return "sesh agent is unlocked for a different vault; run the command again to re-unlock"
}

func (e *vaultChangedError) Unwrap() error { return e.cause }

func userFacing(err error) error {
	var pe *ProtocolError
	switch {
	case errors.As(err, &pe) && pe.Code == ErrCodeUnlockMismatch:
		return &vaultChangedError{cause: err}
	case errors.As(err, &pe) && pe.Code == ErrCodeDecryptFailed:
		// The ciphertext doesn't decrypt with the agent's key, as the
		// direct path reports it.
		return fmt.Errorf("%w (%w)", database.ErrDecrypt, err)
	}
	return err
}

// Close drops the agent connection. The agent process keeps the key.
func (o *Oracle) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return
	}
	o.closed = true
	closeOrLog(o.conn, "agent oracle")
}

var _ database.CryptoOracle = (*Oracle)(nil)
