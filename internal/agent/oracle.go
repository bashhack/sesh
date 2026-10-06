package agent

import (
	"errors"
	"fmt"
	"sync"

	"github.com/bashhack/sesh/internal/database"
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
	if errors.As(err, &pe) && pe.Code == ErrCodeUnlockMismatch {
		return &vaultChangedError{cause: err}
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
