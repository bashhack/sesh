package agent

import (
	"errors"
	"fmt"
	"sync"

	"github.com/bashhack/sesh/internal/database"
)

// AgentKeySource proxies entry encryption through an already-unlocked
// agent. The master key stays in the agent process. unlockID is the
// verify-blob id this source was built for; encrypt and decrypt send it
// so a later unlock of a different vault cannot seal this vault's entries.
// It is a database.CryptoOracle and not a KeySource: it has no way to
// hand out the key.
type AgentKeySource struct {
	conn     *Conn
	unlockID string
	mu       sync.Mutex
	closed   bool
}

// NewAgentKeySource wraps a connection to an agent that holds this
// vault's key. unlockID is the vault's id (UnlockID of its sidecar
// verify blob); every request carries it, and the agent refuses once it
// holds a different key. The caller transfers ownership of conn.
func NewAgentKeySource(conn *Conn, unlockID string) *AgentKeySource {
	return &AgentKeySource{conn: conn, unlockID: unlockID}
}

func (s *AgentKeySource) EncryptEntry(plaintext []byte) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, fmt.Errorf("agent key source is closed")
	}
	ct, salt, err := Encrypt(s.conn, plaintext, s.unlockID)
	return ct, salt, userFacing(err)
}

func (s *AgentKeySource) DecryptEntry(encryptedData, salt []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("agent key source is closed")
	}
	plain, err := Decrypt(s.conn, encryptedData, salt, s.unlockID)
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
func (s *AgentKeySource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	closeOrLog(s.conn, "agent key source")
}

var _ database.CryptoOracle = (*AgentKeySource)(nil)
