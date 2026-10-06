package agent

import (
	"errors"
	"testing"

	"github.com/bashhack/sesh/internal/database"
)

// The agent's "doesn't decrypt" reply is database.ErrDecrypt, as the direct
// path reports it; a locked agent isn't.
func TestUserFacing_DecryptFailure(t *testing.T) {
	if err := userFacing(&ProtocolError{Code: ErrCodeDecryptFailed, Message: "decrypt failed"}); !errors.Is(err, database.ErrDecrypt) {
		t.Errorf("decrypt_failed: err = %v, want ErrDecrypt", err)
	}
	if err := userFacing(&ProtocolError{Code: ErrCodeNotUnlocked, Message: "agent is locked"}); errors.Is(err, database.ErrDecrypt) {
		t.Errorf("not_unlocked: err = %v, want it not to be ErrDecrypt", err)
	}
}
