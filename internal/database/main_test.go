package database

import (
	"os"
	"testing"
)

// TestMain gives the vaults tests create cheap Argon2id settings, so the
// many derivations stay fast; tests that care about the settings say so.
func TestMain(m *testing.M) {
	newSourceParams = func() Argon2idParams { return Argon2idParams{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32} }
	os.Exit(m.Run())
}
