package screenlock

import (
	"runtime"
	"testing"
)

// Asking never fails; off macOS, or without a session to ask, it's not known.
func TestLocked(t *testing.T) {
	locked, known := Locked()
	if runtime.GOOS != "darwin" && (locked || known) {
		t.Errorf("Locked() = %v, %v off macOS", locked, known)
	}
	if locked && !known {
		t.Error("locked, but not known")
	}
}
