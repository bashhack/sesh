//go:build darwin && cgo && touchid_hardware

package touchid

import (
	"bytes"
	"testing"
)

// Run by hand on a Mac with Touch ID; it asks for a fingerprint:
//
//	go test -tags touchid_hardware -run TestHardware -v ./internal/touchid
func TestHardware_WrapThenUnwrapWithAFingerprint(t *testing.T) {
	if !Available() {
		t.Skip("Touch ID isn't available to this process")
	}
	blob, pub, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	t.Logf("Secure Enclave key: %d-byte blob, %d-byte public key", len(blob), len(pub))
	secret := bytes.Repeat([]byte{0x42}, 32)
	w, err := Wrap(pub, secret, []byte("hardware test"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(blob, w, []byte("hardware test"), "run the sesh Touch ID hardware test", "Use Test Password")
	if err != nil {
		t.Fatalf("Unwrap (touch the sensor when asked): %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unwrapped %x, want %x", got, secret)
	}
}
