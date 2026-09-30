package database

import (
	"bytes"
	"testing"
)

type closingKeySource struct {
	mockKeySource
	closed bool
}

func (c *closingKeySource) Close() { c.closed = true }

func TestKeySourceOracle_RoundTripAndClose(t *testing.T) {
	ks := &closingKeySource{mockKeySource: mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)}}
	oracle := NewKeySourceOracle(ks)

	ct, salt, err := oracle.EncryptEntry([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := oracle.DecryptEntry(ct, salt)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("plaintext = %q", got)
	}

	closer, ok := oracle.(interface{ Close() })
	if !ok {
		t.Fatal("oracle has no Close")
	}
	closer.Close()
	if !ks.closed {
		t.Fatal("Close did not reach the wrapped key source")
	}
}
