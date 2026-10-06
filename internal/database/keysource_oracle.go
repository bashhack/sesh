package database

import "github.com/bashhack/sesh/internal/secure"

// keySourceOracle is the CryptoOracle for a KeySource that can hand out
// its key. Each call fetches the key, runs the entry crypto, and zeroes
// the key before returning.
type keySourceOracle struct {
	ks KeySource
}

// NewKeySourceOracle returns a CryptoOracle backed by ks. Closing the
// oracle closes ks when ks has a Close method.
func NewKeySourceOracle(ks KeySource) CryptoOracle {
	return &keySourceOracle{ks: ks}
}

func (o *keySourceOracle) EncryptEntry(plaintext, aad []byte) (encryptedData, salt []byte, err error) {
	key, err := o.ks.GetEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	defer secure.SecureZeroBytes(key)
	return EncryptEntry(key, plaintext, aad)
}

func (o *keySourceOracle) DecryptEntry(encryptedData, salt, aad []byte) ([]byte, error) {
	key, err := o.ks.GetEncryptionKey()
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(key)
	return DecryptEntry(key, encryptedData, salt, aad)
}

// Close releases the wrapped source (MasterPasswordSource zeroes its
// cached key).
func (o *keySourceOracle) Close() {
	if c, ok := o.ks.(interface{ Close() }); ok {
		c.Close()
	}
}
