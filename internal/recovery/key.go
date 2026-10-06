// Package recovery makes and uses a vault's recovery key: a random key the
// user writes down, which can open the vault when the master password is
// forgotten.
//
// The key is the seed of a P-256 key pair. sesh keeps only the public half
// (in the vault's recovery record) and wraps the vault key to it,
// which needs no secret, so a password change re-wraps the new key without
// asking for the recovery key. Only the written-down key can unwrap it.
package recovery

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/bashhack/sesh/internal/keywrap"
)

const (
	// alphabet is Crockford's base32: no I, L, O, or U, so handwriting
	// can't confuse 1 with I or 0 with O.
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// A key is 26 characters for its 128 bits (130 bits, the top two zero)
	// and 2 for a 10-bit checksum: 7 groups of 4.
	dataChars  = 26
	keyChars   = 28
	groupChars = 4

	checksumInfo = "sesh recovery key v1 checksum"
	privateInfo  = "sesh recovery key v1 private key"
	// wrapInfo names this use of a wrap (see keywrap), so a recovery wrap
	// never opens as another kind.
	wrapInfo = "sesh recovery key v1"
)

var (
	// ErrInvalidKey means the text isn't a recovery key: the wrong length,
	// a character that can't appear, or a typo the checksum caught.
	ErrInvalidKey = errors.New("invalid recovery key")
	// ErrWrongKey means a valid recovery key that doesn't open this vault's
	// recovery record: another vault's key, or one that has been replaced.
	ErrWrongKey = errors.New("this recovery key doesn't open this vault")
)

// invalidKeyError is an ErrInvalidKey with a message for the person typing.
type invalidKeyError string

func (e invalidKeyError) Error() string        { return string(e) }
func (e invalidKeyError) Is(target error) bool { return target == ErrInvalidKey }

// Key is a recovery key: 128 random bits.
type Key struct {
	secret [16]byte
}

// New makes a random recovery key.
func New() (Key, error) {
	var k Key
	if _, err := rand.Read(k.secret[:]); err != nil {
		return Key{}, err
	}
	return k, nil
}

// String is the key as the user writes it down: 7 groups of 4 characters.
func (k Key) String() string {
	vals := make([]byte, 0, keyChars)
	// 130 bits, most significant first: two zero bits, then the secret.
	var acc uint32
	bits := 2
	for _, b := range k.secret {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			vals = append(vals, byte(acc>>bits)&31) //nolint:gosec // keeps the low 5 bits on purpose
		}
	}
	c := k.checksum()
	vals = append(vals, byte(c>>5), byte(c&31)) //nolint:gosec // c is 10 bits: two 5-bit values

	var b strings.Builder
	for i, v := range vals {
		if i > 0 && i%groupChars == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[v])
	}
	return b.String()
}

// Parse reads a recovery key as the user typed it: any case, with or
// without dashes and spaces, and I or L for 1, O for 0.
func Parse(s string) (Key, error) {
	var vals []byte
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		i := strings.IndexRune(alphabet, r)
		if i < 0 {
			return Key{}, invalidKeyError(fmt.Sprintf("%q can't appear in a recovery key", string(r)))
		}
		vals = append(vals, byte(i)) //nolint:gosec // an index into the 32-character alphabet
	}
	if len(vals) != keyChars {
		return Key{}, invalidKeyError(fmt.Sprintf("a recovery key has %d characters (7 groups of 4); got %d", keyChars, len(vals)))
	}
	typo := invalidKeyError("that's not a valid recovery key: a character is wrong")
	// The first character holds the two always-zero bits.
	if vals[0] >= 8 {
		return Key{}, typo
	}
	var k Key
	var acc uint32
	bits := 0
	n := 0
	for i, v := range vals[:dataChars] {
		acc = acc<<5 | uint32(v)
		bits += 5
		if i == 0 {
			bits -= 2 // drop the two zero bits
		}
		for bits >= 8 {
			bits -= 8
			k.secret[n] = byte(acc >> bits) //nolint:gosec // keeps the low 8 bits on purpose
			n++
		}
	}
	if c := uint16(vals[dataChars])<<5 | uint16(vals[dataChars+1]); c != k.checksum() {
		return Key{}, typo
	}
	return k, nil
}

// checksum is 10 bits of a hash of the secret.
func (k Key) checksum() uint16 {
	h := sha256.Sum256(append([]byte(checksumInfo), k.secret[:]...))
	return (uint16(h[0])<<8 | uint16(h[1])) >> 6
}

// privateKey derives the key pair from the secret. A derived value that
// isn't a valid P-256 scalar (about one in 2^32) is skipped by counting on.
func (k Key) privateKey() (*ecdh.PrivateKey, error) {
	for i := range 16 {
		b, err := hkdf.Key(sha256.New, k.secret[:], nil, fmt.Sprintf("%s %d", privateInfo, i), 32)
		if err != nil {
			return nil, err
		}
		priv, err := ecdh.P256().NewPrivateKey(b)
		clear(b)
		if err == nil {
			return priv, nil
		}
	}
	return nil, errors.New("recovery key: no valid private key derived")
}

// PublicKey is the uncompressed P-256 public key the vault key is wrapped to.
func (k Key) PublicKey() ([]byte, error) {
	priv, err := k.privateKey()
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

// Wrap seals secret (the vault key) to pub, a recovery key's public key,
// binding it to aad (the vault's unlock id). It needs no recovery key.
func Wrap(pub, secret, aad []byte) (keywrap.Wrapped, error) {
	return keywrap.Wrap(pub, secret, aad, wrapInfo)
}

// CheckPublicKey reports whether pub is a public key Wrap can wrap to.
func CheckPublicKey(pub []byte) error {
	_, err := ecdh.P256().NewPublicKey(pub)
	return err
}

// Unwrap recovers the secret wrapped to this key's public key, bound to aad.
func (k Key) Unwrap(w keywrap.Wrapped, aad []byte) ([]byte, error) {
	priv, err := k.privateKey()
	if err != nil {
		return nil, err
	}
	secret, err := keywrap.Unwrap(func(peer []byte) ([]byte, error) {
		p, err := ecdh.P256().NewPublicKey(peer)
		if err != nil {
			return nil, err
		}
		return priv.ECDH(p)
	}, w, aad, wrapInfo)
	if errors.Is(err, keywrap.ErrMismatch) {
		return nil, ErrWrongKey
	}
	return secret, err
}
