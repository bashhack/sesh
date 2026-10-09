package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/bashhack/sesh/internal/secure"
)

// The key derivations a password-protected export may use (kdf-type.enum.ts).
const (
	kdfPBKDF2   = 0
	kdfArgon2id = 1
)

// Bounds on the KDF settings an export may ask for, so a damaged or hostile
// file can't make sesh spend unbounded time or memory. Bitwarden's own
// minimums (bitwarden-crypto kdf.rs) are 5000 PBKDF2 iterations, and for
// Argon2id 16 MiB, 2 iterations, 1 thread.
const (
	maxPBKDF2Iterations = 10_000_000
	maxArgon2MemoryMiB  = 1024
	maxArgon2Iterations = 10
	maxArgon2Threads    = 16
)

// ErrWrongPassword is a password that doesn't open the export.
var ErrWrongPassword = errors.New("wrong password for this Bitwarden export, or the file is damaged")

// decrypt opens a password-protected export's data, as Bitwarden makes it
// (base-vault-export.service.ts, default-key-generation.service.ts):
//   - the salt is the UTF-8 bytes of its base64 text, not the decoded
//     bytes; Argon2id gets SHA-256 of that;
//   - PBKDF2-SHA256 or Argon2id gives a 32-byte key, stretched by
//     HKDF-Expand (SHA-256, no extract) into "enc" and "mac" keys;
//   - the data is an EncString "2.iv|ciphertext|mac": AES-256-CBC, with
//     HMAC-SHA256 over the IV and ciphertext, checked first.
//
// The password is checked against encKeyValidation_DO_NOT_EDIT first.
func decrypt(env *envelope, password []byte) ([]byte, error) {
	if env.Salt == "" || env.Data == "" || env.Validation == "" {
		return nil, errors.New("this Bitwarden export is damaged: its salt, data, or check is missing")
	}
	key, err := deriveKey(env, password)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(key)
	encKey, err := hkdf.Expand(sha256.New, key, "enc", 32)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(encKey)
	macKey, err := hkdf.Expand(sha256.New, key, "mac", 32)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(macKey)
	if _, err := openEncString(env.Validation, encKey, macKey); err != nil {
		return nil, ErrWrongPassword
	}
	plain, err := openEncString(env.Data, encKey, macKey)
	if err != nil {
		return nil, fmt.Errorf("this Bitwarden export is damaged: %w", err)
	}
	return plain, nil
}

func deriveKey(env *envelope, password []byte) ([]byte, error) {
	salt := []byte(env.Salt)
	switch env.KDFType {
	case kdfPBKDF2:
		if env.KDFIterations < 1 || env.KDFIterations > maxPBKDF2Iterations {
			return nil, fmt.Errorf("this Bitwarden export asks for %d PBKDF2 iterations, which sesh doesn't accept", env.KDFIterations)
		}
		return pbkdf2.Key(sha256.New, string(password), salt, env.KDFIterations, 32)
	case kdfArgon2id:
		if env.KDFIterations < 1 || env.KDFIterations > maxArgon2Iterations ||
			env.KDFMemory < 1 || env.KDFMemory > maxArgon2MemoryMiB ||
			env.KDFParallelism < 1 || env.KDFParallelism > maxArgon2Threads {
			return nil, fmt.Errorf("this Bitwarden export asks for Argon2id settings sesh doesn't accept (%d MiB, %d passes, %d threads)", env.KDFMemory, env.KDFIterations, env.KDFParallelism)
		}
		hashed := sha256.Sum256(salt)
		return argon2.IDKey(password, hashed[:], uint32(env.KDFIterations), uint32(env.KDFMemory)*1024, uint8(env.KDFParallelism), 32), nil //nolint:gosec // bounded above
	}
	return nil, fmt.Errorf("this Bitwarden export uses a key derivation sesh doesn't know (type %d)", env.KDFType)
}

// openEncString checks and decrypts a type 2 EncString, "2.iv|ct|mac".
func openEncString(s string, encKey, macKey []byte) ([]byte, error) {
	body, ok := strings.CutPrefix(s, "2.")
	if !ok {
		return nil, errors.New("an encrypted value isn't of the kind exports use")
	}
	parts := strings.Split(body, "|")
	if len(parts) != 3 {
		return nil, errors.New("an encrypted value doesn't have three parts")
	}
	var dec [3][]byte
	for i, p := range parts {
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("an encrypted value doesn't read: %w", err)
		}
		dec[i] = b
	}
	iv, ct, mac := dec[0], dec[1], dec[2]
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, errors.New("an encrypted value doesn't match its check")
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("an encrypted value has the wrong length")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	n := int(plain[len(plain)-1])
	if n < 1 || n > aes.BlockSize || !bytes.Equal(plain[len(plain)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		secure.SecureZeroBytes(plain)
		return nil, errors.New("an encrypted value's padding is wrong")
	}
	return plain[:len(plain)-n], nil
}
