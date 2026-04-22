package password

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/bashhack/sesh/internal/secure"
)

const encryptedExportVersion = 1

// encryptedExportParams holds Argon2id tuning for the encrypted export envelope.
// Kept local to avoid importing the database package (import cycle).
type encryptedExportParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

func defaultEncryptedExportParams() encryptedExportParams {
	return encryptedExportParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
	}
}

// EncryptedEnvelope is the on-disk format for a password-encrypted export.
// salt + params are public (needed to re-derive the key); ciphertext is the
// AES-256-GCM output of the JSON-serialized entries.
type EncryptedEnvelope struct {
	Algorithm  string                `json:"algorithm"`
	Salt       string                `json:"salt"`       // base64
	Ciphertext string                `json:"ciphertext"` // base64
	Params     encryptedExportParams `json:"params"`
	Version    int                   `json:"version"`
}

// ExportEncrypted writes a password-encrypted export to w.
// The password is used to derive a key via Argon2id; the derived key
// encrypts the JSON payload with AES-256-GCM. The output is portable —
// anyone with the password can decrypt it, regardless of key source.
func (m *Manager) ExportEncrypted(w io.Writer, opts ExportOptions, password []byte) (int, error) {
	if len(password) == 0 {
		return 0, fmt.Errorf("password cannot be empty")
	}

	var buf bytes.Buffer
	count, err := m.Export(&buf, ExportOptions{
		Format:    FormatJSON,
		EntryType: opts.EntryType,
	})
	if err != nil {
		return 0, err
	}
	defer secure.SecureZeroBytes(buf.Bytes())

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return 0, fmt.Errorf("generate salt: %w", err)
	}

	params := defaultEncryptedExportParams()
	key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	defer secure.SecureZeroBytes(key)

	ciphertext, err := gcmSeal(key, buf.Bytes())
	if err != nil {
		return 0, fmt.Errorf("encrypt payload: %w", err)
	}

	envelope := EncryptedEnvelope{
		Version:    encryptedExportVersion,
		Algorithm:  "argon2id",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Params:     params,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return 0, fmt.Errorf("write envelope: %w", err)
	}
	return count, nil
}

// ImportEncrypted reads a password-encrypted export from r and imports it.
func (m *Manager) ImportEncrypted(r io.Reader, opts ImportOptions, password []byte) (ImportResult, error) {
	if len(password) == 0 {
		return ImportResult{}, fmt.Errorf("password cannot be empty")
	}

	var envelope EncryptedEnvelope
	if err := json.NewDecoder(r).Decode(&envelope); err != nil {
		return ImportResult{}, fmt.Errorf("read envelope: %w", err)
	}

	if envelope.Version != encryptedExportVersion {
		return ImportResult{}, fmt.Errorf("unsupported envelope version %d (expected %d)", envelope.Version, encryptedExportVersion)
	}

	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return ImportResult{}, fmt.Errorf("decode salt: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return ImportResult{}, fmt.Errorf("decode ciphertext: %w", err)
	}

	p := envelope.Params
	key := argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	defer secure.SecureZeroBytes(key)

	payload, err := gcmOpen(key, ciphertext)
	if err != nil {
		return ImportResult{}, fmt.Errorf("wrong password or corrupted export: %w", err)
	}
	defer secure.SecureZeroBytes(payload)

	forwardOpts := opts
	forwardOpts.Format = FormatJSON
	return m.Import(bytes.NewReader(payload), forwardOpts)
}

// gcmSeal returns nonce || ciphertext || tag.
func gcmSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func gcmOpen(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, enc := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, enc, nil)
}
