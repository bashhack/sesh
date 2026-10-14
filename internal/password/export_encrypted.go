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
	"strings"

	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/secure"
)

const encryptedExportVersion = 1

// EncryptedEnvelope is the on-disk format for a password-encrypted export.
// salt + params are public (needed to re-derive the key); ciphertext is the
// AES-256-GCM output of the JSON-serialized entries.
type EncryptedEnvelope struct {
	Algorithm  string     `json:"algorithm"`
	Salt       string     `json:"salt"`       // base64
	Ciphertext string     `json:"ciphertext"` // base64
	Params     kdf.Params `json:"params"`
	Version    int        `json:"version"`
}

// ExportEncrypted writes a password-encrypted export to w.
// The password is used to derive a key via Argon2id; the derived key
// encrypts the JSON payload with AES-256-GCM. The output is portable —
// anyone with the password can decrypt it, on any machine.
func (m *Manager) ExportEncrypted(w io.Writer, opts *ExportOptions, password []byte) (int, error) {
	if len(password) == 0 {
		return 0, fmt.Errorf("password cannot be empty")
	}

	var buf bytes.Buffer
	// The plain JSON is wiped however this ends.
	defer func() { secure.SecureZeroBytes(buf.Bytes()) }()
	count, err := m.Export(&buf, &ExportOptions{
		Format:    FormatJSON,
		EntryType: opts.EntryType,
		Folder:    opts.Folder,
		FolderSet: opts.FolderSet,
		Tags:      opts.Tags,
	})
	if err != nil {
		return 0, err
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return 0, fmt.Errorf("generate salt: %w", err)
	}

	params := opts.KDF
	if params == (kdf.Params{}) {
		params = kdf.Default()
	}
	if err := params.CheckBounds(); err != nil {
		return 0, fmt.Errorf("export settings: %w", err)
	}
	key := kdf.Derive(password, salt, params)
	defer secure.SecureZeroBytes(key)

	plaintext := buf.Bytes()
	ciphertext, err := gcmSeal(key, plaintext)
	secure.SecureZeroBytes(plaintext)
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
	payload, err := DecryptExport(r, password)
	if err != nil {
		return ImportResult{}, err
	}
	// Zeroes the JSON envelope buffer once Import returns, but the parsed
	// entry secrets land in immutable Go strings inside the unmarshalled
	// structs and outlive this defer — same caveat as elsewhere in the
	// codebase. See internal/secure/memory.go for the broader context.
	defer secure.SecureZeroBytes(payload)

	forwardOpts := opts
	forwardOpts.Format = FormatJSON
	return m.Import(bytes.NewReader(payload), forwardOpts)
}

// Sealed is a password-encrypted export whose envelope has been read and
// checked: its settings are ones sesh accepts, so its password can be
// asked for.
type Sealed struct {
	salt, ciphertext []byte
	params           kdf.Params
}

// ReadSealed reads and checks a password-encrypted export's envelope from
// r, opening nothing.
func ReadSealed(r io.Reader) (*Sealed, error) {
	var envelope EncryptedEnvelope
	if err := json.NewDecoder(r).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("read envelope: %w", err)
	}

	if envelope.Version != encryptedExportVersion {
		return nil, fmt.Errorf("unsupported envelope version %d (expected %d)", envelope.Version, encryptedExportVersion)
	}
	if envelope.Algorithm != "argon2id" {
		return nil, fmt.Errorf("unsupported algorithm %q", envelope.Algorithm)
	}
	// Bounded, so a damaged or hostile file can't make sesh use unbounded
	// memory or time.
	if err := envelope.Params.CheckBounds(); err != nil {
		return nil, fmt.Errorf("export envelope: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("envelope salt too short: %d bytes (min 16)", len(salt))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return &Sealed{salt: salt, ciphertext: ciphertext, params: envelope.Params}, nil
}

// Open is the export's JSON, which the caller wipes.
func (s *Sealed) Open(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	key := kdf.Derive(password, s.salt, s.params)
	defer secure.SecureZeroBytes(key)
	payload, err := gcmOpen(key, s.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted export: %w", err)
	}
	return payload, nil
}

// Entries are the export's entries, importing nothing. Their secrets are
// in Go strings, which can't be wiped.
func (s *Sealed) Entries(password []byte) ([]ExportEntry, error) {
	payload, err := s.Open(password)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(payload)
	entries, err := readJSON(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("read the export: %w", err)
	}
	return entries, nil
}

// IsEncryptedExport says whether b is a password-encrypted export's
// envelope.
func IsEncryptedExport(b []byte) bool {
	var envelope EncryptedEnvelope
	return json.Unmarshal(b, &envelope) == nil && envelope.Algorithm == "argon2id" && envelope.Ciphertext != "" && envelope.Salt != ""
}

// IsPlainExport says whether b is a plain export of sesh's: JSON or CSV.
func IsPlainExport(b []byte) bool {
	if bytes.HasPrefix(b, []byte(strings.Join(csvHeader, ",")+"\n")) {
		return true
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(b, &entries) != nil {
		return false
	}
	if len(entries) == 0 {
		// An empty export: nothing in it says another app's.
		return true
	}
	_, service := entries[0]["service"]
	_, kind := entries[0]["type"]
	return service && kind
}

// DecryptExport opens a password-encrypted export from r: its JSON, which
// the caller wipes.
func DecryptExport(r io.Reader, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	s, err := ReadSealed(r)
	if err != nil {
		return nil, err
	}
	return s.Open(password)
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
