package password

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/kdf"
)

func newEncryptedTestManager(t *testing.T) *Manager {
	t.Helper()
	m, _ := newTestManager(t)
	return m
}

func TestExportImportEncrypted_RoundTrip(t *testing.T) {
	mgr := newEncryptedTestManager(t)

	if err := mgr.StorePasswordString("github", "alice", "gh-secret", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("stripe", "admin", "sk_live_abc", EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	password := []byte("my-export-password")
	count, err := mgr.ExportEncrypted(&buf, &ExportOptions{KDF: kdf.Minimum()}, password)
	if err != nil {
		t.Fatalf("ExportEncrypted: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 exported, got %d", count)
	}

	plaintextSecrets := []string{"gh-secret", "sk_live_abc"}
	for _, s := range plaintextSecrets {
		if bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Fatalf("encrypted export contains plaintext secret %q", s)
		}
	}

	mgr2 := newEncryptedTestManager(t)
	result, err := mgr2.ImportEncrypted(&buf, ImportOptions{}, password)
	if err != nil {
		t.Fatalf("ImportEncrypted: %v", err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %d (errors: %v)", result.Imported, result.Errors)
	}

	got, err := mgr2.GetPasswordString("github", "alice", EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if got != "gh-secret" {
		t.Fatalf("expected 'gh-secret', got %q", got)
	}

	gotAPI, err := mgr2.GetPasswordString("stripe", "admin", EntryTypeAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if gotAPI != "sk_live_abc" {
		t.Fatalf("expected 'sk_live_abc', got %q", gotAPI)
	}
}

func TestImportEncrypted_WrongPassword(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	if err := mgr.StorePasswordString("github", "alice", "secret", EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := mgr.ExportEncrypted(&buf, &ExportOptions{KDF: kdf.Minimum()}, []byte("correct-password")); err != nil {
		t.Fatal(err)
	}

	mgr2 := newEncryptedTestManager(t)
	_, err := mgr2.ImportEncrypted(&buf, ImportOptions{}, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "wrong password or corrupted") {
		t.Errorf("error %q does not mention wrong password — may have failed an unrelated check", err.Error())
	}
}

func TestExportEncrypted_EmptyPassword(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	var buf bytes.Buffer
	_, err := mgr.ExportEncrypted(&buf, &ExportOptions{}, nil)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestImportEncrypted_EmptyPassword(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	_, err := mgr.ImportEncrypted(bytes.NewReader([]byte("{}")), ImportOptions{}, nil)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestImportEncrypted_UnsupportedVersion(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	data := []byte(`{"version": 99, "algorithm": "argon2id", "salt": "", "params": {}, "ciphertext": ""}`)
	_, err := mgr.ImportEncrypted(bytes.NewReader(data), ImportOptions{}, []byte("any"))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error %q does not mention version — may have failed an unrelated check", err.Error())
	}
}

func TestImportEncrypted_UnsupportedAlgorithm(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	data := []byte(`{"version": 1, "algorithm": "scrypt", "salt": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}, "ciphertext": ""}`)
	_, err := mgr.ImportEncrypted(bytes.NewReader(data), ImportOptions{}, []byte("any"))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("error %q does not mention algorithm — may have failed an unrelated check", err.Error())
	}
}

func TestImportEncrypted_RejectsOutOfRangeParams(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantSub string // substring the param-validation error must contain
	}{
		{"zero memory", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":3,"memory":0,"threads":4,"key_len":32}}`, "memory"},
		{"huge memory", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":3,"memory":2147483647,"threads":4,"key_len":32}}`, "memory"},
		{"zero time", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":0,"memory":65536,"threads":4,"key_len":32}}`, "time"},
		{"huge time", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":999,"memory":65536,"threads":4,"key_len":32}}`, "time"},
		{"zero threads", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":3,"memory":65536,"threads":0,"key_len":32}}`, "threads"},
		{"huge threads", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":3,"memory":65536,"threads":99,"key_len":32}}`, "threads"},
		{"wrong key_len", `{"version":1,"algorithm":"argon2id","salt":"","ciphertext":"","params":{"time":3,"memory":65536,"threads":4,"key_len":16}}`, "key_len"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newEncryptedTestManager(t)
			_, err := mgr.ImportEncrypted(bytes.NewReader([]byte(tc.body)), ImportOptions{}, []byte("any"))
			if err == nil {
				t.Fatal("expected error for out-of-range params")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q — may have failed an unrelated check", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestImportEncrypted_MalformedSaltOrCiphertext(t *testing.T) {
	const validSalt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes
	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{"bad salt base64", `{"version":1,"algorithm":"argon2id","salt":"!!!","ciphertext":"","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`, "decode salt"},
		{"short salt", `{"version":1,"algorithm":"argon2id","salt":"AAA=","ciphertext":"","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`, "salt too short"},
		{"bad ciphertext base64", `{"version":1,"algorithm":"argon2id","salt":"` + validSalt + `","ciphertext":"!!!","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`, "decode ciphertext"},
		{"short ciphertext", `{"version":1,"algorithm":"argon2id","salt":"` + validSalt + `","ciphertext":"AAA=","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`, "wrong password or corrupted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newEncryptedTestManager(t)
			_, err := mgr.ImportEncrypted(bytes.NewReader([]byte(tc.body)), ImportOptions{}, []byte("password"))
			if err == nil {
				t.Fatal("expected error for malformed envelope")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q — may have failed an unrelated check", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestImportEncrypted_BadJSON(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	_, err := mgr.ImportEncrypted(bytes.NewReader([]byte("not json")), ImportOptions{}, []byte("any"))
	if err == nil {
		t.Fatal("expected error for malformed JSON envelope")
	}
}

// An encrypted export records the settings it was made with; zero ones mean
// the defaults.
func TestExportEncrypted_RecordsItsSettings(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	if err := mgr.StorePasswordString("github", "alice", "gh-secret", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	for _, want := range []kdf.Params{{}, {Time: 2, Memory: 19 * 1024, Threads: 1, KeyLen: kdf.KeyLen}} {
		var buf bytes.Buffer
		if _, err := mgr.ExportEncrypted(&buf, &ExportOptions{KDF: want}, []byte("export-password")); err != nil {
			t.Fatal(err)
		}
		var env EncryptedEnvelope
		if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if want == (kdf.Params{}) {
			want = kdf.Default()
		}
		if env.Params != want {
			t.Errorf("envelope settings = %+v, want %+v", env.Params, want)
		}
	}
}

// An export whose settings are out of bounds is refused before any key is
// derived, so a hostile file can't make sesh use unbounded memory.
func TestImportEncrypted_RefusesSettingsOutOfBounds(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	env := `{"version":1,"algorithm":"argon2id","salt":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AA==","params":{"time":3,"memory":4294967295,"threads":4,"key_len":32}}`
	_, err := mgr.ImportEncrypted(strings.NewReader(env), ImportOptions{}, []byte("pw"))
	if err == nil || !strings.Contains(err.Error(), "export envelope: memory setting out of range") {
		t.Fatalf("err = %v", err)
	}
}
