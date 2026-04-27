package password

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
)

func newEncryptedTestManager(t *testing.T) *Manager {
	t.Helper()
	data := map[string][]byte{}
	desc := map[string]string{}
	kc := &mocks.MockProvider{
		GetSecretFunc: func(account, service string) ([]byte, error) {
			v, ok := data[service]
			if !ok {
				return nil, keychain.ErrNotFound
			}
			cp := make([]byte, len(v))
			copy(cp, v)
			return cp, nil
		},
		SetSecretFunc: func(account, service string, secret []byte) error {
			cp := make([]byte, len(secret))
			copy(cp, secret)
			data[service] = cp
			return nil
		},
		DeleteEntryFunc: func(account, service string) error {
			delete(data, service)
			return nil
		},
		SetDescriptionFunc: func(service, account, description string) error {
			desc[service] = description
			return nil
		},
		ListEntriesFunc: func(prefix string) ([]keychain.KeychainEntry, error) {
			var entries []keychain.KeychainEntry
			for svc := range data {
				if strings.HasPrefix(svc, prefix) {
					entries = append(entries, keychain.KeychainEntry{Service: svc, Account: "testuser", Description: desc[svc]})
				}
			}
			return entries, nil
		},
	}
	return NewManager(kc, "testuser")
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
	count, err := mgr.ExportEncrypted(&buf, ExportOptions{}, password)
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
	if _, err := mgr.ExportEncrypted(&buf, ExportOptions{}, []byte("correct-password")); err != nil {
		t.Fatal(err)
	}

	mgr2 := newEncryptedTestManager(t)
	_, err := mgr2.ImportEncrypted(&buf, ImportOptions{}, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestExportEncrypted_EmptyPassword(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	var buf bytes.Buffer
	_, err := mgr.ExportEncrypted(&buf, ExportOptions{}, nil)
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
}

func TestImportEncrypted_UnsupportedAlgorithm(t *testing.T) {
	mgr := newEncryptedTestManager(t)
	data := []byte(`{"version": 1, "algorithm": "scrypt", "salt": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}, "ciphertext": ""}`)
	_, err := mgr.ImportEncrypted(bytes.NewReader(data), ImportOptions{}, []byte("any"))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
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
	cases := map[string]string{
		"bad salt base64":       `{"version":1,"algorithm":"argon2id","salt":"!!!","ciphertext":"","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`,
		"short salt":            `{"version":1,"algorithm":"argon2id","salt":"AAA=","ciphertext":"","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`,
		"bad ciphertext base64": `{"version":1,"algorithm":"argon2id","salt":"` + validSalt + `","ciphertext":"!!!","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`,
		"short ciphertext":      `{"version":1,"algorithm":"argon2id","salt":"` + validSalt + `","ciphertext":"AAA=","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			mgr := newEncryptedTestManager(t)
			_, err := mgr.ImportEncrypted(bytes.NewReader([]byte(body)), ImportOptions{}, []byte("password"))
			if err == nil {
				t.Fatal("expected error for malformed envelope")
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
