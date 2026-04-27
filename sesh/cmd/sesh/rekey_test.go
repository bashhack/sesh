package main

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keychain"
)

type rekeyTestEnv struct {
	tmpDir      string
	dataDir     string
	dbPath      string
	sidecarPath string
	account     string
}

func setupRekeyEnv(t *testing.T) *rekeyTestEnv {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "xdg"))
	t.Setenv("SESH_BACKEND", "sqlite")
	t.Setenv("SESH_KEY_SOURCE", "")
	t.Setenv("SESH_MASTER_PASSWORD", "")

	dbPath, err := database.DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath: %v", err)
	}
	dataDir := filepath.Dir(dbPath)
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	return &rekeyTestEnv{
		tmpDir:      tmp,
		dataDir:     dataDir,
		dbPath:      dbPath,
		sidecarPath: filepath.Join(dataDir, "passwords.key"),
		account:     u.Username,
	}
}

func hexKey() []byte {
	return []byte(strings.Repeat("ab", 32))
}

func rekeyTestApp(stdin string) (*App, *bytes.Buffer) {
	stderr := new(bytes.Buffer)
	return &App{
		Stdin:  strings.NewReader(stdin),
		Stdout: new(bytes.Buffer),
		Stderr: stderr,
		Exit:   func(int) {},
	}, stderr
}

type kcMock struct {
	stored []byte
	mu     sync.Mutex
}

func newKCMock(stored []byte) *kcMock {
	if stored == nil {
		return &kcMock{}
	}
	return &kcMock{stored: append([]byte{}, stored...)}
}

func (m *kcMock) GetSecret(_, _ string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stored == nil {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, m.stored...), nil
}

func (m *kcMock) SetSecret(_, _ string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored = append([]byte{}, secret...)
	return nil
}

func (m *kcMock) GetSecretString(_, _ string) (string, error)            { return "", nil }
func (m *kcMock) SetSecretString(_, _, _ string) error                   { return nil }
func (m *kcMock) GetMFASerialBytes(_, _ string) ([]byte, error)          { return nil, keychain.ErrNotFound }
func (m *kcMock) ListEntries(_ string) ([]keychain.KeychainEntry, error) { return nil, nil }
func (m *kcMock) SetDescription(_, _, _ string) error                    { return nil }
func (m *kcMock) DeleteEntry(_, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored = nil
	return nil
}

func populateKeychainStore(t *testing.T, env *rekeyTestEnv, kc keychain.Provider, entries map[string]string) {
	t.Helper()
	ks := database.NewKeychainSource(kc, env.account)
	store, err := database.Open(env.dbPath, ks)
	if err != nil {
		t.Fatalf("open store for seeding: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close seed store: %v", cerr)
		}
	}()
	if err := store.InitKeyMetadata(); err != nil {
		t.Fatalf("init key metadata: %v", err)
	}
	for service, secret := range entries {
		if err := store.SetSecret(env.account, service, []byte(secret)); err != nil {
			t.Fatalf("seed entry %s: %v", service, err)
		}
	}
}

func populatePasswordStore(t *testing.T, env *rekeyTestEnv, entries map[string]string) {
	t.Helper()
	ks := database.NewMasterPasswordSource(env.dataDir, promptMasterPassword)
	store, err := database.Open(env.dbPath, ks)
	if err != nil {
		t.Fatalf("open store for seeding: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close seed store: %v", cerr)
		}
	}()
	if err := store.InitKeyMetadata(); err != nil {
		t.Fatalf("init key metadata: %v", err)
	}
	for service, secret := range entries {
		if err := store.SetSecret(env.account, service, []byte(secret)); err != nil {
			t.Fatalf("seed entry %s: %v", service, err)
		}
	}
}

func readEntriesViaPassword(t *testing.T, env *rekeyTestEnv, services []string) map[string]string {
	t.Helper()
	ks := database.NewMasterPasswordSource(env.dataDir, promptMasterPassword)
	store, err := database.Open(env.dbPath, ks)
	if err != nil {
		t.Fatalf("open store for verify: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close verify store: %v", cerr)
		}
	}()
	out := make(map[string]string, len(services))
	for _, svc := range services {
		b, err := store.GetSecret(env.account, svc)
		if err != nil {
			t.Fatalf("get entry %s: %v", svc, err)
		}
		out[svc] = string(b)
	}
	return out
}

func readEntriesViaKeychain(t *testing.T, env *rekeyTestEnv, kc keychain.Provider, services []string) map[string]string {
	t.Helper()
	ks := database.NewKeychainSource(kc, env.account)
	store, err := database.Open(env.dbPath, ks)
	if err != nil {
		t.Fatalf("open store for verify: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close verify store: %v", cerr)
		}
	}()
	out := make(map[string]string, len(services))
	for _, svc := range services {
		b, err := store.GetSecret(env.account, svc)
		if err != nil {
			t.Fatalf("get entry %s: %v", svc, err)
		}
		out[svc] = string(b)
	}
	return out
}

func TestRekey_RefusesIfBackendNotSqlite(t *testing.T) {
	t.Setenv("SESH_BACKEND", "")
	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=password"}, nil)
	if err == nil || !strings.Contains(err.Error(), "SESH_BACKEND=sqlite") {
		t.Fatalf("expected SESH_BACKEND error, got %v", err)
	}
}

func TestRekey_RefusesIfTargetMissing(t *testing.T) {
	t.Setenv("SESH_BACKEND", "sqlite")
	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--to") {
		t.Fatalf("expected --to error, got %v", err)
	}
}

func TestRekey_RefusesIfTargetInvalid(t *testing.T) {
	t.Setenv("SESH_BACKEND", "sqlite")
	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=banana"}, nil)
	if err == nil || !strings.Contains(err.Error(), "--to") {
		t.Fatalf("expected --to validation error, got %v", err)
	}
}

func TestRekey_RefusesIfSameSource(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "test-password-1234")
	populatePasswordStore(t, env, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=password"}, nil)
	if err == nil || !strings.Contains(err.Error(), "already using") {
		t.Fatalf("expected already-using error, got %v", err)
	}
}

func TestRekey_RefusesIfNoDatabase(t *testing.T) {
	setupRekeyEnv(t)
	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=password"}, newKCMock(hexKey()))
	if err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatalf("expected no-database error, got %v", err)
	}
}

func TestRekey_RefusesIfTargetSidecarExists(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	if err := os.WriteFile(env.sidecarPath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("pre-create sidecar: %v", err)
	}

	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=password"}, kc)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected sidecar-exists error, got %v", err)
	}

	if _, err := os.Stat(env.dbPath); err != nil {
		t.Fatalf("source DB should still exist: %v", err)
	}
	if _, err := os.Stat(env.dbPath + rekeyBackupSuffix); err == nil {
		t.Fatalf("backup file should not exist on refusal")
	}
}

func TestRekey_KeychainToPassword(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	entries := map[string]string{
		"sesh-password/password/github/alice": "hunter2",
		"sesh-totp/github":                    "JBSWY3DPEHPK3PXP",
		"sesh-password/api_key/stripe/admin":  "sk_test_xyz",
	}
	populateKeychainStore(t, env, kc, entries)

	t.Setenv("SESH_MASTER_PASSWORD", "new-master-password-1234")

	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=password"}, kc); err != nil {
		t.Fatalf("runRekey: %v\nstderr:\n%s", err, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Rekeyed 3 entries") {
		t.Errorf("stderr missing rekey summary:\n%s", stderr.String())
	}
	if _, err := os.Stat(env.dbPath + rekeyBackupSuffix); err != nil {
		t.Errorf("backup DB missing: %v", err)
	}
	if _, err := os.Stat(env.sidecarPath); err != nil {
		t.Errorf("new sidecar missing: %v", err)
	}
	// Old keychain entry left in place — the design contract.
	if existing, err := kc.GetSecret(env.account, encKeyService); err != nil {
		t.Errorf("old keychain entry should still exist: %v", err)
	} else if len(existing) != 64 {
		t.Errorf("old keychain entry hex length = %d, want 64", len(existing))
	}

	services := make([]string, 0, len(entries))
	for s := range entries {
		services = append(services, s)
	}
	got := readEntriesViaPassword(t, env, services)
	for svc, want := range entries {
		if got[svc] != want {
			t.Errorf("entry %s = %q, want %q", svc, got[svc], want)
		}
	}
}

func TestRekey_PasswordToKeychain(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	entries := map[string]string{
		"sesh-password/password/github/alice": "hunter2",
		"sesh-totp/github":                    "JBSWY3DPEHPK3PXP",
	}
	populatePasswordStore(t, env, entries)

	kc := &kcMock{}

	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=keychain"}, kc); err != nil {
		t.Fatalf("runRekey: %v\nstderr:\n%s", err, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Rekeyed 2 entries") {
		t.Errorf("stderr missing rekey summary:\n%s", stderr.String())
	}
	if _, err := os.Stat(env.sidecarPath); err != nil {
		t.Errorf("old sidecar should still exist: %v", err)
	}
	if kc.stored == nil {
		t.Errorf("new keychain entry not stored")
	} else if len(kc.stored) != 64 {
		t.Errorf("new keychain entry hex length = %d, want 64", len(kc.stored))
	}
	if _, err := os.Stat(env.dbPath + rekeyBackupSuffix); err != nil {
		t.Errorf("backup DB missing: %v", err)
	}

	services := []string{"sesh-password/password/github/alice", "sesh-totp/github"}
	got := readEntriesViaKeychain(t, env, kc, services)
	for svc, want := range entries {
		if got[svc] != want {
			t.Errorf("entry %s = %q, want %q", svc, got[svc], want)
		}
	}
}

func TestRekey_PreservesTimestamps(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	srcKS := database.NewKeychainSource(kc, env.account)
	srcStore, err := database.Open(env.dbPath, srcKS)
	if err != nil {
		t.Fatal(err)
	}
	srcEntries, err := srcStore.ListEntries("sesh-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(srcEntries) != 1 {
		t.Fatalf("setup: expected 1 entry, got %d", len(srcEntries))
	}
	wantCreated := srcEntries[0].CreatedAt
	wantUpdated := srcEntries[0].UpdatedAt
	if err := srcStore.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "new-master-password-1234")

	app, _ := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=password"}, kc); err != nil {
		t.Fatalf("runRekey: %v", err)
	}

	mps := database.NewMasterPasswordSource(env.dataDir, promptMasterPassword)
	store, err := database.Open(env.dbPath, mps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("close verify store: %v", cerr)
		}
	}()
	postEntries, err := store.ListEntries("sesh-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(postEntries) != 1 {
		t.Fatalf("post-rekey: expected 1 entry, got %d", len(postEntries))
	}
	if !postEntries[0].CreatedAt.Equal(wantCreated) {
		t.Errorf("CreatedAt = %v, want %v", postEntries[0].CreatedAt, wantCreated)
	}
	if !postEntries[0].UpdatedAt.Equal(wantUpdated) {
		t.Errorf("UpdatedAt = %v, want %v", postEntries[0].UpdatedAt, wantUpdated)
	}
}

func TestRekey_EmptyDB(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, nil)

	t.Setenv("SESH_MASTER_PASSWORD", "new-master-password-1234")

	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=password"}, kc); err != nil {
		t.Fatalf("runRekey: %v", err)
	}
	if !strings.Contains(stderr.String(), "Rekeyed 0 entries") {
		t.Errorf("stderr missing zero-entry summary:\n%s", stderr.String())
	}
	if _, err := os.Stat(env.sidecarPath); err != nil {
		t.Errorf("new sidecar should be created even for empty DB: %v", err)
	}
}

func TestRekey_CancelledLeavesNoChanges(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	t.Setenv("SESH_MASTER_PASSWORD", "new-master-password-1234")

	app, stderr := rekeyTestApp("\n")
	if err := runRekey(app, []string{"--to=password"}, kc); err != nil {
		t.Fatalf("runRekey: %v", err)
	}
	if !strings.Contains(stderr.String(), "Rekey cancelled") {
		t.Errorf("stderr missing cancel message:\n%s", stderr.String())
	}
	if _, err := os.Stat(env.sidecarPath); err == nil {
		t.Errorf("sidecar should not exist after cancellation")
	}
	if _, err := os.Stat(env.dbPath + rekeyBackupSuffix); err == nil {
		t.Errorf("backup should not exist after cancellation")
	}
	if _, err := os.Stat(env.dbPath + rekeyDestSuffix); err == nil {
		t.Errorf(".new DB should not exist after cancellation")
	}
}

func TestRekey_RoundtripKeychainPasswordKeychain(t *testing.T) {
	env := setupRekeyEnv(t)
	kc1 := newKCMock(hexKey())
	entries := map[string]string{
		"sesh-password/password/github/alice": "hunter2",
		"sesh-totp/github":                    "JBSWY3DPEHPK3PXP",
	}
	populateKeychainStore(t, env, kc1, entries)

	t.Setenv("SESH_MASTER_PASSWORD", "intermediate-password-1234")
	app1, _ := rekeyTestApp("y\n")
	if err := runRekey(app1, []string{"--to=password"}, kc1); err != nil {
		t.Fatalf("first rekey: %v", err)
	}

	t.Setenv("SESH_KEY_SOURCE", "password")
	if err := os.Remove(env.dbPath + rekeyBackupSuffix); err != nil {
		t.Fatalf("clean step-1 backup: %v", err)
	}

	kc2 := &kcMock{}
	app2, _ := rekeyTestApp("y\n")
	if err := runRekey(app2, []string{"--to=keychain"}, kc2); err != nil {
		t.Fatalf("second rekey: %v", err)
	}

	services := []string{"sesh-password/password/github/alice", "sesh-totp/github"}
	got := readEntriesViaKeychain(t, env, kc2, services)
	for svc, want := range entries {
		if got[svc] != want {
			t.Errorf("entry %s after roundtrip = %q, want %q", svc, got[svc], want)
		}
	}
}
