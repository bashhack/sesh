package main

import (
	"bytes"
	"errors"
	"fmt"
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
	store map[string][]byte
	mu    sync.Mutex
}

// kcMockKey routes mock entries by both account and service so the mock
// can't accidentally satisfy a lookup against the wrong (account, service)
// pair.
func kcMockKey(account, service string) string {
	return account + "|" + service
}

// newKCMock builds a keychain mock. If stored is non-nil, it pre-populates
// the encryption key under the canonical (current_user, encKeyService)
// pair so KeychainSource lookups find it.
func newKCMock(stored []byte) *kcMock {
	m := &kcMock{store: make(map[string][]byte)}
	if stored != nil {
		u, err := user.Current()
		if err != nil {
			panic(fmt.Errorf("user.Current: %w", err))
		}
		m.store[kcMockKey(u.Username, encKeyService)] = append([]byte{}, stored...)
	}
	return m
}

func (m *kcMock) GetSecret(account, service string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.store[kcMockKey(account, service)]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, v...), nil
}

func (m *kcMock) SetSecret(account, service string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[kcMockKey(account, service)] = append([]byte{}, secret...)
	return nil
}

func (m *kcMock) GetSecretString(_, _ string) (string, error)            { return "", nil }
func (m *kcMock) SetSecretString(_, _, _ string) error                   { return nil }
func (m *kcMock) GetMFASerialBytes(_, _ string) ([]byte, error)          { return nil, keychain.ErrNotFound }
func (m *kcMock) ListEntries(_ string) ([]keychain.KeychainEntry, error) { return nil, nil }
func (m *kcMock) SetDescription(_, _, _ string) error                    { return nil }
func (m *kcMock) DeleteEntry(account, service string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, kcMockKey(account, service))
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
	ks := resolvePasswordPrompt().newSource(env.dataDir)
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
	ks := resolvePasswordPrompt().newSource(env.dataDir)
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

func TestRekey_RefusesKeychainToKeychain(t *testing.T) {
	// password → password is the in-place rotation case and is handled
	// by runRotateMasterPassword; see TestRotate_*. The keychain → keychain
	// case isn't supported yet (Flavor B in docs/KEY_ROTATION_ROADMAP.md)
	// and should still hit the "already using" guard.
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "keychain")
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=keychain"}, kc)
	if err == nil || !strings.Contains(err.Error(), "already using") {
		t.Fatalf("expected already-using error for keychain→keychain, got %v", err)
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

func TestRekey_RefusesIfBackupPathExists(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	if err := os.WriteFile(env.dbPath+rekeyBackupSuffix, []byte("stale"), 0o600); err != nil {
		t.Fatalf("pre-create backup: %v", err)
	}

	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=password"}, kc)
	if err == nil || !strings.Contains(err.Error(), "backup path") {
		t.Fatalf("expected backup-path-exists error, got %v", err)
	}

	if _, err := os.Stat(env.sidecarPath); err == nil {
		t.Errorf("sidecar should not exist after refusal")
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

func TestRekey_RefusesIfTargetKeychainEntryExists(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "test-password-1234")
	populatePasswordStore(t, env, map[string]string{
		"sesh-password/password/github/alice": "hunter2",
	})

	kc := newKCMock(hexKey())

	app, _ := rekeyTestApp("")
	err := runRekey(app, []string{"--to=keychain"}, kc)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected target-keychain-exists error, got %v", err)
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

	kc := newKCMock(nil)

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
	storedKey, err := kc.GetSecret(env.account, encKeyService)
	if err != nil {
		t.Errorf("new keychain entry not stored: %v", err)
	} else if len(storedKey) != 64 {
		t.Errorf("new keychain entry hex length = %d, want 64", len(storedKey))
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

	mps := resolvePasswordPrompt().newSource(env.dataDir)
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

	got := readEntriesViaKeychain(t, env, kc, []string{"sesh-password/password/github/alice"})
	if got["sesh-password/password/github/alice"] != "hunter2" {
		t.Errorf("original entry corrupted after cancellation, got %q want %q", got["sesh-password/password/github/alice"], "hunter2")
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

	kc2 := newKCMock(nil)
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

func TestAppendErr_NilPrimary(t *testing.T) {
	got := appendErr(nil, "label", errors.New("secondary"))
	if got == nil || got.Error() != "label: secondary" {
		t.Errorf("got %v, want 'label: secondary'", got)
	}
}

func TestAppendErr_WithPrimary(t *testing.T) {
	primary := errors.New("primary failure")
	got := appendErr(primary, "rollback step", errors.New("cleanup failed"))
	if !strings.Contains(got.Error(), "primary failure") {
		t.Errorf("primary not preserved in %q", got.Error())
	}
	if !strings.Contains(got.Error(), "rollback step also failed: cleanup failed") {
		t.Errorf("secondary not labelled correctly in %q", got.Error())
	}
	if !errors.Is(got, primary) {
		t.Errorf("appended error should still wrap primary for errors.Is")
	}
}

func TestCleanupNewKeyState_PasswordRemovesSidecar(t *testing.T) {
	dir := t.TempDir()
	sidecar := filepath.Join(dir, "passwords.key")
	if err := os.WriteFile(sidecar, []byte("anything"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupNewKeyState("password", dir, nil); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Errorf("sidecar should be removed, stat err = %v", err)
	}
}

func TestCleanupNewKeyState_PasswordNoSidecarIsOK(t *testing.T) {
	if err := cleanupNewKeyState("password", t.TempDir(), nil); err != nil {
		t.Errorf("cleanup of missing sidecar should succeed, got %v", err)
	}
}

func TestCleanupNewKeyState_KeychainDeletesEntry(t *testing.T) {
	kc := newKCMock(hexKey())
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanupNewKeyState("keychain", "", kc); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := kc.GetSecret(u.Username, encKeyService); !errors.Is(err, keychain.ErrNotFound) {
		t.Errorf("keychain entry should be deleted, got %v", err)
	}
}

func TestCleanupNewKeyState_UnknownTarget(t *testing.T) {
	if err := cleanupNewKeyState("banana", "", nil); err == nil {
		t.Error("expected error for unknown target")
	}
}

func TestCheckTargetKeyStateClean_UnknownTarget(t *testing.T) {
	if err := checkTargetKeyStateClean("banana", "", nil); err == nil {
		t.Error("expected error for unknown target")
	}
}

func TestNewKeySourceByName_UnknownReturnsError(t *testing.T) {
	if _, err := newKeySourceByName("banana", "/tmp", nil); err == nil {
		t.Error("expected error for unknown source")
	}
}

func TestInitializeTargetKeySource_UnknownReturnsError(t *testing.T) {
	if err := initializeTargetKeySource(nil, "banana"); err == nil {
		t.Error("expected error for unknown target")
	}
}

func TestUnusedKeyStateNote(t *testing.T) {
	dir := t.TempDir()
	if got := unusedKeyStateNote("banana", dir); got != "" {
		t.Errorf("unknown source should yield empty note, got %q", got)
	}
	if got := unusedKeyStateNote("keychain", dir); !strings.Contains(got, encKeyService) {
		t.Errorf("keychain note should mention service name, got %q", got)
	}
	if got := unusedKeyStateNote("password", dir); got != "" {
		t.Errorf("password note with no sidecar should be empty, got %q", got)
	}
	sidecar := filepath.Join(dir, "passwords.key")
	if err := os.WriteFile(sidecar, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := unusedKeyStateNote("password", dir); !strings.Contains(got, sidecar) {
		t.Errorf("password note with sidecar should mention path, got %q", got)
	}
}

func TestPromptYesNo(t *testing.T) {
	cases := map[string]bool{
		"y\n":     true,
		"Y\n":     true,
		"yes\n":   false,
		"n\n":     false,
		"\n":      false,
		"":        false,
		"  y  \n": true,
	}
	for input, want := range cases {
		t.Run(strings.TrimSpace(input), func(t *testing.T) {
			got, err := promptYesNo(strings.NewReader(input), new(bytes.Buffer), "")
			if err != nil {
				t.Fatalf("promptYesNo(%q): %v", input, err)
			}
			if got != want {
				t.Errorf("promptYesNo(%q) = %v, want %v", input, got, want)
			}
		})
	}
}

// sequencedPrompt returns each password in order, erroring once the list
// is exhausted. Used by rotation tests where source unlock and target
// create+confirm need different inputs from the same prompt callback.
func sequencedPrompt(passwords ...string) database.PasswordPromptFunc {
	i := 0
	return func(_ string) ([]byte, error) {
		if i >= len(passwords) {
			return nil, fmt.Errorf("test prompt exhausted at call %d", i+1)
		}
		pw := []byte(passwords[i])
		i++
		return pw, nil
	}
}

// rotateTestCfg builds a non-interactive prompt config from a sequenced
// list of passwords. Non-interactive disables the retry loop, which is
// what we want in tests — a wrong password should fail fast, not consume
// extra entries from the sequence.
func rotateTestCfg(passwords ...string) passwordPromptConfig {
	return passwordPromptConfig{prompt: sequencedPrompt(passwords...), interactive: false}
}

func TestRotate_PasswordChangesPassword(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	entries := map[string]string{
		"sesh-password/password/github/alice": "hunter2",
		"sesh-password/api_key/stripe/admin":  "sk_test_xyz",
	}
	populatePasswordStore(t, env, entries)
	t.Setenv("SESH_MASTER_PASSWORD", "")

	app, stderr := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("runRotateMasterPassword: %v\nstderr:\n%s", err, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Rotated 2 entries") {
		t.Errorf("stderr missing rotation summary:\n%s", stderr.String())
	}
	if _, err := os.Stat(env.dbPath + rotateBackupSuffix); err != nil {
		t.Errorf("DB backup missing at .pre-rotate: %v", err)
	}
	if _, err := os.Stat(env.sidecarPath + rotateBackupSuffix); err != nil {
		t.Errorf("sidecar backup missing at .pre-rotate: %v", err)
	}

	// New password unlocks the rotated DB.
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	services := []string{"sesh-password/password/github/alice", "sesh-password/api_key/stripe/admin"}
	got := readEntriesViaPassword(t, env, services)
	for svc, want := range entries {
		if got[svc] != want {
			t.Errorf("entry %s under new password = %q, want %q", svc, got[svc], want)
		}
	}
}

func TestRotate_PreservesPerEntryFreshness(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{
		"sesh-password/password/github/alice": "same-secret",
		"sesh-password/password/github/bob":   "same-secret",
	})

	beforeBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	afterBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforeBlob, afterBlob) {
		t.Fatal("rotated DB byte-for-byte identical to original — re-encryption did not run")
	}

	// Sidecar salt must also have changed (proves new KDF derivation, not
	// just a re-encryption with the same derived key).
	beforeSidecar, err := os.ReadFile(env.sidecarPath + rotateBackupSuffix)
	if err != nil {
		t.Fatalf("read backup sidecar: %v", err)
	}
	afterSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatalf("read rotated sidecar: %v", err)
	}
	if bytes.Equal(beforeSidecar, afterSidecar) {
		t.Fatal("rotated sidecar identical to backup — salt was not regenerated")
	}
}

func TestRotate_PasswordRefusesIfNewSidecarExists(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	if err := os.WriteFile(env.sidecarPath+rekeyDestSuffix, []byte("stale"), 0o600); err != nil {
		t.Fatalf("pre-create staging sidecar: %v", err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "exists from a prior rotation") {
		t.Fatalf("expected refusal because staging sidecar exists, got %v", err)
	}
}

func TestRotate_PasswordRefusesIfBackupSidecarExists(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	if err := os.WriteFile(env.sidecarPath+rotateBackupSuffix, []byte("stale"), 0o600); err != nil {
		t.Fatalf("pre-create backup sidecar: %v", err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "exists from a prior rotation") {
		t.Fatalf("expected refusal because backup sidecar exists, got %v", err)
	}
}

func TestRotate_RemovesStagingLockOnSuccess(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	stagingLock := env.sidecarPath + rekeyDestSuffix + ".lock"
	if _, err := os.Stat(stagingLock); !os.IsNotExist(err) {
		t.Errorf("staging sidecar lock %s should be removed after successful rotation, got stat err %v", stagingLock, err)
	}
}

func TestRotate_RemovesStagingLockOnConfirmMismatch(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	// Mismatched confirm fires inside initialize(), AFTER the staging
	// lock file has been created via O_CREATE in initializeLocked. The
	// lock file should be cleaned up by the rollback path.
	cfg := rotateTestCfg("old-pw-1234", "new-pw-aaaaaa", "new-pw-bbbbbb")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "passwords do not match") {
		t.Fatalf("expected passwords-do-not-match error, got %v", err)
	}
	stagingLock := env.sidecarPath + rekeyDestSuffix + ".lock"
	if _, err := os.Stat(stagingLock); !os.IsNotExist(err) {
		t.Errorf("staging sidecar lock %s should be removed after rollback, got stat err %v", stagingLock, err)
	}
}

func TestRotate_RemovesStagingLockOnCancel(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	t.Setenv("SESH_MASTER_PASSWORD", "")
	// Cancel before the destination source is constructed at all — the
	// staging lock should never be created. Regression guard against a
	// future change that moves destKS construction earlier.
	app, _ := rekeyTestApp("n\n")
	cfg := rotateTestCfg("old-pw-1234")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("cancelled rotation should not error: %v", err)
	}
	stagingLock := env.sidecarPath + rekeyDestSuffix + ".lock"
	if _, err := os.Stat(stagingLock); !os.IsNotExist(err) {
		t.Errorf("staging sidecar lock %s should not exist after cancel, got stat err %v", stagingLock, err)
	}
}

func TestRotate_RefusesIfBackendNotSqlite(t *testing.T) {
	t.Setenv("SESH_BACKEND", "")
	app, _ := rekeyTestApp("")
	err := runRotateMasterPassword(app, rotateTestCfg("any-pw-1234"))
	if err == nil || !strings.Contains(err.Error(), "SESH_BACKEND=sqlite") {
		t.Fatalf("expected SESH_BACKEND error, got %v", err)
	}
}

func TestRotate_RefusesIfDatabaseMissing(t *testing.T) {
	setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	app, _ := rekeyTestApp("")
	err := runRotateMasterPassword(app, rotateTestCfg("any-pw-1234"))
	if err == nil || !strings.Contains(err.Error(), "no database to rotate") {
		t.Fatalf("expected no-database error, got %v", err)
	}
}

func TestRotate_RefusesIfSidecarMissing(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	// Create a DB file directly (bypassing sesh) so the DB-stat check passes
	// but the sidecar doesn't exist — the "is SESH_KEY_SOURCE=password
	// actually in use?" failure mode.
	if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.dbPath, []byte("not a real db"), 0o600); err != nil {
		t.Fatalf("write fake db: %v", err)
	}
	app, _ := rekeyTestApp("")
	err := runRotateMasterPassword(app, rotateTestCfg("any-pw-1234"))
	if err == nil || !strings.Contains(err.Error(), "no sidecar to rotate") {
		t.Fatalf("expected no-sidecar error, got %v", err)
	}
}

func TestRotate_PasswordRefusesIfNewDBExists(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	if err := os.WriteFile(env.dbPath+rekeyDestSuffix, []byte("stale"), 0o600); err != nil {
		t.Fatalf("pre-create staging DB: %v", err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "exists from a prior rotation") {
		t.Fatalf("expected refusal because staging DB exists, got %v", err)
	}
}

func TestRotate_PasswordRefusesIfBackupDBExists(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})

	if err := os.WriteFile(env.dbPath+rotateBackupSuffix, []byte("stale"), 0o600); err != nil {
		t.Fatalf("pre-create backup DB: %v", err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	cfg := rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")
	err := runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "exists from a prior rotation") {
		t.Fatalf("expected refusal because backup DB exists, got %v", err)
	}
}

func TestRotate_WrongSourcePassword(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "right-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})
	beforeSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, _ := rekeyTestApp("y\n")
	// Wrong source password — fails at unlock before any prompt for a new
	// password. cfg only provides the wrong one; if we accidentally drained
	// further from the sequence, the "test prompt exhausted" error would
	// surface and tell us the test no longer pins the right behavior.
	cfg := rotateTestCfg("wrong-pw-1234")
	err = runRotateMasterPassword(app, cfg)
	if err == nil || !strings.Contains(err.Error(), "unlock current sidecar") {
		t.Fatalf("expected unlock error for wrong source password, got %v", err)
	}
	if !strings.Contains(err.Error(), "wrong master password") {
		t.Errorf("error %q should bubble up the underlying wrong-password message", err.Error())
	}
	// Canonical sidecar must be untouched. No write path is reachable
	// before the failed unlock, so this is a regression guard against
	// future refactors that move sidecar writes earlier in the flow.
	afterSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeSidecar, afterSidecar) {
		t.Error("canonical sidecar modified after wrong-password failure")
	}
}

func TestRotate_PasswordCancelledLeavesNoChanges(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})
	beforeBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "")
	// Pass "n" to the y/N prompt to abort. Source unlock still happens (one
	// password drained from the sequence); target Create+Confirm is never
	// reached, so only the source password is consumed.
	app, _ := rekeyTestApp("n\n")
	cfg := rotateTestCfg("old-pw-1234")
	if err := runRotateMasterPassword(app, cfg); err != nil {
		t.Fatalf("cancelled rotation should not error: %v", err)
	}

	afterBlob, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeBlob, afterBlob) {
		t.Error("DB modified after cancelled rotation")
	}
	afterSidecar, err := os.ReadFile(env.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeSidecar, afterSidecar) {
		t.Error("canonical sidecar modified after cancelled rotation")
	}
	for _, p := range []string{
		env.dbPath + rekeyDestSuffix,
		env.dbPath + rotateBackupSuffix,
		env.sidecarPath + rekeyDestSuffix,
		env.sidecarPath + rotateBackupSuffix,
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("staging/backup file %s should not exist after cancel: %v", p, err)
		}
	}
}

func TestCurrentKeySourceName(t *testing.T) {
	t.Setenv("SESH_KEY_SOURCE", "")
	if got := currentKeySourceName(); got != "keychain" {
		t.Errorf("empty env should default to keychain, got %q", got)
	}
	t.Setenv("SESH_KEY_SOURCE", "password")
	if got := currentKeySourceName(); got != "password" {
		t.Errorf("explicit password not preserved, got %q", got)
	}
}
