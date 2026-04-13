package keychain

import (
	"os"
	"os/exec"
	"testing"
)

func TestNewDefaultProvider(t *testing.T) {
	provider := NewDefaultProvider()

	_, ok := provider.(*DefaultProvider)
	if !ok {
		t.Errorf("Expected *DefaultProvider, got %T", provider)
	}
}

func TestDefaultProviderImplementsProvider(t *testing.T) {
	var _ Provider = (*DefaultProvider)(nil)
}

func TestDefaultProviderGetSecret(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("test-secret"), nil
	}

	provider := NewDefaultProvider()
	secretBytes, err := provider.GetSecret("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if string(secretBytes) != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got '%s'", string(secretBytes))
	}
}

func TestDefaultProviderGetMFASerialBytes(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("test-serial"), nil
	}

	provider := NewDefaultProvider()
	serialBytes, err := provider.GetMFASerialBytes("testuser", "")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if string(serialBytes) != "test-serial" {
		t.Errorf("Expected serial 'test-serial', got '%s'", string(serialBytes))
	}
}

func TestDefaultProviderSetSecret(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

	execSecretInput = func(cmd *exec.Cmd, input []byte) error {
		return nil
	}

	provider := NewDefaultProvider()
	err := provider.SetSecret("testuser", "test-service", []byte("test-secret"))

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDefaultProviderGetSecretString(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("test-secret-string"), nil
	}

	provider := NewDefaultProvider()
	secret, err := provider.GetSecretString("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if secret != "test-secret-string" {
		t.Errorf("Expected secret 'test-secret-string', got '%s'", secret)
	}
}

func TestDefaultProviderSetSecretString(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

	execSecretInput = func(cmd *exec.Cmd, input []byte) error {
		return nil
	}

	provider := NewDefaultProvider()
	err := provider.SetSecretString("testuser", "test-service", "test-secret-string")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDefaultProviderListEntries(t *testing.T) {
	originalFunc := loadEntryMetadataImpl
	defer func() { loadEntryMetadataImpl = originalFunc }()

	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		if servicePrefix == "test-service" {
			return []KeychainEntryMeta{
				{
					Service:     "test-service-1",
					Account:     "testuser",
					Description: "Test Entry 1",
					ServiceType: "test",
				},
				{
					Service:     "test-service-2",
					Account:     "testuser",
					Description: "Test Entry 2",
					ServiceType: "test",
				},
			}, nil
		}
		return []KeychainEntryMeta{}, nil
	}

	provider := NewDefaultProvider()
	entries, err := provider.ListEntries("test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	if entries[0].Service != "test-service-1" {
		t.Errorf("Expected first entry service 'test-service-1', got '%s'", entries[0].Service)
	}
}

// TestDefaultProviderDeleteEntry uses subprocess pattern because
// DeleteEntry calls execCommand + cmd.Run() directly.
func TestDefaultProviderDeleteEntry(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
		return cmd
	}

	provider := NewDefaultProvider()
	err := provider.DeleteEntry("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDefaultProviderSetDescription(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	// Mock execCommand so LoadAllEntryMetadata doesn't hit the real keychain
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("echo", "")
	}

	var savedMeta []KeychainEntryMeta
	originalSaveFunc := saveEntryMetadataImpl
	defer func() { saveEntryMetadataImpl = originalSaveFunc }()
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		savedMeta = meta
		return nil
	}

	provider := NewDefaultProvider()
	err := provider.SetDescription("test-service", "testuser", "Test Description")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(savedMeta) != 1 {
		t.Errorf("Expected 1 saved metadata entry, got %d", len(savedMeta))
	}
}
