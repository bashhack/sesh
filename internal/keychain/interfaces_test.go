package keychain

import (
	"os"
	"os/exec"
	"testing"
)

func TestNewDefaultProvider(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		// Return a no-op command for any exec calls during initialization
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
		return cmd
	}

	provider := NewDefaultProvider()

	_, ok := provider.(*DefaultProvider)
	if !ok {
		t.Errorf("Expected *DefaultProvider, got %T", provider)
	}
}
func TestDefaultProviderImplementsProvider(t *testing.T) {
	// Compile-time check that DefaultProvider implements Provider
	var _ Provider = (*DefaultProvider)(nil)
}

func TestDefaultProviderGetSecret(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=test-secret")
		}
		return cmd
	}

	provider := NewDefaultProvider()
	secretBytes, err := provider.GetSecret("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	secretStr := string(secretBytes)
	expectedStr := "test-secret"
	if secretStr != expectedStr {
		t.Errorf("Expected secret '%s', got '%s'", expectedStr, secretStr)
	}
}

func TestDefaultProviderGetMFASerialBytes(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=test-serial")
		}
		return cmd
	}

	provider := NewDefaultProvider()
	serialBytes, err := provider.GetMFASerialBytes("testuser")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	serial := string(serialBytes)
	if serial != "test-serial" {
		t.Errorf("Expected serial 'test-serial', got '%s'", serial)
	}
}

func TestDefaultProviderSetSecret(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" && len(args) > 0 && (args[0] == "add-generic-password" || args[0] == "-i") {
			// Don't set MOCK_ERROR for successful addition or interactive mode
		} else {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}
		return cmd
	}

	provider := NewDefaultProvider()
	err := provider.SetSecret("testuser", "test-service", []byte("test-secret"))

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDefaultProviderGetSecretString(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=test-secret-string")
		}
		return cmd
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
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" && len(args) > 0 && (args[0] == "add-generic-password" || args[0] == "-i") {
			// Don't set MOCK_ERROR for successful addition or interactive mode
		} else {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}
		return cmd
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

func TestDefaultProviderDeleteEntry(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" && len(args) > 0 && args[0] == "delete-generic-password" {
			// Don't set MOCK_ERROR for successful deletion
		} else {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}
		return cmd
	}

	provider := NewDefaultProvider()
	err := provider.DeleteEntry("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDefaultProviderStoreEntryMetadata(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		// Return error for security commands to simulate no existing metadata
		if command == "security" {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}
		return cmd
	}

	originalSaveFunc := saveEntryMetadataImpl
	defer func() { saveEntryMetadataImpl = originalSaveFunc }()

	var savedMeta []KeychainEntryMeta
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		savedMeta = meta
		return nil
	}

	originalLoadFunc := loadEntryMetadataImpl
	defer func() { loadEntryMetadataImpl = originalLoadFunc }()

	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}

	provider := NewDefaultProvider()
	err := provider.StoreEntryMetadata("test-prefix", "test-service", "testuser", "Test Description")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(savedMeta) != 1 {
		t.Errorf("Expected 1 saved metadata entry, got %d", len(savedMeta))
	}
}

func TestDefaultProviderLoadEntryMetadata(t *testing.T) {
	originalFunc := loadEntryMetadataImpl
	defer func() { loadEntryMetadataImpl = originalFunc }()

	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		if servicePrefix == "test-prefix" {
			return []KeychainEntryMeta{
				{
					Service:     "test-service",
					Account:     "testuser",
					Description: "Test Description",
					ServiceType: "test-prefix",
				},
			}, nil
		}
		return []KeychainEntryMeta{}, nil
	}

	provider := NewDefaultProvider()
	entries, err := provider.LoadEntryMetadata("test-prefix")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	if entries[0].Service != "test-service" {
		t.Errorf("Expected service 'test-service', got '%s'", entries[0].Service)
	}
}

func TestDefaultProviderRemoveEntryMetadata(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

		// Mock the security find-generic-password call for metadata
		if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			// Return empty to simulate no existing metadata
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=")
		}

		return cmd
	}

	originalSaveFunc := saveEntryMetadataImpl
	defer func() { saveEntryMetadataImpl = originalSaveFunc }()

	var savedMeta []KeychainEntryMeta
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		savedMeta = meta
		return nil
	}

	originalLoadFunc := loadEntryMetadataImpl
	defer func() { loadEntryMetadataImpl = originalLoadFunc }()

	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{
			{
				Service:     "test-service",
				Account:     "testuser",
				Description: "Test Description",
				ServiceType: "test-prefix",
			},
		}, nil
	}

	provider := NewDefaultProvider()
	err := provider.RemoveEntryMetadata("test-prefix", "test-service", "testuser")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(savedMeta) != 0 {
		t.Errorf("Expected 0 saved metadata entries after removal, got %d", len(savedMeta))
	}
}
