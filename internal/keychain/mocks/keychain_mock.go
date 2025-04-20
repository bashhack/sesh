package mocks

// MockProvider is a mock implementation of the keychain.Provider interface
type MockProvider struct {
	GetSecretFunc    func(account, service string) (string, error)
	GetMFASerialFunc func(account string) (string, error)
}

// GetSecret implements the keychain.Provider interface
func (m *MockProvider) GetSecret(account, service string) (string, error) {
	return m.GetSecretFunc(account, service)
}

// GetMFASerial implements the keychain.Provider interface
func (m *MockProvider) GetMFASerial(account string) (string, error) {
	return m.GetMFASerialFunc(account)
}
