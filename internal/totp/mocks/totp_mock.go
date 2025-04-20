package mocks

// MockProvider is a mock implementation of the totp.Provider interface
type MockProvider struct {
	GenerateFunc                 func(secret string) (string, error)
	GenerateConsecutiveCodesFunc func(secret string) (current string, next string, err error)
}

// Generate implements the totp.Provider interface
func (m *MockProvider) Generate(secret string) (string, error) {
	return m.GenerateFunc(secret)
}

// GenerateConsecutiveCodes implements the totp.Provider interface
func (m *MockProvider) GenerateConsecutiveCodes(secret string) (current string, next string, err error) {
	return m.GenerateConsecutiveCodesFunc(secret)
}
