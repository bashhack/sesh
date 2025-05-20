package mocks

import "github.com/bashhack/sesh/internal/aws"

// MockProvider is a mock implementation of the aws.Provider interface
type MockProvider struct {
	GetSessionTokenFunc   func(profile, serial string, code []byte) (aws.Credentials, error)
	GetFirstMFADeviceFunc func(profile string) (string, error)
}

// Ensure MockProvider implements the aws.Provider interface
var _ aws.Provider = (*MockProvider)(nil)

// GetSessionToken implements the aws.Provider interface
func (m *MockProvider) GetSessionToken(profile, serial string, code []byte) (aws.Credentials, error) {
	return m.GetSessionTokenFunc(profile, serial, code)
}

// GetFirstMFADevice implements the aws.Provider interface
func (m *MockProvider) GetFirstMFADevice(profile string) (string, error) {
	return m.GetFirstMFADeviceFunc(profile)
}
