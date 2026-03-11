package mocks

import "github.com/bashhack/sesh/internal/aws"

// MockProvider is a test double for aws.Provider.
type MockProvider struct {
	GetSessionTokenFunc   func(profile, serial string, code []byte) (aws.Credentials, error)
	GetFirstMFADeviceFunc func(profile string) (string, error)
}

// Ensure MockProvider implements the aws.Provider interface.
var _ aws.Provider = (*MockProvider)(nil)

// GetSessionToken returns temporary AWS credentials using MFA, or a zero value if the func is not set.
func (m *MockProvider) GetSessionToken(profile, serial string, code []byte) (aws.Credentials, error) {
	if m.GetSessionTokenFunc == nil {
		return aws.Credentials{}, nil
	}
	return m.GetSessionTokenFunc(profile, serial, code)
}

// GetFirstMFADevice returns the first MFA device for the given profile, or a zero value if the func is not set.
func (m *MockProvider) GetFirstMFADevice(profile string) (string, error) {
	if m.GetFirstMFADeviceFunc == nil {
		return "", nil
	}
	return m.GetFirstMFADeviceFunc(profile)
}
