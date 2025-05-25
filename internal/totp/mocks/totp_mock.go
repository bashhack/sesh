package mocks

import "time"

// MockProvider is a mock implementation of the totp.Provider interface
type MockProvider struct {
	GenerateFunc                      func(secret string) (string, error)
	GenerateConsecutiveCodesFunc      func(secret string) (current string, next string, err error)
	GenerateForTimeFunc               func(secret string, t time.Time) (string, error)
	GenerateSecureFunc                func(secret string) (string, error)
	GenerateForTimeSecureFunc         func(secret string, t time.Time) (string, error)
	GenerateBytesFunc                 func(secret []byte) (string, error)
	GenerateConsecutiveCodesBytesFunc func(secret []byte) (current string, next string, err error)
	GenerateForTimeBytesFunc          func(secret []byte, t time.Time) (string, error)
}

// Generate implements the totp.Provider interface
func (m *MockProvider) Generate(secret string) (string, error) {
	if m.GenerateFunc == nil {
		return "", nil
	}
	return m.GenerateFunc(secret)
}

// GenerateConsecutiveCodes implements the totp.Provider interface
func (m *MockProvider) GenerateConsecutiveCodes(secret string) (current string, next string, err error) {
	if m.GenerateConsecutiveCodesFunc == nil {
		return "", "", nil
	}
	return m.GenerateConsecutiveCodesFunc(secret)
}

// GenerateForTime implements the totp.Provider interface
func (m *MockProvider) GenerateForTime(secret string, t time.Time) (string, error) {
	if m.GenerateForTimeFunc == nil {
		return "", nil
	}
	return m.GenerateForTimeFunc(secret, t)
}

// GenerateSecure implements the totp.Provider interface
func (m *MockProvider) GenerateSecure(secret string) (string, error) {
	if m.GenerateSecureFunc == nil {
		return "", nil
	}
	return m.GenerateSecureFunc(secret)
}

// GenerateForTimeSecure implements the totp.Provider interface
func (m *MockProvider) GenerateForTimeSecure(secret string, t time.Time) (string, error) {
	if m.GenerateForTimeSecureFunc == nil {
		return "", nil
	}
	return m.GenerateForTimeSecureFunc(secret, t)
}

// GenerateBytes implements the totp.Provider interface
func (m *MockProvider) GenerateBytes(secret []byte) (string, error) {
	if m.GenerateBytesFunc == nil {
		return "", nil
	}
	return m.GenerateBytesFunc(secret)
}

// GenerateConsecutiveCodesBytes implements the totp.Provider interface
func (m *MockProvider) GenerateConsecutiveCodesBytes(secret []byte) (current string, next string, err error) {
	if m.GenerateConsecutiveCodesBytesFunc == nil {
		return "", "", nil
	}
	return m.GenerateConsecutiveCodesBytesFunc(secret)
}

// GenerateForTimeBytes implements the totp.Provider interface
func (m *MockProvider) GenerateForTimeBytes(secret []byte, t time.Time) (string, error) {
	if m.GenerateForTimeBytesFunc == nil {
		return "", nil
	}
	return m.GenerateForTimeBytesFunc(secret, t)
}
