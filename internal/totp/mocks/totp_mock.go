// Package mocks provides test doubles for the TOTP package interfaces.
package mocks

import (
	"time"

	"github.com/bashhack/sesh/internal/totp"
)

// MockProvider is a test double for totp.Provider.
type MockProvider struct {
	GenerateFunc                                func(secret string) (string, error)
	GenerateConsecutiveCodesFunc                func(secret string) (current, next string, err error)
	GenerateConsecutiveCodesForTimeFunc         func(secret string, baseTime time.Time) (current, next string, err error)
	GenerateForTimeFunc                         func(secret string, t time.Time) (string, error)
	GenerateSecureFunc                          func(secret string) (string, error)
	GenerateForTimeSecureFunc                   func(secret string, t time.Time) (string, error)
	GenerateBytesFunc                           func(secret []byte) (string, error)
	GenerateConsecutiveCodesBytesFunc           func(secret []byte) (current, next string, err error)
	GenerateConsecutiveCodesBytesWithParamsFunc func(secret []byte, params totp.Params) (current, next string, err error)
	GenerateConsecutiveCodesForTimeBytesFunc    func(secret []byte, baseTime time.Time) (current, next string, err error)
	GenerateForTimeBytesFunc                    func(secret []byte, t time.Time) (string, error)
}

// Generate returns a TOTP code, or a zero value if GenerateFunc is not set.
func (m *MockProvider) Generate(secret string) (string, error) {
	if m.GenerateFunc == nil {
		return "", nil
	}
	return m.GenerateFunc(secret)
}

// GenerateConsecutiveCodes returns consecutive TOTP codes, or zero values if the func is not set.
func (m *MockProvider) GenerateConsecutiveCodes(secret string) (current, next string, err error) {
	if m.GenerateConsecutiveCodesFunc == nil {
		return "", "", nil
	}
	return m.GenerateConsecutiveCodesFunc(secret)
}

// GenerateForTime returns a TOTP code for a specific time, or a zero value if the func is not set.
func (m *MockProvider) GenerateForTime(secret string, t time.Time) (string, error) {
	if m.GenerateForTimeFunc == nil {
		return "", nil
	}
	return m.GenerateForTimeFunc(secret, t)
}

// GenerateSecure returns a TOTP code with best-effort zeroing, or a zero value if the func is not set.
func (m *MockProvider) GenerateSecure(secret string) (string, error) {
	if m.GenerateSecureFunc == nil {
		return "", nil
	}
	return m.GenerateSecureFunc(secret)
}

// GenerateForTimeSecure returns a time-specific TOTP code with best-effort zeroing, or a zero value if the func is not set.
func (m *MockProvider) GenerateForTimeSecure(secret string, t time.Time) (string, error) {
	if m.GenerateForTimeSecureFunc == nil {
		return "", nil
	}
	return m.GenerateForTimeSecureFunc(secret, t)
}

// GenerateBytes returns a TOTP code from a byte slice, or a zero value if the func is not set.
func (m *MockProvider) GenerateBytes(secret []byte) (string, error) {
	if m.GenerateBytesFunc == nil {
		return "", nil
	}
	return m.GenerateBytesFunc(secret)
}

// GenerateConsecutiveCodesBytes returns consecutive TOTP codes from a byte slice, or zero values if the func is not set.
func (m *MockProvider) GenerateConsecutiveCodesBytes(secret []byte) (current, next string, err error) {
	if m.GenerateConsecutiveCodesBytesFunc == nil {
		return "", "", nil
	}
	return m.GenerateConsecutiveCodesBytesFunc(secret)
}

// GenerateConsecutiveCodesForTime returns consecutive TOTP codes for a given base time, or zero values if the func is not set.
func (m *MockProvider) GenerateConsecutiveCodesForTime(secret string, baseTime time.Time) (current, next string, err error) {
	if m.GenerateConsecutiveCodesForTimeFunc == nil {
		return "", "", nil
	}
	return m.GenerateConsecutiveCodesForTimeFunc(secret, baseTime)
}

// GenerateConsecutiveCodesBytesWithParams returns consecutive TOTP codes using custom params, or delegates to GenerateConsecutiveCodesBytes if the func is not set.
func (m *MockProvider) GenerateConsecutiveCodesBytesWithParams(secret []byte, params totp.Params) (current, next string, err error) {
	if m.GenerateConsecutiveCodesBytesWithParamsFunc == nil {
		return m.GenerateConsecutiveCodesBytes(secret)
	}
	return m.GenerateConsecutiveCodesBytesWithParamsFunc(secret, params)
}

// GenerateConsecutiveCodesForTimeBytes returns consecutive TOTP codes from a byte slice for a given base time, or zero values if the func is not set.
func (m *MockProvider) GenerateConsecutiveCodesForTimeBytes(secret []byte, baseTime time.Time) (current, next string, err error) {
	if m.GenerateConsecutiveCodesForTimeBytesFunc == nil {
		return "", "", nil
	}
	return m.GenerateConsecutiveCodesForTimeBytesFunc(secret, baseTime)
}

// GenerateForTimeBytes returns a time-specific TOTP code from a byte slice, or a zero value if the func is not set.
func (m *MockProvider) GenerateForTimeBytes(secret []byte, t time.Time) (string, error) {
	if m.GenerateForTimeBytesFunc == nil {
		return "", nil
	}
	return m.GenerateForTimeBytesFunc(secret, t)
}
