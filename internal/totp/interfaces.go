package totp

import "time"

// Provider defines the interface for TOTP operations.
type Provider interface {
	// Generate returns a 6-digit TOTP code for the current time.
	Generate(secret string) (string, error)

	// GenerateConsecutiveCodes returns the current and next 30-second window TOTP codes.
	GenerateConsecutiveCodes(secret string) (current, next string, err error)

	// GenerateConsecutiveCodesForTime returns TOTP codes for a given base time and the next 30-second window.
	GenerateConsecutiveCodesForTime(secret string, baseTime time.Time) (current, next string, err error)

	// GenerateForTime returns a TOTP code for a specific point in time.
	GenerateForTime(secret string, t time.Time) (string, error)

	// GenerateSecure generates a TOTP code and zeroes the secret's byte representation on return.
	GenerateSecure(secret string) (string, error)

	// GenerateForTimeSecure generates a time-specific TOTP code and zeroes the secret's byte representation on return.
	GenerateForTimeSecure(secret string, t time.Time) (string, error)

	// GenerateBytes generates a TOTP code from a byte slice, zeroing the copy after use.
	GenerateBytes(secret []byte) (string, error)

	// GenerateConsecutiveCodesBytes generates consecutive TOTP codes from a byte slice, zeroing the copy after use.
	GenerateConsecutiveCodesBytes(secret []byte) (current, next string, err error)

	// GenerateConsecutiveCodesBytesWithParams generates consecutive codes using non-standard TOTP parameters.
	GenerateConsecutiveCodesBytesWithParams(secret []byte, params Params) (current, next string, err error)

	// GenerateConsecutiveCodesForTimeBytes generates consecutive TOTP codes from a byte slice for a given base time, zeroing the copy after use.
	GenerateConsecutiveCodesForTimeBytes(secret []byte, baseTime time.Time) (current, next string, err error)

	// GenerateForTimeBytes generates a time-specific TOTP code from a byte slice, zeroing the copy after use.
	GenerateForTimeBytes(secret []byte, t time.Time) (string, error)
}

// DefaultProvider delegates to the package-level functions using the pquerna/otp library.
type DefaultProvider struct{}

var _ Provider = (*DefaultProvider)(nil)

// Generate returns a 6-digit TOTP code for the current time.
func (p *DefaultProvider) Generate(secret string) (string, error) {
	return Generate(secret)
}

// GenerateConsecutiveCodes returns the current and next 30-second window TOTP codes.
func (p *DefaultProvider) GenerateConsecutiveCodes(secret string) (current, next string, err error) {
	return GenerateConsecutiveCodes(secret)
}

// GenerateConsecutiveCodesForTime returns TOTP codes for a given base time and the next 30-second window.
func (p *DefaultProvider) GenerateConsecutiveCodesForTime(secret string, baseTime time.Time) (current, next string, err error) {
	return GenerateConsecutiveCodesForTime(secret, baseTime)
}

// GenerateForTime returns a TOTP code for a specific point in time.
func (p *DefaultProvider) GenerateForTime(secret string, t time.Time) (string, error) {
	return GenerateForTime(secret, t)
}

// GenerateSecure generates a TOTP code and zeroes the secret's byte representation on return.
func (p *DefaultProvider) GenerateSecure(secret string) (string, error) {
	return GenerateSecure(secret)
}

// GenerateForTimeSecure generates a time-specific TOTP code and zeroes the secret's byte representation on return.
func (p *DefaultProvider) GenerateForTimeSecure(secret string, t time.Time) (string, error) {
	return GenerateForTimeSecure(secret, t)
}

// GenerateBytes generates a TOTP code from a byte slice, zeroing the copy after use.
func (p *DefaultProvider) GenerateBytes(secret []byte) (string, error) {
	return GenerateBytes(secret)
}

// GenerateConsecutiveCodesBytes generates consecutive TOTP codes from a byte slice, zeroing the copy after use.
func (p *DefaultProvider) GenerateConsecutiveCodesBytes(secret []byte) (current, next string, err error) {
	return GenerateConsecutiveCodesBytes(secret)
}

// GenerateConsecutiveCodesBytesWithParams generates consecutive codes using non-standard TOTP parameters.
func (p *DefaultProvider) GenerateConsecutiveCodesBytesWithParams(secret []byte, params Params) (current, next string, err error) {
	return GenerateConsecutiveCodesBytesWithParams(secret, params)
}

// GenerateConsecutiveCodesForTimeBytes generates consecutive TOTP codes from a byte slice for a given base time, zeroing the copy after use.
func (p *DefaultProvider) GenerateConsecutiveCodesForTimeBytes(secret []byte, baseTime time.Time) (current, next string, err error) {
	return GenerateConsecutiveCodesForTimeBytes(secret, baseTime)
}

// GenerateForTimeBytes generates a time-specific TOTP code from a byte slice, zeroing the copy after use.
func (p *DefaultProvider) GenerateForTimeBytes(secret []byte, t time.Time) (string, error) {
	return GenerateForTimeBytes(secret, t)
}

// NewDefaultProvider creates a Provider backed by the pquerna/otp library.
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
