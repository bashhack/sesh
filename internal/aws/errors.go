package aws

// MFADeviceNotFoundError represents an error when no MFA devices can be found
type MFADeviceNotFoundError struct {
	Message string
}

// Error implements the error interface for MFADeviceNotFoundError.
func (e *MFADeviceNotFoundError) Error() string {
	return e.Message
}
