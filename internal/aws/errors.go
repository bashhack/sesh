package aws

// MFADeviceNotFoundError represents an error when no MFA devices can be found
type MFADeviceNotFoundError struct {
	Message string
}

func (e *MFADeviceNotFoundError) Error() string {
	return e.Message
}
