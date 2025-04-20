package aws

import (
	"testing"
)

func TestMFADeviceNotFoundError_Error(t *testing.T) {
	testMessage := "test error message"
	err := &MFADeviceNotFoundError{Message: testMessage}

	if err.Error() != testMessage {
		t.Errorf("Expected error message '%s', got '%s'", testMessage, err.Error())
	}

	err = &MFADeviceNotFoundError{Message: ""}
	if err.Error() != "" {
		t.Errorf("Expected empty error message, got '%s'", err.Error())
	}
}
