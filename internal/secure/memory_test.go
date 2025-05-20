package secure

import (
	"testing"
)

func TestSecureZeroBytes(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"nil slice", nil},
		{"empty slice", []byte{}},
		{"sample data", []byte("sensitive data")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a copy we can check later
			var dataCopy []byte
			if tc.data != nil {
				dataCopy = make([]byte, len(tc.data))
				copy(dataCopy, tc.data)
			}

			// Call the function
			SecureZeroBytes(tc.data)

			// Check if it was zeroed properly
			if tc.data == nil || len(tc.data) == 0 {
				// Nothing to check for nil or empty slices
				return
			}

			// Verify all bytes are zero
			for i, b := range tc.data {
				if b != 0 {
					t.Errorf("Byte at index %d was not zeroed, expected 0, got %d", i, b)
				}
			}

			// Verify original data was actually changed
			if len(dataCopy) > 0 && dataCopy[0] == tc.data[0] && dataCopy[0] != 0 {
				t.Error("Original data doesn't appear to have been modified")
			}
		})
	}
}

func TestSecureZeroString(t *testing.T) {
	// Note: We can't directly test if the string was zeroed in memory,
	// but we can at least verify the function runs without errors
	testCases := []struct {
		name string
		data string
	}{
		{"empty string", ""},
		{"sample string", "sensitive string data"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simply verify no panic occurs
			SecureZeroString(tc.data)
		})
	}
}

func TestZeroMultiple(t *testing.T) {
	// Test ZeroStrings
	ZeroStrings("secret1", "secret2", "")

	// Test ZeroBytes
	data1 := []byte("secret1")
	data2 := []byte("secret2")
	ZeroBytes(data1, data2, nil)

	// Verify bytes were zeroed
	for i, b := range data1 {
		if b != 0 {
			t.Errorf("data1: Byte at index %d was not zeroed", i)
		}
	}
	for i, b := range data2 {
		if b != 0 {
			t.Errorf("data2: Byte at index %d was not zeroed", i)
		}
	}
}