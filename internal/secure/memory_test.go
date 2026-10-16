package secure

import "testing"

func TestSecureZeroBytes(t *testing.T) {
	tests := map[string]struct {
		data []byte
	}{
		"nil slice":   {nil},
		"empty slice": {[]byte{}},
		"sample data": {[]byte("sensitive data")},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var dataCopy []byte
			if tc.data != nil {
				dataCopy = make([]byte, len(tc.data))
				copy(dataCopy, tc.data)
			}

			SecureZeroBytes(tc.data)

			if len(tc.data) == 0 {
				return
			}

			for i, b := range tc.data {
				if b != 0 {
					t.Errorf("Byte at index %d was not zeroed, expected 0, got %d", i, b)
				}
			}

			if len(dataCopy) > 0 && dataCopy[0] == tc.data[0] && dataCopy[0] != 0 {
				t.Error("Original data doesn't appear to have been modified")
			}
		})
	}
}
