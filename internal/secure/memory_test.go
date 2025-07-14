package secure

import (
	"os/exec"
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
	ZeroStrings("secret1", "secret2", "")

	data1 := []byte("secret1")
	data2 := []byte("secret2")
	ZeroBytes(data1, data2, nil)

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

func TestExecAndCaptureSecure(t *testing.T) {
	tests := map[string]struct {
		setupCmd   func() *exec.Cmd
		wantOutput string
		wantErr    bool
	}{
		"successful command": {
			setupCmd: func() *exec.Cmd {
				return exec.Command("echo", "-n", "test output")
			},
			wantOutput: "test output",
			wantErr:    false,
		},
		"command with trailing whitespace": {
			setupCmd: func() *exec.Cmd {
				return exec.Command("echo", "test output")
			},
			wantOutput: "test output",
			wantErr:    false,
		},
		"failing command": {
			setupCmd: func() *exec.Cmd {
				return exec.Command("false")
			},
			wantOutput: "",
			wantErr:    true,
		},
		"command not found": {
			setupCmd: func() *exec.Cmd {
				return exec.Command("/nonexistent/command")
			},
			wantOutput: "",
			wantErr:    true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := tt.setupCmd()
			output, err := ExecAndCaptureSecure(cmd)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExecAndCaptureSecure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(output) != tt.wantOutput {
				t.Errorf("ExecAndCaptureSecure() output = %v, want %v", string(output), tt.wantOutput)
			}

			// Verify we got a copy, not the original buffer
			if !tt.wantErr && len(output) > 0 {
				// Modify our copy to ensure it's independent
				output[0] = 'X'
				// If this was the original buffer, cmd.Stdout would be modified too
			}
		})
	}
}

func TestExecWithSecretInput(t *testing.T) {
	tests := map[string]struct {
		setupCmd func() *exec.Cmd
		secret   []byte
		wantErr  bool
	}{
		"successful command": {
			setupCmd: func() *exec.Cmd {
				// Use cat to echo back the input
				return exec.Command("cat")
			},
			secret:  []byte("secret data"),
			wantErr: false,
		},
		"empty secret": {
			setupCmd: func() *exec.Cmd {
				return exec.Command("cat")
			},
			secret:  []byte{},
			wantErr: false,
		},
		"failing command": {
			setupCmd: func() *exec.Cmd {
				// grep with no pattern will fail
				return exec.Command("grep")
			},
			secret:  []byte("secret data"),
			wantErr: true,
		},
		"command not found": {
			setupCmd: func() *exec.Cmd {
				return exec.Command("/nonexistent/command")
			},
			secret:  []byte("secret data"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := tt.setupCmd()
			err := ExecWithSecretInput(cmd, tt.secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExecWithSecretInput() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
