package clipboard

import (
	"os/exec"
	"testing"
)

func TestCopy(t *testing.T) {
	// Save originals
	originalExecCommand := execCommand
	originalRuntimeGOOS := runtimeGOOS
	defer func() {
		execCommand = originalExecCommand
		runtimeGOOS = originalRuntimeGOOS
	}()

	tests := map[string]struct {
		name     string
		text     string
		goos     string
		mockCmd  func(name string, args ...string) *exec.Cmd
		wantErr  bool
		errMsg   string
	}{
		"darwin success": {
			text: "test text",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					// Return a command that will succeed
					return exec.Command("true")
				}
				return nil
			},
			wantErr: false,
		},
		"darwin empty text": {
			text: "",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("true")
				}
				return nil
			},
			wantErr: false,
		},
		"darwin command not found": {
			text: "test text",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				// Return a command that doesn't exist
				return exec.Command("/nonexistent/pbcopy")
			},
			wantErr: true,
		},
		"unsupported platform": {
			text:    "test text",
			goos:    "linux",
			wantErr: true,
			errMsg:  "unsupported platform: linux",
		},
		"windows platform": {
			text:    "test text",
			goos:    "windows",
			wantErr: true,
			errMsg:  "unsupported platform: windows",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Set up mocks
			runtimeGOOS = tt.goos
			if tt.mockCmd != nil {
				execCommand = tt.mockCmd
			}

			// Test
			err := Copy(tt.text)

			if (err != nil) != tt.wantErr {
				t.Errorf("Copy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.errMsg != "" && err != nil && err.Error() != tt.errMsg {
				t.Errorf("Copy() error = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestCopyOSX(t *testing.T) {
	// Save original
	originalExecCommand := execCommand
	defer func() {
		execCommand = originalExecCommand
	}()

	tests := map[string]struct {
		name    string
		text    string
		mockCmd func(name string, args ...string) *exec.Cmd
		wantErr bool
	}{
		"success": {
			text: "clipboard content",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					// Use echo to simulate successful command
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"multiline text": {
			text: "line1\nline2\nline3",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"special characters": {
			text: "text with 'quotes' and \"double quotes\" and $variables",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"command fails": {
			text: "test",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("false")
				}
				return nil
			},
			wantErr: true,
		},
		"command not found": {
			text: "test",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				return exec.Command("/nonexistent/command")
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Set up mock
			execCommand = tt.mockCmd

			// Test
			err := copyOSX(tt.text)

			if (err != nil) != tt.wantErr {
				t.Errorf("copyOSX() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMockExecCommand verifies our mock works correctly
func TestMockExecCommand(t *testing.T) {
	// This test verifies that our execCommand variable can be properly mocked
	originalExecCommand := execCommand
	defer func() {
		execCommand = originalExecCommand
	}()

	called := false
	execCommand = func(name string, args ...string) *exec.Cmd {
		called = true
		return exec.Command("echo", "mocked")
	}

	// Create a command using our mock
	cmd := execCommand("test")
	if !called {
		t.Error("Mock execCommand was not called")
	}

	if cmd == nil {
		t.Error("Mock execCommand returned nil")
	}
}