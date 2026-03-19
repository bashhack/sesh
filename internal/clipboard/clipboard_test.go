package clipboard

import (
	"os/exec"
	"testing"
)

func TestCopy(t *testing.T) {
	originalExecCommand := execCommand
	originalRuntimeGOOS := runtimeGOOS
	defer func() {
		execCommand = originalExecCommand
		runtimeGOOS = originalRuntimeGOOS
	}()

	tests := map[string]struct {
		mockCmd func(name string, args ...string) *exec.Cmd
		text    string
		goos    string
		errMsg  string
		wantErr bool
	}{
		"darwin success": {
			text: "test text",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
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
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"darwin command not found": {
			text: "test text",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runtimeGOOS = tc.goos
			if tc.mockCmd != nil {
				execCommand = tc.mockCmd
			}

			err := Copy(tc.text)

			if (err != nil) != tc.wantErr {
				t.Errorf("Copy() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.errMsg != "" && err != nil && err.Error() != tc.errMsg {
				t.Errorf("Copy() error = %v, want %v", err.Error(), tc.errMsg)
			}
		})
	}
}

func TestCopyOSX(t *testing.T) {
	originalExecCommand := execCommand
	defer func() {
		execCommand = originalExecCommand
	}()

	tests := map[string]struct {
		mockCmd func(name string, args ...string) *exec.Cmd
		text    string
		wantErr bool
	}{
		"success": {
			text: "clipboard content",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			execCommand = tc.mockCmd

			err := copyOSX(tc.text)

			if (err != nil) != tc.wantErr {
				t.Errorf("copyOSX() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
