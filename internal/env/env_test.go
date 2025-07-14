package env

import (
	"os"
	"os/exec"
	"testing"
)

func TestGetCurrentUser(t *testing.T) {
	originalExecCommand := execCommand
	defer func() {
		execCommand = originalExecCommand
	}()

	tests := map[string]struct {
		envUser   string
		cmdOutput string
		cmdError  bool
		want      string
		wantErr   bool
		setup     func()
		teardown  func()
	}{
		"user from env variable": {
			envUser: "testuser",
			want:    "testuser",
			setup: func() {
				os.Setenv("USER", "testuser")
			},
			teardown: func() {
				os.Unsetenv("USER")
			},
		},
		"user from whoami command": {
			envUser:   "",
			cmdOutput: "cmduser",
			want:      "cmduser",
			setup: func() {
				os.Unsetenv("USER")
			},
		},
		"user from whoami with trailing newline": {
			envUser:   "",
			cmdOutput: "cmduser\n",
			want:      "cmduser",
			setup: func() {
				os.Unsetenv("USER")
			},
		},
		"error when whoami fails": {
			envUser:  "",
			cmdError: true,
			wantErr:  true,
			setup: func() {
				os.Unsetenv("USER")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			if tt.teardown != nil {
				defer tt.teardown()
			}

			execCommand = func(name string, args ...string) *exec.Cmd {
				if name == "whoami" {
					if tt.cmdError {
						return exec.Command("false")
					}
					return exec.Command("echo", "-n", tt.cmdOutput)
				}
				return originalExecCommand(name, args...)
			}

			got, err := GetCurrentUser()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCurrentUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetCurrentUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
