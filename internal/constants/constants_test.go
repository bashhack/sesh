package constants

import (
	"errors"
	"os"
	"testing"
)

func TestGetSeshBinaryPath(t *testing.T) {
	// Save originals
	originalExecutable := osExecutable
	originalStat := osStat
	defer func() {
		osExecutable = originalExecutable
		osStat = originalStat
	}()

	tests := map[string]struct {
		name            string
		executablePath  string
		executableError bool
		statResults     map[string]bool // path -> exists
		want            string
	}{
		"returns current executable path": {
			executablePath: "/usr/local/bin/current-sesh",
			statResults: map[string]bool{
				"/usr/local/bin/current-sesh": true,
			},
			want: "/usr/local/bin/current-sesh",
		},
		"falls back to default path when executable fails": {
			executableError: true,
			statResults: map[string]bool{
				os.ExpandEnv("$HOME/.local/bin/sesh"): true,
			},
			want: os.ExpandEnv("$HOME/.local/bin/sesh"),
		},
		"executable returns empty string": {
			executablePath: "",
			statResults: map[string]bool{
				os.ExpandEnv("$HOME/.local/bin/sesh"): true,
			},
			want: os.ExpandEnv("$HOME/.local/bin/sesh"),
		},
		"executable path doesn't exist": {
			executablePath: "/nonexistent/sesh",
			statResults: map[string]bool{
				"/nonexistent/sesh":                    false,
				os.ExpandEnv("$HOME/.local/bin/sesh"): true,
			},
			want: os.ExpandEnv("$HOME/.local/bin/sesh"),
		},
		"checks go install path": {
			executableError: true,
			statResults: map[string]bool{
				os.ExpandEnv("$HOME/.local/bin/sesh"): false,
				os.ExpandEnv("$HOME/go/bin/sesh"):     true,
			},
			want: os.ExpandEnv("$HOME/go/bin/sesh"),
		},
		"checks homebrew intel path": {
			executableError: true,
			statResults: map[string]bool{
				os.ExpandEnv("$HOME/.local/bin/sesh"): false,
				os.ExpandEnv("$HOME/go/bin/sesh"):     false,
				"/usr/local/bin/sesh":                  true,
			},
			want: "/usr/local/bin/sesh",
		},
		"checks homebrew arm64 path": {
			executableError: true,
			statResults: map[string]bool{
				os.ExpandEnv("$HOME/.local/bin/sesh"): false,
				os.ExpandEnv("$HOME/go/bin/sesh"):     false,
				"/usr/local/bin/sesh":                  false,
				"/opt/homebrew/bin/sesh":               true,
			},
			want: "/opt/homebrew/bin/sesh",
		},
		"returns empty string when no binary found": {
			executableError: true,
			statResults: map[string]bool{
				os.ExpandEnv("$HOME/.local/bin/sesh"): false,
				os.ExpandEnv("$HOME/go/bin/sesh"):     false,
				"/usr/local/bin/sesh":                  false,
				"/opt/homebrew/bin/sesh":               false,
			},
			want: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock osExecutable
			osExecutable = func() (string, error) {
				if tt.executableError {
					return "", errors.New("mock error")
				}
				return tt.executablePath, nil
			}

			// Mock osStat
			osStat = func(path string) (os.FileInfo, error) {
				if exists, ok := tt.statResults[path]; ok && exists {
					return nil, nil // We don't need actual FileInfo for this test
				}
				return nil, os.ErrNotExist
			}

			// Test
			got := GetSeshBinaryPath()
			if got != tt.want {
				t.Errorf("GetSeshBinaryPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	tests := map[string]struct {
		got  string
		want string
	}{
		"AWSServicePrefix":    {got: AWSServicePrefix, want: "sesh-aws"},
		"AWSServiceMFAPrefix": {got: AWSServiceMFAPrefix, want: "sesh-aws-serial"},
		"TOTPServicePrefix":   {got: TOTPServicePrefix, want: "sesh-totp"},
		"MetadataServiceName": {got: MetadataServiceName, want: "sesh-metadata"},
		"DefaultBinaryPath":   {got: DefaultBinaryPath, want: "$HOME/.local/bin/sesh"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", name, tt.got, tt.want)
			}
		})
	}
}