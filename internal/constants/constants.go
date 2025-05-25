package constants

import (
	"os"
)

const (
	AWSServicePrefix    = "sesh-aws"
	AWSServiceMFAPrefix = "sesh-aws-serial"

	TOTPServicePrefix = "sesh-totp"

	// MetadataServiceName is the single keychain entry name used to store all metadata
	MetadataServiceName = "sesh-metadata"

	// DefaultBinaryPath is the installation path as a fallback
	DefaultBinaryPath = "$HOME/.local/bin/sesh"
)

// For testing - allows us to mock these functions
var (
	osExecutable = os.Executable
	osStat       = os.Stat
)

// GetSeshBinaryPath returns the path to the current sesh binary or a known installation path
func GetSeshBinaryPath() string {
	// First try os.Executable() to get the current binary path
	selfPath, err := osExecutable()
	if err == nil && selfPath != "" {
		// Check if this path exists
		if _, statErr := osStat(selfPath); statErr == nil {
			return selfPath
		}
	}

	// Otherwise, check for known installation paths
	defaultPath := os.ExpandEnv(DefaultBinaryPath)
	knownPaths := []string{
		defaultPath,                       // User-install path via install.sh
		os.ExpandEnv("$HOME/go/bin/sesh"), // `go install` path
		"/usr/local/bin/sesh",             // Intel Mac Homebrew
		"/opt/homebrew/bin/sesh",          // Apple Silicon Homebrew
	}

	for _, path := range knownPaths {
		if _, err := osStat(path); err == nil {
			return path
		}
	}

	// If no binary was found, return an empty string
	// This will cause keychain operations to fail early
	// rather than creating inaccessible keychain items
	return ""
}
