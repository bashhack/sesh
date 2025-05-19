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

// GetSeshBinaryPath returns the path to the current sesh binary or a known installation path
func GetSeshBinaryPath() string {
	// First try os.Executable() to get the current binary path
	selfPath, err := os.Executable()
	if err == nil && selfPath != "" {
		// Check if this path exists
		if _, statErr := os.Stat(selfPath); statErr == nil {
			return selfPath
		}
	}

	// Otherwise, check for known installation paths
	knownPaths := []string{
		os.ExpandEnv(DefaultBinaryPath),
		"/usr/local/bin/sesh",
		"/opt/homebrew/bin/sesh",
	}

	for _, path := range knownPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Fall back to the default as a last resort
	return DefaultBinaryPath
}
