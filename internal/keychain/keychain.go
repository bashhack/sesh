package keychain

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var execCommand = exec.Command

// Default installation path as a fallback
var seshBinaryPath = "/usr/local/bin/sesh"

// getCurrentExecutablePath gets the path of the current binary or a valid installed path
func getCurrentExecutablePath() string {
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
		os.ExpandEnv("$HOME/.local/bin/sesh"),
		"/usr/local/bin/sesh",
		"/opt/homebrew/bin/sesh",
	}

	for _, path := range knownPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Fall back to the default as a last resort
	return seshBinaryPath
}

// GetSecret retrieves a secret from the keychain
func GetSecret(account, service string) (string, error) {
	if account == "" {
		out, err := execCommand("whoami").Output()
		if err != nil {
			return "", fmt.Errorf("could not determine current user: %w", err)
		}
		account = strings.TrimSpace(string(out))
	}

	cmd := execCommand("security", "find-generic-password",
		"-a", account,
		"-s", service,
		"-w",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Intentionally using a message here that doesn't leak more information than necessary
		return "", fmt.Errorf("no secret found in Keychain for account %q and service %q. Run setup to configure",
			account, service)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// SetSecret sets a secret in the keychain
func SetSecret(account, service, secret string) error {
	if account == "" {
		out, err := execCommand("whoami").Output()
		if err != nil {
			return fmt.Errorf("could not determine current user: %w", err)
		}
		account = strings.TrimSpace(string(out))
	}

	// Get the current executable path at the time of access
	execPath := getCurrentExecutablePath()

	// Allow only the sesh binary to access this keychain item
	cmd := execCommand("security", "add-generic-password",
		"-a", account,
		"-s", service,
		"-w", secret,
		"-U",           // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to set secret in keychain: %w", err)
	}

	// Store in metadata system with simple description
	serviceType := getServicePrefix(service)
	StoreEntryMetadata(serviceType, service, account, service)

	return nil
}

// GetMFASerial retrieves the MFA device serial number from keychain
func GetMFASerial(account string) (string, error) {
	if account == "" {
		out, err := execCommand("whoami").Output()
		if err != nil {
			return "", fmt.Errorf("could not determine current user: %w", err)
		}
		account = strings.TrimSpace(string(out))
	}

	cmd := execCommand("security", "find-generic-password",
		"-a", account,
		"-s", "sesh-mfa-serial",
		"-w",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("no MFA serial stored in Keychain for account %q", account)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// keychainItem represents a parsed keychain entry
type keychainItem struct {
	Service     string
	Account     string
	Description string
	Label       string
	Data        string
}

// ListEntries lists all entries for a given service prefix
func ListEntries(servicePrefix string) ([]KeychainEntry, error) {
	// Use the metadata system to get entries - no fallback to insecure dump-keychain
	metaEntries, err := LoadEntryMetadata(servicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to load entry metadata: %w", err)
	}

	// Convert metadata entries to KeychainEntry format
	entries := make([]KeychainEntry, 0, len(metaEntries))
	for _, meta := range metaEntries {
		entries = append(entries, KeychainEntry{
			Service:     meta.Service,
			Account:     meta.Account,
			Description: meta.Description,
		})
	}

	return entries, nil
}

// DeleteEntry deletes an entry from the keychain
func DeleteEntry(account, service string) error {
	if account == "" {
		out, err := execCommand("whoami").Output()
		if err != nil {
			return fmt.Errorf("could not determine current user: %w", err)
		}
		account = strings.TrimSpace(string(out))
	}

	// Delete from the actual keychain
	cmd := execCommand("security", "delete-generic-password",
		"-a", account,
		"-s", service,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete entry from keychain: %w", err)
	}

	// Also remove from our metadata system
	serviceType := getServicePrefix(service)
	RemoveEntryMetadata(serviceType, service, account)

	return nil
}
