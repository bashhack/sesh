// Package keychain provides access to the macOS Keychain for storing and retrieving secrets.
package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/keyformat"
	"github.com/bashhack/sesh/internal/secure"
)

// ErrNotFound is returned when a keychain item does not exist.
var ErrNotFound = errors.New("secret not found in keychain")

// exitCodeItemNotFound is the macOS `security` command exit code for errSecItemNotFound.
const exitCodeItemNotFound = 44

// execCommand is kept for the one case (delete) that needs *exec.Cmd for stderr + Run().
// For new code, prefer the higher-level mockable functions below.
var execCommand = exec.Command

// getCurrentUser returns the current OS username. Mockable for tests.
var getCurrentUser = func() (string, error) {
	out, err := exec.Command("whoami").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// captureSecure wraps secure.ExecAndCaptureSecure. Mockable for tests.
var captureSecure = secure.ExecAndCaptureSecure

// execSecretInput wraps secure.ExecWithSecretInput. Mockable for tests.
var execSecretInput = secure.ExecWithSecretInput

// GetSecretBytes retrieves a secret from the keychain as a byte slice
// This is the more secure variant of GetSecret
func GetSecretBytes(account, service string) ([]byte, error) {
	if account == "" {
		user, err := getCurrentUser()
		if err != nil {
			return nil, fmt.Errorf("could not determine current user: %w", err)
		}
		account = user
	}
	cmd := execCommand("security", "find-generic-password",
		"-a", account,
		"-s", service,
		"-w",
	)

	// Use secure capturing to ensure memory is zeroed if there are errors
	secret, err := captureSecure(cmd)
	if err != nil {
		// macOS `security` exits with code 44 for errSecItemNotFound
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == exitCodeItemNotFound {
			return nil, fmt.Errorf("%w for account %q and service %q", ErrNotFound, account, service)
		}
		return nil, fmt.Errorf("keychain read failed for account %q and service %q: %w", account, service, err)
	}

	// For TOTP secrets, ensure they are properly normalized
	if strings.HasPrefix(service, "sesh-aws") || strings.HasPrefix(service, "sesh-totp") {
		// Trim whitespace - CRITICAL: removes any newlines, which can cause base32 decode failures
		secretTrimmed := bytes.TrimSpace(secret)
		if len(secretTrimmed) != len(secret) {
			secret = secretTrimmed
		}
	}

	// Make a defensive copy to return
	result := make([]byte, len(secret))
	copy(result, secret)

	// Zero the original
	secure.SecureZeroBytes(secret)

	return result, nil
}

// GetSecretString retrieves a secret from the keychain as a string
// This is provided for backward compatibility but is less secure
// than GetSecretBytes
func GetSecretString(account, service string) (string, error) {
	secretBytes, err := GetSecretBytes(account, service)
	if err != nil {
		return "", err
	}

	// Convert to string and zero the bytes
	secret := string(secretBytes)
	secure.SecureZeroBytes(secretBytes)

	return secret, nil
}

// SetSecretBytes sets a byte slice secret in the keychain
// This is the more secure variant of SetSecret
func SetSecretBytes(account, service string, secret []byte) error {
	// Create a defensive copy to avoid mutating the caller's data
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	if account == "" {
		user, err := getCurrentUser()
		if err != nil {
			return fmt.Errorf("could not determine current user: %w", err)
		}
		account = user
	}

	// Get the current executable path at the time of access
	execPath := constants.GetSeshBinaryPath()
	if execPath == "" {
		return fmt.Errorf("could not determine the path to the sesh binary, cannot access keychain")
	}

	// Use interactive mode to keep password out of process listings
	// This approach is inspired by the Python keyring library
	// Ref: https://github.com/jaraco/keyring
	secretStr := string(secretCopy)
	defer secure.SecureZeroString(secretStr)

	// Build the command to send to security -i
	addCmd := fmt.Sprintf("add-generic-password -a %s -s %s -w %s -U -T %s",
		account, service, secretStr, execPath)

	// Use security in interactive mode
	cmd := execCommand("security", "-i")

	// Provide the command via stdin
	err := execSecretInput(cmd, []byte(addCmd+"\n"))
	if err != nil {
		return fmt.Errorf("failed to set secret in keychain: %w", err)
	}

	// Store in metadata system — required for ListEntries and DeleteEntry to find this entry
	serviceType := getServicePrefix(service)
	if err := StoreEntryMetadata(serviceType, service, account, service); err != nil {
		return fmt.Errorf("secret stored but metadata write failed (entry won't appear in -list): %w", err)
	}

	return nil
}

// SetSecretString sets a string secret in the keychain
// This is provided for backward compatibility but is less secure
// than SetSecretBytes
func SetSecretString(account, service, secret string) error {
	secretBytes := []byte(secret)
	defer secure.SecureZeroBytes(secretBytes)

	return SetSecretBytes(account, service, secretBytes)
}

// GetMFASerialBytes retrieves the MFA device serial number from keychain as bytes
// This is more secure than GetMFASerial
func GetMFASerialBytes(account, profile string) ([]byte, error) {
	if account == "" {
		user, err := getCurrentUser()
		if err != nil {
			return nil, fmt.Errorf("could not determine current user: %w", err)
		}
		account = user
	}
	if profile == "" {
		profile = "default"
	}
	service, err := keyformat.Build(constants.AWSServiceMFAPrefix, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to build MFA serial key: %w", err)
	}
	cmd := execCommand("security", "find-generic-password",
		"-a", account,
		"-s", service,
		"-w",
	)

	// Use secure capturing to ensure memory is zeroed if there are errors
	serialBytes, err := captureSecure(cmd)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == exitCodeItemNotFound {
			return nil, fmt.Errorf("%w for account %q and service %q", ErrNotFound, account, service)
		}
		return nil, fmt.Errorf("keychain read failed for account %q and service %q: %w", account, service, err)
	}

	// Make a defensive copy
	result := make([]byte, len(serialBytes))
	copy(result, serialBytes)

	// Zero the original
	secure.SecureZeroBytes(serialBytes)

	return result, nil
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
		user, err := getCurrentUser()
		if err != nil {
			return fmt.Errorf("could not determine current user: %w", err)
		}
		account = user
	}

	// Remove metadata first — if this fails, nothing has been deleted yet
	serviceType := getServicePrefix(service)
	if err := RemoveEntryMetadata(serviceType, service, account); err != nil {
		return fmt.Errorf("failed to remove entry metadata: %w", err)
	}

	// Now delete from the actual keychain
	cmd := execCommand("security", "delete-generic-password",
		"-a", account,
		"-s", service,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete entry from keychain: %w", err)
	}

	return nil
}
