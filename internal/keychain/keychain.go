// Package keychain defines the store interface sesh's entries go through,
// and reads, writes, and deletes the single macOS Keychain item that the
// keychain key source keeps the vault's key in.
package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bashhack/sesh/internal/constants"
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

	// Make a defensive copy to return
	result := make([]byte, len(secret))
	copy(result, secret)

	// Zero the original
	secure.SecureZeroBytes(secret)

	return result, nil
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

	return nil
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

	cmd := execCommand("security", "delete-generic-password",
		"-a", account,
		"-s", service,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == exitCodeItemNotFound {
			return fmt.Errorf("%w for account %q and service %q", ErrNotFound, account, service)
		}
		return fmt.Errorf("failed to delete entry from keychain: %w", err)
	}

	return nil
}

// ItemStore reads, writes, and deletes single Keychain items: all the
// keychain key source needs.
type ItemStore interface {
	GetSecret(account, service string) ([]byte, error)
	SetSecret(account, service string, secret []byte) error
	DeleteEntry(account, service string) error
}

// Items is the macOS Keychain as an ItemStore.
type Items struct{}

var _ ItemStore = Items{}

// GetSecret reads the item's secret.
func (Items) GetSecret(account, service string) ([]byte, error) {
	return GetSecretBytes(account, service)
}

// SetSecret creates or replaces the item.
func (Items) SetSecret(account, service string, secret []byte) error {
	return SetSecretBytes(account, service, secret)
}

// DeleteEntry deletes the item.
func (Items) DeleteEntry(account, service string) error {
	return DeleteEntry(account, service)
}
