package keychain

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/secure"
)

var execCommand = exec.Command

// GetSecretBytes retrieves a secret from the keychain as a byte slice
// This is the more secure variant of GetSecret
func GetSecretBytes(account, service string) ([]byte, error) {
	if account == "" {
		out, err := execCommand("whoami").Output()
		if err != nil {
			return nil, fmt.Errorf("could not determine current user: %w", err)
		}
		account = strings.TrimSpace(string(out))
	}

	cmd := execCommand("security", "find-generic-password",
		"-a", account,
		"-s", service,
		"-w",
	)

	// Use secure capturing to ensure memory is zeroed if there are errors
	secret, err := secure.ExecAndCaptureSecure(cmd)
	if err != nil {
		// Intentionally using a message here that doesn't leak more information than necessary
		return nil, fmt.Errorf("no secret found in Keychain for account %q and service %q. Run setup to configure",
			account, service)
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
		out, err := execCommand("whoami").Output()
		if err != nil {
			return fmt.Errorf("could not determine current user: %w", err)
		}
		account = strings.TrimSpace(string(out))
	}

	// Get the current executable path at the time of access
	execPath := constants.GetSeshBinaryPath()
	if execPath == "" {
		return fmt.Errorf("could not determine the path to the sesh binary, cannot access keychain")
	}

	// Convert to string for the security command
	// This is necessary because we need to pass it as a command-line argument
	secretStr := string(secretCopy)
	
	// Allow only the sesh binary to access this keychain item
	cmd := execCommand("security", "add-generic-password",
		"-a", account,
		"-s", service,
		"-w", secretStr,
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

// SetSecretString sets a string secret in the keychain
// This is provided for backward compatibility but is less secure
// than SetSecretBytes
func SetSecretString(account, service, secret string) error {
	secretBytes := []byte(secret)
	defer secure.SecureZeroBytes(secretBytes)
	
	return SetSecretBytes(account, service, secretBytes)
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

	// Use secure capturing to ensure memory is zeroed if there are errors
	serialBytes, err := secure.ExecAndCaptureSecure(cmd)
	if err != nil {
		return "", fmt.Errorf("no MFA serial stored in Keychain for account %q", account)
	}

	// Convert to string
	serial := string(serialBytes)
	
	// Zero the byte slice
	secure.SecureZeroBytes(serialBytes)
	
	return serial, nil
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
