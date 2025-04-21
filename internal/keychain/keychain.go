package keychain

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
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

// SetSeshBinaryPath allows setting the path to the sesh binary for keychain access control
// This is maintained for backward compatibility but isn't used by the new implementation
func SetSeshBinaryPath(path string) {
	if path != "" {
		seshBinaryPath = path
	}
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

	// Debug the current binary path at time of access
	execPath := getCurrentExecutablePath()
	fmt.Fprintf(os.Stderr, "DEBUG: Current binary path used for keychain access: %s\n", execPath)
	
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
		"-U", // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to set secret in keychain: %w", err)
	}

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
	// Run security command to list all keychain items
	cmd := execCommand("security", "dump-keychain", "-d")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		return nil, fmt.Errorf("failed to list keychain entries: %w (%s)", err, errMsg)
	}

	output := stdout.String()

	// Parse the output to find matching entries
	// Each keychain entry is enclosed in blocks of "attributes:", "data:", etc
	var entries []KeychainEntry
	
	// Split output by keychain items
	itemPattern := regexp.MustCompile(`(?s)keychain: "[^"]+"\s+class: "genp".*?data:.*?$`)
	items := itemPattern.FindAllString(output, -1)

	for _, item := range items {
		// Only process items that match our service prefix
		if strings.Contains(item, fmt.Sprintf(`"svce"<blob>="%-s`, servicePrefix)) {
			// Parse the service name
			serviceMatch := regexp.MustCompile(`"svce"<blob>="([^"]+)"`).FindStringSubmatch(item)
			if len(serviceMatch) < 2 {
				continue
			}
			service := serviceMatch[1]
			
			// Parse the account name
			accountMatch := regexp.MustCompile(`"acct"<blob>="([^"]+)"`).FindStringSubmatch(item)
			if len(accountMatch) < 2 {
				continue
			}
			account := accountMatch[1]

			// Parse label/description if available
			var description string
			labelMatch := regexp.MustCompile(`"labl"<blob>="([^"]+)"`).FindStringSubmatch(item)
			if len(labelMatch) >= 2 {
				description = labelMatch[1]
			} else {
				descMatch := regexp.MustCompile(`"desc"<blob>="([^"]+)"`).FindStringSubmatch(item)
				if len(descMatch) >= 2 {
					description = descMatch[1]
				}
			}

			entries = append(entries, KeychainEntry{
				Service:     service,
				Account:     account,
				Description: description,
			})
		}
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

	return nil
}