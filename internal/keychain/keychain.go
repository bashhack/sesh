package keychain

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

var execCommand = exec.Command

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
