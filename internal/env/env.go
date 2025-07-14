package env

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var execCommand = exec.Command

// GetCurrentUser gets the current system user
func GetCurrentUser() (string, error) {
	user := os.Getenv("USER")
	if user != "" {
		return user, nil
	}

	out, err := execCommand("whoami").Output()
	if err != nil {
		return "", fmt.Errorf("could not determine current user: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
