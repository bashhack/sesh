package aws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/bashhack/sesh/internal/secure"
)

// execCommand wraps exec.Command to allow for mocking
var execCommand = exec.Command

type Credentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// ZeroSecrets zeroes out the sensitive fields in the credentials
func (c *Credentials) ZeroSecrets() {
	if c == nil {
		return
	}
	secure.ZeroStrings(c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	c.AccessKeyId = ""
	c.SecretAccessKey = ""
	c.SessionToken = ""
}

type SessionTokenResponse struct {
	Credentials Credentials `json:"Credentials"`
}

type MFADevice struct {
	SerialNumber string `json:"SerialNumber"`
}

type ListDevicesResponse struct {
	MFADevices []MFADevice `json:"MFADevices"`
}

func GetSessionToken(profile, serial, code string) (Credentials, error) {
	// Create a copy of the code to zero after use
	codeBytes := []byte(code)
	defer secure.SecureZeroBytes(codeBytes)

	args := []string{"sts", "get-session-token",
		"--serial-number", serial,
		"--token-code", code,
		"--output", "json",
	}
	if profile != "" {
		args = append(args, "--profile", profile)
	}

	cmd := execCommand("aws", args...)

	// Create a clean environment without any AWS credential variables
	// to avoid interference with the command execution,
	// ensuring consistent behavior regardless of the user's
	// current environment state
	env := os.Environ()
	cleanEnv := make([]string, 0, len(env))
	for _, e := range env {
		// Filter out all AWS credential variables that might interfere
		if !strings.HasPrefix(e, "AWS_SESSION_TOKEN=") &&
			!strings.HasPrefix(e, "AWS_SECURITY_TOKEN=") &&
			!strings.HasPrefix(e, "AWS_ACCESS_KEY_ID=") &&
			!strings.HasPrefix(e, "AWS_SECRET_ACCESS_KEY=") {
			cleanEnv = append(cleanEnv, e)
		}
	}
	cmd.Env = cleanEnv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to run aws sts get-session-token: %w\nArgs: %v\nStderr: %s",
			err, args, stderr.String())
	}

	out := stdout.Bytes()
	defer secure.SecureZeroBytes(out)

	var parsed SessionTokenResponse
	if err := json.Unmarshal(out, &parsed); err != nil {
		return Credentials{}, fmt.Errorf("failed to parse session token response: %w", err)
	}

	return parsed.Credentials, nil
}

func GetFirstMFADevice(profile string) (string, error) {
	args := []string{"iam", "list-mfa-devices", "--output", "json"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}

	out, err := execCommand("aws", args...).Output()
	if err != nil {
		return "", fmt.Errorf("failed to list MFA devices: %w", err)
	}

	var parsed ListDevicesResponse
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse device list: %w", err)
	}

	if len(parsed.MFADevices) == 0 {
		return "", &MFADeviceNotFoundError{Message: "no MFA devices found"}
	}

	return parsed.MFADevices[0].SerialNumber, nil
}
