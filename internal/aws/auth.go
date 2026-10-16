// Package aws handles AWS STS authentication and temporary credential management.
package aws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bashhack/sesh/internal/secure"
)

// execCommand wraps exec.Command to allow for mocking
var execCommand = exec.Command

// InvalidMFAMessage is what the AWS CLI says when it refuses an MFA code
// that's wrong or already used, which a caller can retry with the next.
const InvalidMFAMessage = "MultiFactorAuthentication failed with invalid MFA one time pass code"

// Credentials holds the temporary AWS session credentials returned by STS.
type Credentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// Clear drops the credentials' values. Go can't overwrite a string's
// bytes, so this only stops c holding them; the strings stay in memory
// until the garbage collector reuses it.
func (c *Credentials) Clear() {
	if c == nil {
		return
	}
	c.AccessKeyID = ""
	c.SecretAccessKey = ""
	c.SessionToken = ""
}

// SessionTokenResponse wraps the JSON response from aws sts get-session-token.
type SessionTokenResponse struct {
	Credentials Credentials `json:"Credentials"`
}

// MFADevice represents a single MFA device from the IAM list-mfa-devices response.
type MFADevice struct {
	SerialNumber string `json:"SerialNumber"`
}

// ListDevicesResponse wraps the JSON response from aws iam list-mfa-devices.
type ListDevicesResponse struct {
	MFADevices []MFADevice `json:"MFADevices"`
}

// GetSessionToken calls aws sts get-session-token with the given MFA serial and TOTP code,
// returning temporary credentials. The code goes on the AWS CLI's command
// line, where ps can see it while the CLI runs; it's a one-time code.
func GetSessionToken(profile, serial string, code []byte) (Credentials, error) {
	cmd := execCommand("aws", CLIArgs(profile, "sts", "get-session-token",
		"--serial-number", serial,
		"--token-code", string(code),
		"--output", "json",
	)...)
	cmd.Env = CLIEnv(profile)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// The AWS CLI's message is read before the buffers are zeroed:
		// callers match it to retry with the next code. The arguments,
		// which hold the code, are left out.
		msg := strings.TrimSpace(stderr.String())
		secure.SecureZeroBytes(stdout.Bytes())
		secure.SecureZeroBytes(stderr.Bytes())
		if msg == "" {
			return Credentials{}, fmt.Errorf("aws sts get-session-token: %w", err)
		}
		return Credentials{}, fmt.Errorf("aws sts get-session-token: %s", msg)
	}

	// Note: out shares the same backing array as stdout.Bytes(), so the
	// explicit SecureZeroBytes(stdout.Bytes()) calls below also zero out.
	out := stdout.Bytes()

	var parsed SessionTokenResponse
	if err := json.Unmarshal(out, &parsed); err != nil {
		secure.SecureZeroBytes(stdout.Bytes())
		secure.SecureZeroBytes(stderr.Bytes())
		return Credentials{}, fmt.Errorf("failed to parse session token response: %w", err)
	}

	secure.SecureZeroBytes(stdout.Bytes())
	secure.SecureZeroBytes(stderr.Bytes())

	return parsed.Credentials, nil
}

// GetFirstMFADevice returns the first virtual MFA device (authenticator
// app) of the IAM user profile signs in as.
func GetFirstMFADevice(profile string) (string, error) {
	devices, err := ListMFADevices(profile)
	if err != nil {
		return "", err
	}
	if len(devices) == 0 {
		return "", errors.New("AWS lists no authenticator app as an MFA device for this profile's user: set one up with sesh aws setup")
	}
	return devices[0], nil
}
