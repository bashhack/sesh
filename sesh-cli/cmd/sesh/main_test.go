package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/keychain/mocks"
	setupMocks "github.com/bashhack/sesh/internal/setup/mocks"
	"github.com/bashhack/sesh/internal/testutil"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

// TestHelperProcess is needed for the testutil.MockExecCommand function
func TestHelperProcess(t *testing.T) {
	testutil.TestHelperProcess()
}

func mockApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	return &App{
		AWS:          &awsMocks.MockProvider{},
		Keychain:     &mocks.MockProvider{},
		TOTP:         &totpMocks.MockProvider{},
		SetupWizard:  &setupMocks.MockWizardRunner{},
		ExecLookPath: func(string) (string, error) { return "/usr/local/bin/aws", nil },
		Exit:         func(int) {},
		Stdout:       stdoutBuf,
		Stderr:       stderrBuf,
		VersionInfo: VersionInfo{
			Version: "test-version",
			Commit:  "test-commit",
			Date:    "test-date",
		},
	}, stdoutBuf, stderrBuf
}

func TestVersionFlag(t *testing.T) {
	app, stdoutBuf, _ := mockApp()

	exitCalled := false
	app.Exit = func(int) { exitCalled = true }

	run(app, []string{"sesh", "--version"})

	output := stdoutBuf.String()

	if !strings.Contains(output, "test-version") || !strings.Contains(output, "test-commit") {
		t.Errorf("Expected version output to contain version and commit info, got: %s", output)
	}

	if exitCalled {
		t.Error("Exit was called but shouldn't have been")
	}
}

func TestHelpFlag(t *testing.T) {
	app, stdoutBuf, _ := mockApp()

	exitCalled := false
	app.Exit = func(int) { exitCalled = true }

	run(app, []string{"sesh", "--help"})

	output := stdoutBuf.String()

	if !strings.Contains(output, "Usage of") {
		t.Errorf("Expected help output to contain usage info, got: %s", output)
	}

	if exitCalled {
		t.Error("Exit was called but shouldn't have been")
	}
}

func TestNoAwsCli(t *testing.T) {
	app, _, stderrBuf := mockApp()

	app.ExecLookPath = func(string) (string, error) {
		return "", os.ErrNotExist
	}

	exitCalled := false
	exitCode := 0
	app.Exit = func(code int) {
		exitCalled = true
		exitCode = code
	}

	run(app, []string{"sesh"})

	output := stderrBuf.String()

	if !strings.Contains(output, "AWS CLI not found") {
		t.Errorf("Expected error message about AWS CLI not found, got: %s", output)
	}

	if !exitCalled {
		t.Error("Exit was not called")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestMFASerialFromKeychain(t *testing.T) {
	app, stdoutBuf, stderrBuf := mockApp()

	keychainMock := app.Keychain.(*mocks.MockProvider)
	keychainMock.GetMFASerialFunc = func(account string) (string, error) {
		return "arn:aws:iam::123456789012:mfa/username", nil
	}

	totpMock := app.TOTP.(*totpMocks.MockProvider)
	totpMock.GenerateFunc = func(secret string) (string, error) {
		return "123456", nil
	}

	keychainMock.GetSecretFunc = func(account, service string) (string, error) {
		return "test-secret", nil
	}

	awsMock := app.AWS.(*awsMocks.MockProvider)
	awsMock.GetSessionTokenFunc = func(profile, serial, code string) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			SessionToken:    "test-session-token",
			Expiration:      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		}, nil
	}

	exitCalled := false
	app.Exit = func(int) { exitCalled = true }

	run(app, []string{"sesh"})

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()

	if !strings.Contains(stdout, "export AWS_ACCESS_KEY_ID=test-access-key") {
		t.Errorf("Expected stdout to contain credentials, got: %s", stdout)
	}

	if !strings.Contains(stdout, "export AWS_SECRET_ACCESS_KEY=test-secret-key") {
		t.Errorf("Expected stdout to contain secret key, got: %s", stdout)
	}

	if !strings.Contains(stdout, "export AWS_SESSION_TOKEN=test-session-token") {
		t.Errorf("Expected stdout to contain session token, got: %s", stdout)
	}

	if !strings.Contains(stderr, "✅ Credentials acquired") {
		t.Errorf("Expected stderr to contain success message, got: %s", stderr)
	}

	if exitCalled {
		t.Error("Exit was called but shouldn't have been")
	}
}

func TestTOTPSecretError(t *testing.T) {
	app, _, stderrBuf := mockApp()

	keychainMock := app.Keychain.(*mocks.MockProvider)
	keychainMock.GetSecretFunc = func(account, service string) (string, error) {
		return "", &os.PathError{Op: "open", Path: "keychain", Err: os.ErrNotExist}
	}

	keychainMock.GetMFASerialFunc = func(account string) (string, error) {
		return "arn:aws:iam::123456789012:mfa/username", nil
	}

	exitCalled := false
	exitCode := 0
	app.Exit = func(code int) {
		exitCalled = true
		exitCode = code
	}

	run(app, []string{"sesh"})

	output := stderrBuf.String()

	if !strings.Contains(output, "Could not retrieve TOTP secret") {
		t.Errorf("Expected error message about TOTP secret, got: %s", output)
	}

	if !strings.Contains(output, "Run the setup wizard") {
		t.Errorf("Expected error message to contain setup instructions, got: %s", output)
	}

	if !exitCalled {
		t.Error("Exit was not called")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}
