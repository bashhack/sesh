# Testing Guide for Sesh

This guide explains how to test `sesh`, focusing on dependency injection and mocking.

## Testing Architecture

`sesh` has been designed with testability in mind, using:

- Interface-based dependency injection
- Mockable external commands
- Testable component structure

## Interface-Based Testing

The core components of `sesh` implement interfaces that can be replaced with mocks in tests:

```go
// Example interfaces from internal/aws/interfaces.go
type Provider interface {
    GetSessionToken(profile, serial, code string) (Credentials, error)
    GetFirstMFADevice(profile string) (string, error)
}

// Example from internal/keychain/interfaces.go
type Provider interface {
    GetSecret(account, service string) (string, error)
    GetMFASerial(account string) (string, error)
}

// Example from internal/totp/interfaces.go
type Provider interface {
    Generate(secret string) (string, error)
    GenerateConsecutiveCodes(secret string) (current string, next string, err error)
}
```

## Mock Implementations

Each package provides mock implementations for testing:

```go
// Example mock usage for AWS provider
mockAWS := &awsMocks.MockProvider{}
mockAWS.GetSessionTokenFunc = func(profile, serial, code string) (aws.Credentials, error) {
    return aws.Credentials{
        AccessKeyId:     "test-key",
        SecretAccessKey: "test-secret",
        SessionToken:    "test-token",
        Expiration:      "2025-01-01T00:00:00Z",
    }, nil
}
```

## Mocking External Commands

For code that uses `exec.Command()`, we use a helper process pattern:

```go
// Save the original exec.Command and restore it after test
origExecCommand := execCommand
defer func() { execCommand = origExecCommand }()

// Create mock credentials response
mockResp := SessionTokenResponse{
    Credentials: Credentials{
        AccessKeyId:     "MOCK-ACCESS-KEY",
        SecretAccessKey: "mock-secret-key",
        SessionToken:    "mock-session-token",
        Expiration:      "2025-01-01T00:00:00Z",
    },
}

mockRespJSON, _ := json.Marshal(mockResp)

// Mock the exec.Command function to return our prepared response
execCommand = MockExecCommand(string(mockRespJSON), nil)

// Call the function
creds, err := GetSessionToken("test-profile", "arn:aws:iam::123456789012:mfa/test", "123456")
```

## App Testing

The main application has an `App` struct that takes dependencies via interfaces:

```go
type App struct {
    AWS           aws.Provider
    Keychain      keychain.Provider
    TOTP          totp.Provider
    SetupWizard   setup.WizardRunner
    ExecLookPath  ExecLookPathFunc
    Exit          ExitFunc
    Stdout        io.Writer
    Stderr        io.Writer
    VersionInfo   VersionInfo
}
```

This enables testing of all app functions with mocked dependencies.

## Running Tests

Use these commands to run tests:

```bash
# Run all tests
go test ./...

# Run tests with coverage report
go test -cover ./...

# Run tests with detailed coverage report
go test -coverprofile=coverage.txt ./...
go tool cover -func=coverage.txt

# Run only fast tests (skips integration tests)
go test -short ./...
```

## Current Test Coverage

As of the latest update, the test coverage is:

- aws: 97.3%
- keychain: 79.3%
- setup: 28.0%
- testutil: 85.4%
- totp: 94.1%
- sesh-cli/cmd/sesh: 81.5%

The setup package remains the area with the lowest coverage due to the interactive nature of the setup wizard.

## Writing New Tests

When writing new tests:

1. Use the interface-based dependency injection pattern
2. Create mocks for all dependencies
3. Test both success and failure paths
4. Use `testutil` package for common testing functions
5. Consider adding test to improve coverage in low-coverage areas

## Integration Testing

For integration tests that need actual AWS credentials:

1. These tests are skipped by default in CI environments and short mode
2. They check for environment variables like `CI=true` or `SKIP_AWS_TESTS=true`
3. They use conditional execution with `t.Skip()` when appropriate

Example:

```go
func TestGetSessionToken_Integration(t *testing.T) {
    // Skip in CI or short mode
    if testing.Short() || os.Getenv("CI") == "true" {
        t.Skip("Skipping integration test")
    }
    
    // Test with real AWS credentials...
}
```