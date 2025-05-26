# Coverage TODO

## Functions with 0% Coverage to Address

### High Priority - Core Functionality
These are the most important functions that need test coverage:

#### TOTP Provider
✅ ~~`internal/provider/totp/provider.go:34` - `NewProvider` - Constructor needs testing~~ (DONE)
✅ ~~`internal/provider/totp/provider.go:70` - `GetSetupHandler` - Setup handler creation~~ (DONE)

#### Setup Functions (Critical Path)
- `internal/setup/setup.go:413` - `Setup` (AWS) - Main AWS setup flow
- `internal/setup/setup.go:601` - `Setup` (TOTP) - Main TOTP setup flow

#### Main Entry Points
- `sesh/cmd/sesh/main.go:20` - `main` - Application entry point
✅ ~~`sesh/cmd/sesh/app.go:48` - `NewDefaultApp` - Default app constructor~~ (DONE)
✅ ~~`sesh/cmd/sesh/app.go:164` - `RunSetup` - Setup command handler~~ (DONE)
✅ ~~`sesh/cmd/sesh/app.go:149` - `DeleteEntry` - Delete command handler~~ (DONE)

### Medium Priority - Setup Helpers
These support the setup flow and should be tested:

#### AWS Setup Helpers
- `internal/setup/setup.go:64` - `verifyAWSCredentials`
- `internal/setup/setup.go:82` - `captureMFASecret`
- `internal/setup/setup.go:127` - `captureAWSQRCodeWithFallback`
- `internal/setup/setup.go:132` - `captureAWSManualEntry`
- `internal/setup/setup.go:152` - `setupMFAConsole`
- `internal/setup/setup.go:178` - `selectMFADevice`
- `internal/setup/setup.go:326` - `promptForMFAARN`
- `internal/setup/setup.go:351` - `promptForMFASetupMethod`
- `internal/setup/setup.go:376` - `showSetupCompletionMessage`

#### TOTP Setup Helpers
✅ ~~`internal/setup/setup.go:521` - `promptForServiceName`~~ (DONE)
✅ ~~`internal/setup/setup.go:534` - `promptForProfile`~~ (DONE)
✅ ~~`internal/setup/setup.go:542` - `promptForCaptureMethod`~~ (DONE)
✅ ~~`internal/setup/setup.go:559` - `captureTOTPSecret`~~ (DONE - partial, only error cases)
- `internal/setup/setup.go:571` - `captureQRCodeWithFallback`
- `internal/setup/setup.go:576` - `captureManualEntry`
✅ ~~`internal/setup/setup.go:591` - `showTOTPSetupCompletionMessage`~~ (DONE)
- `internal/setup/setup.go:677` - `captureQRWithRetry`

### Lower Priority - Output Functions
These are primarily display/output functions:

✅ ~~`sesh/cmd/sesh/main.go:202` - `printUsage` - Help text display~~ (DONE)
✅ ~~`sesh/cmd/sesh/app.go:264` - `PrintCredentials` - Credential output formatting~~ (DONE)
✅ ~~`sesh/cmd/sesh/app_subshell.go:13` - `LaunchSubshell` - Subshell launching~~ (DONE)

## Testing Strategy Notes

1. **Setup functions** are interactive and may need mock stdin/stdout for testing
2. **Main functions** might need integration-style tests or be excluded from unit coverage
3. **Provider constructors** should be straightforward to test
4. **Output functions** can be tested by capturing stdout

## Current Overall Coverage: 70.4%

Target: Increase coverage by focusing on high-priority items first.