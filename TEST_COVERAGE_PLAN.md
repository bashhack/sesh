# Test Coverage Improvement Plan

## Current State Analysis

### Coverage Summary
- **Total Coverage**: 40.1% (excluding testutil/mocks)
- **Well-Tested** (>70%): aws (76.9%), provider/totp (79.3%), provider (76.2%), password (75.0%)
- **Moderate** (30-70%): keychain (64.9%), totp (45.2%), cmd/sesh (43.5%), secure (36.1%), provider/aws (53.1%)
- **Low/None** (<30%): setup (4.7%), clipboard (0%), constants (0%), env (0%), qrcode (0%), subshell (0%)

## Priority Tiers

### Tier 1: Quick Wins (High Impact, Easy to Test)
These are simple utility functions with no external dependencies.

1. **internal/env** (0% → ~90%)
   - `GetCurrentUser()` - Simple wrapper, mock os/user
   - 1 file, ~20 lines of code
   - Estimated time: 15 minutes

2. **internal/constants** (0% → ~90%)
   - `GetSeshBinaryPath()` - Simple path resolution
   - 1 file, ~30 lines of code
   - Estimated time: 20 minutes

3. **internal/secure** (36.1% → ~80%)
   - Already has some tests, fill gaps:
   - `ExecAndCaptureSecure()` - Mock exec.Command
   - `ExecWithSecretInput()` - Mock exec.Command
   - Estimated time: 45 minutes

### Tier 2: Core Business Logic (High Value)
These are critical to the application's functionality.

4. **internal/totp** (45.2% → ~80%)
   - `GenerateForTime()` - Core TOTP generation
   - `GenerateSecure/GenerateBytes` variants
   - Already has test infrastructure
   - Estimated time: 1 hour

5. **internal/provider/aws** (53.1% → ~80%)
   - `getAWSProfiles()` - Mock AWS CLI output
   - `ListEntries()` - Uses getAWSProfiles
   - `DeleteEntry()` - Mock keychain operations
   - `parseServiceKey()` - Pure function
   - Estimated time: 1.5 hours

6. **internal/keychain** (64.9% → ~85%)
   - Fill gaps in existing tests:
   - `SetSecret()`, `GetSecretString()`, `SetSecretString()`
   - `ListEntries()`, `DeleteEntry()` 
   - Already has mock infrastructure
   - Estimated time: 1 hour

### Tier 3: Integration Points (Medium Complexity)
These require more setup but are important for reliability.

7. **sesh/cmd/sesh** (43.5% → ~70%)
   - `printUsage()` - Test output formatting
   - `GenerateCredentials()` - Mock provider calls
   - `CopyToClipboard()` - Mock clipboard operations
   - Estimated time: 2 hours

8. **internal/clipboard** (0% → ~80%)
   - `Copy()` and `copyOSX()` - Mock exec.Command
   - Platform-specific but testable with build tags
   - Estimated time: 1 hour

### Tier 4: Complex/Interactive (Lower Priority)
These are harder to test due to user interaction or external dependencies.

9. **internal/setup** (4.7% → ~40%)
   - Focus on non-interactive helpers:
   - `createServiceName()`, `createTOTPServiceName()`
   - `buildServiceKey()` type functions
   - Skip interactive prompts for now
   - Estimated time: 2 hours

10. **internal/subshell** (0% → ~50%)
    - Test configuration generation
    - Mock shell execution
    - Estimated time: 1.5 hours

## Testing Strategy

### 1. Standard Test Pattern
```go
func TestFunctionName(t *testing.T) {
    tests := map[string]struct {
        name     string
        input    InputType
        want     OutputType
        wantErr  bool
        setup    func()
        teardown func()
    }{
        "success case": {
            input: validInput,
            want:  expectedOutput,
        },
        "error case": {
            input:   invalidInput,
            wantErr: true,
        },
    }
    
    for name, tt := range tests {
        t.Run(name, func(t *testing.T) {
            if tt.setup != nil {
                tt.setup()
            }
            if tt.teardown != nil {
                defer tt.teardown()
            }
            
            got, err := FunctionName(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("FunctionName() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("FunctionName() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### 2. Mock Patterns

#### For exec.Command
```go
// Save and restore
oldExecCommand := execCommand
defer func() { execCommand = oldExecCommand }()

execCommand = func(name string, args ...string) *exec.Cmd {
    if name == "expected-command" {
        return exec.Command("echo", "mocked output")
    }
    return exec.Command("false")
}
```

#### For os/user
```go
// In test file
type mockUser struct{}
func (m mockUser) Current() (*user.User, error) {
    return &user.User{Username: "testuser"}, nil
}
```

### 3. Test Data Management
- Use constants for repeated test values
- Create helper functions for complex test data
- Keep test data close to tests (not in separate files)

### 4. Coverage Goals
- Aim for 80% coverage per package
- 100% coverage for pure utility functions
- Focus on happy path + common error cases
- Skip UI/interactive code initially

## Implementation Plan

### Week 1: Foundation (Tiers 1-2)
- Day 1: env, constants, secure (2.5 hours)
- Day 2: totp completion (1 hour)
- Day 3: provider/aws completion (1.5 hours)
- Day 4: keychain completion (1 hour)
- Day 5: Review and refactor

### Week 2: Integration (Tiers 3-4)
- Day 1: cmd/sesh improvements (2 hours)
- Day 2: clipboard (1 hour)
- Day 3: setup helpers (2 hours)
- Day 4: subshell (1.5 hours)
- Day 5: Review and documentation

## Success Metrics
- Overall coverage: 40.1% → 70%+
- Zero-coverage packages: 5 → 0
- All critical business logic: >80% coverage
- Test execution time: <10 seconds

## Testing Commands
```bash
# Run specific package tests
go test -v ./internal/env

# Run with coverage for specific package
go test -cover -coverprofile=pkg.out ./internal/env
go tool cover -func=pkg.out

# Run all tests with our custom coverage
make coverage/func

# Watch mode for TDD
while true; do clear; go test ./internal/env; sleep 2; done
```