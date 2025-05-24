# Provider Consistency TODOs

## Issues Found Between AWS and TOTP Providers

### 1. Flag Validation Inconsistency ✓ RESOLVED
- **AWS Provider**: Uses direct `flag.Lookup()` to validate flags (lines 87-90, 162-165 in aws/provider.go)
- **TOTP Provider**: No equivalent validation for AWS-specific flags
- **Resolution**: No action needed. Investigation revealed:
  - TOTP does accept `--profile` flag (line 64 in totp/provider.go) for multiple accounts
  - There are no AWS-specific flags that TOTP needs to validate against
  - The `--profile` flag is used by both providers (different purposes)
  - AWS's validation of `--service-name` is appropriate since it's TOTP-specific

### 2. Service Key Building Pattern ✓ RESOLVED
- **AWS Provider**: Hardcoded service key logic scattered in multiple places (lines 94-99, 417-423, 442-448)
- **TOTP Provider**: Clean helper function `buildServiceKey()` (line 208)
- **Fix**: AWS should use a consistent helper function like TOTP does
- **Resolution**: Added `buildServiceKey()` helper function to AWS provider (line 481) and refactored all 3 occurrences to use it

### 3. User Retrieval Pattern ✓ RESOLVED
- **AWS Provider**: Sets `p.keyUser` in `SetupFlags()` (lines 69-74)
- **TOTP Provider**: Uses `getCurrentUser()` helper and handles it in `DeleteEntry()` (lines 186-192)
- **Fix**: Standardize on one pattern across both providers
- **Resolution**: Refactored TOTP to follow AWS's pattern:
  - Removed legacy `--keychain-user` flag
  - Removed `SESH_TOTP_KEYCHAIN_NAME` env var and `--keychain-name` flag
  - Set `p.keyUser` in `SetupFlags()` using `env.GetCurrentUser()`
  - Removed `getCurrentUser()` helper function
  - Updated `DeleteEntry()` to use `p.keyUser` directly
  - Removed `keyName` field and used `constants.TOTPServicePrefix` throughout

### 4. Error Context Richness ✓ RESOLVED
- **AWS Provider**: Rich error context with retry logic and detailed messaging (lines 196-263)
- **TOTP Provider**: Basic error messages
- **Consider**: Whether TOTP needs similar retry/context logic
- **Resolution**: 
  - TOTP's simpler error handling is appropriate (no retry needed since it only generates codes)
  - Standardized error message consistency between providers:
    - All user retrieval errors now use "failed to get current user"
    - All secret retrieval errors now use "failed to retrieve TOTP secret" with context
    - Changed "could not" to "failed to" for consistency across providers
    - Both providers already consistent on "could not generate TOTP codes"

### 5. Profile Handling Complexity ✓ RESOLVED
- **AWS Provider**: Complex profile logic scattered throughout multiple methods
- **TOTP Provider**: Clean profile parameter in `buildServiceKey()`
- **Fix**: Consolidate AWS profile logic into helper functions
- **Resolution**: Created comprehensive helper functions to consolidate all profile logic:
  - Added `formatProfile()` for consistent user-facing display ("profile (default)")
  - Added `parseServiceKey()` to complement `buildServiceKey()` for parsing service keys
  - Refactored all scattered profile formatting to use the single `formatProfile()` helper
  - Fixed manual key building to always use `buildServiceKey()`
  - Refactored `ListEntries()` to use the new helpers
  - Eliminated all magic strings and duplicate profile logic

### 6. Secret Validation ✓ ALREADY CONSISTENT
- **AWS Provider**: Basic length check only (lines 120-123)
- **TOTP Provider**: None - should use `totp.ValidateAndNormalizeSecret()`
- **Fix**: TOTP should validate secrets using the validation function we created
- **Resolution**: Both providers already validate consistently:
  - Both AWS and TOTP setup use `ValidateAndNormalizeSecret()` (lines 443 & 625 in setup.go)
  - Validation happens at setup time when secrets are first stored
  - Runtime validation is unnecessary since secrets are pre-validated
  - AWS's runtime length check is just a warning, not validation
  - Both providers handle validation errors the same way during setup

### 7. Method Organization ✓ RESOLVED
- **AWS Provider**: Has both `GetMFASerial()` and `GetMFASerialBytes()` methods
- **TOTP Provider**: Single clean methods for each purpose
- **Consider**: Whether AWS needs both or can consolidate
- **Resolution**: Removed `GetMFASerial()` entirely from the codebase:
  - Removed from keychain interface and implementations
  - Removed from AWS provider (was just a compatibility wrapper)
  - Updated all tests to use the secure `GetMFASerialBytes()` method
  - Removed from all mock implementations
  - Now only the secure bytes version exists, improving security and consistency

### 8. Flag Setup Error Handling ✓ RESOLVED
- **AWS Provider**: Returns actual errors from `SetupFlags()` (line 74)
- **TOTP Provider**: Always returns `nil` (line 71)
- **Fix**: TOTP should handle potential errors in flag setup
- **Resolution**: Already fixed when refactoring user retrieval pattern in item #3
  - TOTP now returns error from `SetupFlags()` if `env.GetCurrentUser()` fails (line 64)
  - Matches AWS provider's error handling pattern

## Priority
These are code quality/consistency improvements rather than functional bugs. The providers work correctly as-is, but standardizing patterns would improve maintainability.

## Files Affected
- `/internal/provider/aws/provider.go`
- `/internal/provider/totp/provider.go`