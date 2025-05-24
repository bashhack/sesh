# Error Message Consistency Analysis: AWS vs TOTP Providers

## 1. Getting Current User Errors

### AWS Provider (line 71)
```go
return fmt.Errorf("failed to get current user: %w", err)
```

### TOTP Provider (line 64)  
```go
return fmt.Errorf("failed to get current user: %w", err)
```

**Status:** ✅ CONSISTENT

## 2. Keychain Retrieval Errors (GetSecret)

### AWS Provider (line 98)
```go
return "", "", 0, fmt.Errorf("could not retrieve TOTP secret: %w", err)
```

### TOTP Provider (line 89)
```go
return provider.Credentials{}, fmt.Errorf("could not retrieve TOTP secret for %s: %w", p.serviceName, err)
```

**Status:** ❌ INCONSISTENT
- AWS uses "could not retrieve"
- TOTP includes service name in error message
- Different context provided

## 3. TOTP Generation Errors

### AWS Provider (line 123)
```go
return "", "", 0, fmt.Errorf("could not generate TOTP codes: %w", err)
```

### TOTP Provider (line 103)
```go
return provider.Credentials{}, fmt.Errorf("could not generate TOTP codes: %w", err)
```

**Status:** ✅ CONSISTENT (same error message)

## 4. Listing Entries Errors

### AWS Provider (line 294)
```go
return nil, fmt.Errorf("failed to list AWS entries: %w", err)
```

### TOTP Provider (line 140)
```go
return nil, fmt.Errorf("failed to list TOTP entries: %w", err)
```

**Status:** ✅ CONSISTENT (pattern is the same)

## 5. Delete Entry Errors

### AWS Provider
- Line 372: `fmt.Errorf("invalid entry ID format: expected 'service:account', got %q", id)`
- Line 379: `fmt.Errorf("failed to delete AWS entry: %w", err)`

### TOTP Provider
- Line 177: `fmt.Errorf("invalid entry ID format: expected 'service:account', got %q", id)`
- Line 187: `fmt.Errorf("failed to delete TOTP entry: %w", err)`

**Status:** ✅ CONSISTENT (pattern is the same)

## 6. Additional AWS-specific Errors

### MFA Device Detection (line 447)
```go
return nil, fmt.Errorf("could not detect MFA device: %w", err)
```

### User Determination (lines 406, 427)
```go
return "", "", fmt.Errorf("could not determine current user: %w", err)
```

**Status:** ❌ INCONSISTENT with "failed to get current user" used elsewhere

## 7. Service Name Flag Validation

### AWS Provider (lines 89, 158)
```go
fmt.Errorf("the --service-name flag is only valid with the TOTP provider, not AWS")
```

### TOTP Provider (line 78)
```go
fmt.Errorf("service name is required, use --service-name flag")
```

**Status:** ✅ CONSISTENT (appropriate for each context)

## Key Inconsistencies Found:

1. **"could not" vs "failed to"**: AWS provider uses "could not" in several places while both providers use "failed to" in others. Should standardize.

2. **Context inclusion**: TOTP provider includes service name in secret retrieval error, AWS doesn't include profile name in similar error.

3. **User error messages**: AWS has two different error messages for user-related errors:
   - "failed to get current user" (in SetupFlags)
   - "could not determine current user" (in GetTOTPKeyInfo/GetMFASerialBytes)

## Recommendations:

1. Standardize on either "failed to" or "could not" across both providers
2. Include relevant context (profile/service name) consistently in error messages
3. Use consistent error messages for the same underlying operation (e.g., getting current user)
4. Consider creating shared error message constants or functions for common operations