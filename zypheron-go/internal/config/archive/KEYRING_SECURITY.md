# Keyring Security Documentation

## Overview

The Zypheron CLI keyring system provides secure, cross-platform API key storage using the operating system's native credential management system. This document describes the security measures implemented and best practices for usage.

## Security Features

### 1. System Keyring Integration

- **Linux**: Uses Secret Service API (GNOME Keyring, KWallet)
- **macOS**: Uses Keychain
- **Windows**: Uses Credential Manager

All credentials are encrypted at rest using OS-native encryption mechanisms.

### 2. Input Validation

#### Provider Name Validation
```go
// Prevents injection attacks and ensures only valid providers
func validateProvider(provider string) error
```

**Security measures:**
- Whitelist-based validation (only known providers accepted)
- Case-insensitive normalization prevents bypass attempts
- Whitespace trimming prevents padding attacks
- Empty string rejection

#### API Key Validation
```go
// Ensures non-empty keys to prevent logic errors
if key == "" {
    return ErrInvalidKey
}
```

**Security measures:**
- Rejects empty keys to prevent accidental misconfiguration
- No maximum length to support all provider key formats
- Keys are never logged or printed (prevents credential leaks)

### 3. Environment Variable Fallback

When the system keyring is unavailable (headless servers, missing keyring services), the system gracefully falls back to environment variables.

**Security considerations:**
- Environment variables are process-scoped (less secure than keyring)
- Clear error messages guide users to set appropriate env vars
- Dual-source checking (keyring first, then env vars)

**Environment variable mapping:**
```
deepseek     -> DEEPSEEK_API_KEY
anthropic    -> ANTHROPIC_API_KEY
openai       -> OPENAI_API_KEY
supabase_url -> SUPABASE_URL
supabase_key -> SUPABASE_KEY
```

### 4. Error Handling

**Secure error handling principles:**
- Never leak sensitive data in error messages
- Distinguish between "not found" and "access denied"
- Provide actionable guidance without exposing internals

```go
// Good: Indicates issue without exposing key
return fmt.Errorf("failed to store API key in keyring: %w", err)

// Bad: Would expose the key value
// return fmt.Errorf("failed to store key %s: %w", key, err)
```

### 5. Thread Safety

The keyring availability check uses `sync.Once` to prevent race conditions:

```go
var keyringAvailableOnce sync.Once

func checkKeyringAvailability() bool {
    keyringAvailableOnce.Do(func() {
        // Test keyring once, cache result
    })
    return keyringAvailable
}
```

**Security benefits:**
- Prevents TOCTOU (Time-Of-Check-Time-Of-Use) vulnerabilities
- Atomic initialization ensures consistent state
- No race conditions in concurrent access

### 6. Defense in Depth

Multiple layers of validation and error checking:

1. **Provider validation** - Ensure only valid providers
2. **Key validation** - Ensure non-empty keys
3. **Keyring availability check** - Graceful degradation
4. **Error propagation** - Meaningful errors without data leaks
5. **Idempotent operations** - Delete returns success even if key missing

## Usage Examples

### Storing an API Key

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"

err := config.SetAPIKey(config.ProviderDeepSeek, "sk-1234567890abcdef")
if err != nil {
    // Handle error - might indicate keyring unavailable
    log.Fatalf("Failed to store API key: %v", err)
}
```

### Retrieving an API Key

```go
key, err := config.GetAPIKey(config.ProviderAnthropic)
if err != nil {
    if err == config.ErrKeyNotFound {
        // Prompt user to configure key
        return fmt.Errorf("Anthropic API key not configured")
    }
    return fmt.Errorf("Failed to retrieve key: %w", err)
}

// Use key - NEVER log or print it
client := anthropic.NewClient(key)
```

### Checking Key Existence

```go
if !config.HasAPIKey(config.ProviderOpenAI) {
    fmt.Println("OpenAI API key not configured")
    fmt.Println("Run: zypheron config set-key openai")
}
```

### Listing Configured Providers

```go
providers := config.ListProviders()
fmt.Printf("Configured providers (%d):\n", len(providers))
for _, provider := range providers {
    fmt.Printf("  - %s ✓\n", provider)
}
```

### Deleting an API Key

```go
err := config.DeleteAPIKey(config.ProviderSupabaseKey)
if err != nil {
    log.Printf("Warning: Failed to delete key: %v", err)
}
```

## Security Best Practices

### For CLI Users

1. **Always use keyring when available**
   - More secure than environment variables
   - Credentials encrypted at rest
   - Per-user isolation

2. **Use environment variables for CI/CD**
   - Set `DEEPSEEK_API_KEY` etc. in pipeline secrets
   - Never commit `.env` files to version control
   - Rotate keys regularly

3. **Protect your environment**
   - Limit shell history exposure (`export HISTIGNORE="*API_KEY*"`)
   - Use `.env` files with restricted permissions (0600)
   - Never share terminal output containing credentials

### For Developers

1. **Never log API keys**
   ```go
   // NEVER do this:
   log.Printf("Using API key: %s", key)

   // Instead:
   log.Printf("API key loaded successfully")
   ```

2. **Zero sensitive memory after use**
   ```go
   // For highly sensitive operations, zero the key
   defer func() {
       for i := range keyBytes {
           keyBytes[i] = 0
       }
   }()
   ```

3. **Validate keys before use**
   ```go
   key, err := config.GetAPIKey(provider)
   if err != nil {
       return err // Don't proceed with invalid/missing key
   }
   ```

4. **Check keyring availability**
   ```go
   if !config.IsKeyringAvailable() {
       fmt.Println("Warning: Using environment variables (less secure)")
   }
   ```

## Threat Model

### Protected Against

1. **Credential Theft via Filesystem**
   - Keys not stored in plaintext files
   - System keyring uses OS-level encryption

2. **Injection Attacks**
   - Provider name whitelist validation
   - No command execution or SQL-like operations

3. **Timing Attacks**
   - Provider validation uses consistent-time checks
   - No early returns based on secret values

4. **Race Conditions**
   - Thread-safe keyring availability check
   - Atomic operations where applicable

5. **Error Information Leakage**
   - Errors never contain key values
   - Generic error messages prevent enumeration

### Not Protected Against

1. **Memory Dumps**
   - Keys exist in memory as Go strings (immutable)
   - OS-level memory protection required

2. **Malicious Code in Same Process**
   - If attacker has code execution, they can call `GetAPIKey()`
   - Rely on OS process isolation

3. **Keyring Malware**
   - If OS keyring is compromised, keys are exposed
   - Trust OS security mechanisms

4. **Physical Access**
   - Unlocked workstation allows keyring access
   - Lock your screen when away

5. **Environment Variable Exposure**
   - `ps aux` may show env vars on some systems
   - Container/process isolation required

## Compliance Considerations

### OWASP Guidelines

- **A02:2021 – Cryptographic Failures**: Uses OS-native encryption
- **A04:2021 – Insecure Design**: Defense in depth, input validation
- **A05:2021 – Security Misconfiguration**: Secure defaults (keyring over env vars)
- **A07:2021 – Identification and Authentication Failures**: Secure credential storage

### Best Practices

- **PCI DSS**: Encrypted credential storage (keyring)
- **GDPR**: No credential logging, secure deletion support
- **SOC 2**: Audit trail via OS keyring logs (OS-level)

## Troubleshooting

### Keyring Not Available

**Symptom**: `SetAPIKey()` returns "system keyring unavailable"

**Solutions**:
1. **Linux**: Install `gnome-keyring` or `kwallet`
2. **Headless Server**: Use environment variables instead
3. **Docker**: Set env vars in container configuration

### Key Not Found

**Symptom**: `GetAPIKey()` returns `ErrKeyNotFound`

**Solutions**:
1. Verify key is set: `config.HasAPIKey(provider)`
2. Check environment variable is set
3. Re-run setup: `zypheron config set-key <provider>`

### Permission Denied

**Symptom**: Keyring operations fail with permission errors

**Solutions**:
1. **Linux**: Unlock keyring (may require desktop login)
2. **macOS**: Grant Keychain access in System Preferences
3. **Windows**: Run as correct user (not admin unless necessary)

## Testing

Run the test suite:

```bash
cd /home/zero/Downloads/Zypheron\ project/Zypheron-CLI-Production/zypheron-go
go test ./internal/config/... -v
```

Test coverage includes:
- Provider validation
- Set/get/delete operations
- Environment variable fallback
- Error handling
- Thread safety (keyring availability check)

## Future Enhancements

Potential security improvements:

1. **Key Rotation Support**
   - Store key version metadata
   - Automatic rotation reminders

2. **Audit Logging**
   - Log key access events (without key values)
   - Integration with SIEM systems

3. **Multi-Factor Protection**
   - Require additional authentication for key retrieval
   - Hardware key support (YubiKey, etc.)

4. **Encrypted Environment Variable Fallback**
   - Encrypt env vars with user-specific key
   - Prevents process memory inspection

5. **Key Expiration**
   - Set TTL for API keys
   - Force renewal after expiration

## References

- [Zalando go-keyring](https://github.com/zalando/go-keyring) - Cross-platform keyring library
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines
