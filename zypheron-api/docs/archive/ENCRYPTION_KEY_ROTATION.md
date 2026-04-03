# Encryption Key Rotation Guide

## Overview

Zypheron API implements **versioned encryption key rotation** to protect BYOK (Bring Your Own Key) API keys from total compromise. This feature allows you to rotate encryption keys without losing access to encrypted data.

## Security Benefits

### Before (CRITICAL-7 Vulnerability)
- **Single encryption key** - compromise decrypts ALL historical data
- **No rotation mechanism** - stuck with same key forever
- **Total data exposure** on key leak

### After (Fixed)
- **5 versioned keys** - compromise only affects data encrypted with that version
- **Graceful rotation** - decrypt old data, encrypt new data with latest key
- **Limited blast radius** - only data encrypted with compromised key is exposed

## Key Concepts

### Version Format

Encrypted data is prefixed with its version:

```
v1:gAAAAABh... (encrypted with V1 key)
v2:gAAAAABh... (encrypted with V2 key)
gAAAAABh...     (legacy format, assumed V1)
```

### Rotation Strategy

1. **Backward compatibility**: Can decrypt data from all available key versions (1-5)
2. **Forward encryption**: Always encrypts new data with the current version
3. **Gradual migration**: Re-encrypt old data incrementally with rotation script

## Configuration

### Environment Variables

#### Versioned Keys (Recommended)

```bash
# Key versions (Fernet base64-encoded keys)
BYOK_ENCRYPTION_KEY_V1="KEY_VERSION_1_HERE"
BYOK_ENCRYPTION_KEY_V2="KEY_VERSION_2_HERE"
BYOK_ENCRYPTION_KEY_V3="KEY_VERSION_3_HERE"
BYOK_ENCRYPTION_KEY_V4="KEY_VERSION_4_HERE"
BYOK_ENCRYPTION_KEY_V5="KEY_VERSION_5_HERE"

# Current version for new encryptions (optional - defaults to highest)
BYOK_ENCRYPTION_KEY_CURRENT=2
```

#### Legacy Single Key (Deprecated)

```bash
# Treated as V1 for backward compatibility
BYOK_ENCRYPTION_KEY="LEGACY_KEY_HERE"
```

### Generating Keys

```bash
# Generate a new Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Example output:
```
Zvx8YBE3mT4qC0p9JKL2NwR5Xz7FhGvU6sA1bD8eM3k=
```

## Key Rotation Procedure

### Step 1: Generate New Key

```bash
# Generate new key (V2)
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
echo "BYOK_ENCRYPTION_KEY_V2=$NEW_KEY"
```

### Step 2: Update Environment Variables

Add the new key while **keeping old keys**:

```bash
# .env or environment
BYOK_ENCRYPTION_KEY_V1="OLD_KEY_KEEP_THIS"  # Keep for decrypting old data
BYOK_ENCRYPTION_KEY_V2="NEW_KEY_HERE"       # New key for encryption
BYOK_ENCRYPTION_KEY_CURRENT=2               # Use V2 for new data
```

### Step 3: Restart Application

```bash
# Application will now:
# - Encrypt new data with V2
# - Decrypt existing data with V1 or V2 (automatic detection)
```

### Step 4: Re-encrypt Existing Data (Optional but Recommended)

```bash
# Test rotation first (dry run)
python scripts/rotate_encryption_keys.py --dry-run

# Perform actual rotation
python scripts/rotate_encryption_keys.py

# With custom batch size
python scripts/rotate_encryption_keys.py --batch-size 50
```

**Output Example:**

```
2026-01-03 12:00:00 - Starting encryption key rotation
2026-01-03 12:00:00 - Current encryption version: 2
2026-01-03 12:00:00 - Available key versions: [1, 2]
2026-01-03 12:00:00 - Found 150 API keys to check
2026-01-03 12:00:05 - Committed batch of 100 keys
2026-01-03 12:00:06 - Committed final batch of 50 keys

============================================================
Key Rotation Summary
============================================================
Total keys checked:      150
Already current version: 0
Needed rotation:         150
Successfully rotated:    150
Errors:                  0
============================================================
Rotation completed successfully
```

### Step 5: Remove Old Key (After Verification)

**CRITICAL**: Only remove old keys after ALL data is re-encrypted.

```bash
# After successful rotation, remove old V1 key
# BYOK_ENCRYPTION_KEY_V1=""  # Remove this line
BYOK_ENCRYPTION_KEY_V2="CURRENT_KEY"
BYOK_ENCRYPTION_KEY_CURRENT=2
```

## Rotation Scenarios

### Scenario 1: First-Time Setup (New Installation)

```bash
# Generate initial key
BYOK_ENCRYPTION_KEY_V1=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# No need to set BYOK_ENCRYPTION_KEY_CURRENT (defaults to V1)
```

### Scenario 2: Migrate from Legacy Single Key

```bash
# Old setup
BYOK_ENCRYPTION_KEY="LEGACY_KEY"

# New setup (legacy key becomes V1)
BYOK_ENCRYPTION_KEY="LEGACY_KEY"          # Keep for backward compatibility
BYOK_ENCRYPTION_KEY_V1="LEGACY_KEY"       # Explicit V1 (optional but recommended)
BYOK_ENCRYPTION_KEY_V2="NEW_KEY"          # New key
BYOK_ENCRYPTION_KEY_CURRENT=2             # Use V2 for new encryptions
```

### Scenario 3: Suspected Key Compromise

```bash
# Immediate rotation
# 1. Generate new key
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. Add as next version (keep compromised key temporarily)
BYOK_ENCRYPTION_KEY_V1="COMPROMISED_KEY_KEEP_TEMPORARILY"
BYOK_ENCRYPTION_KEY_V2="$NEW_KEY"
BYOK_ENCRYPTION_KEY_CURRENT=2

# 3. Restart application (new data uses V2)

# 4. Re-encrypt ALL data immediately
python scripts/rotate_encryption_keys.py

# 5. Remove compromised key after verification
# BYOK_ENCRYPTION_KEY_V1=""  # Remove completely
```

### Scenario 4: Scheduled Regular Rotation (Best Practice)

Rotate keys every 90-180 days:

```bash
# Quarter 1: V1
BYOK_ENCRYPTION_KEY_V1="Q1_KEY"

# Quarter 2: Add V2, rotate
BYOK_ENCRYPTION_KEY_V1="Q1_KEY"
BYOK_ENCRYPTION_KEY_V2="Q2_KEY"
BYOK_ENCRYPTION_KEY_CURRENT=2
# Run: python scripts/rotate_encryption_keys.py

# Quarter 3: Add V3, rotate, remove V1
BYOK_ENCRYPTION_KEY_V2="Q2_KEY"
BYOK_ENCRYPTION_KEY_V3="Q3_KEY"
BYOK_ENCRYPTION_KEY_CURRENT=3
# Run: python scripts/rotate_encryption_keys.py

# Repeat pattern (max 5 versions)
```

## API Usage

### Encrypt/Decrypt (Automatic Versioning)

```python
from app.core.encryption import encrypt_api_key, decrypt_api_key

# Encrypt (uses current version automatically)
encrypted = encrypt_api_key("sk-1234567890abcdef")
# Returns: "v2:gAAAAABh..."

# Decrypt (detects version automatically)
plaintext = decrypt_api_key("v2:gAAAAABh...")
# Returns: "sk-1234567890abcdef"

# Also decrypts legacy format
plaintext = decrypt_api_key("gAAAAABh...")  # Assumes V1
```

### Advanced Usage

```python
from app.core.encryption import get_encryption_service

service = get_encryption_service()

# Check current version
print(f"Current version: {service.current_version}")
# Output: Current version: 2

# Check available versions
print(f"Available: {service.available_versions}")
# Output: Available: [1, 2, 3]

# Check if re-encryption needed
if service.needs_re_encryption(encrypted_data):
    new_encrypted = service.re_encrypt(encrypted_data)
```

## Monitoring and Verification

### Check Version Distribution

```python
from sqlalchemy import select, func
from app.models.user_api_key import UserAPIKey

# Count keys by version
stmt = select(
    func.substr(UserAPIKey.encrypted_key, 1, 3).label("version_prefix"),
    func.count().label("count")
).group_by("version_prefix")

results = await session.execute(stmt)
for row in results:
    print(f"{row.version_prefix}: {row.count} keys")

# Output:
# v1: 50 keys   (old version)
# v2: 100 keys  (current version)
# gAA: 10 keys  (legacy format)
```

### Verify Rotation Success

```bash
# Check logs for errors
grep "Encryption failed" /var/log/zypheron-api.log

# Verify no old versions remain
python scripts/rotate_encryption_keys.py --dry-run
```

## Security Best Practices

1. **Store keys securely**: Use secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
2. **Rotate regularly**: Schedule rotations every 90-180 days
3. **Monitor access**: Log all decryption operations
4. **Audit trail**: Track which keys are used when
5. **Backup keys**: Keep encrypted backups of old keys (you may need to decrypt historical data)
6. **Immediate rotation on compromise**: Don't wait for scheduled rotation if breach suspected

## Troubleshooting

### Error: "Encryption key version X not available"

**Cause**: Trying to decrypt data with a key version that's no longer configured.

**Solution**: Add the missing key version back:

```bash
BYOK_ENCRYPTION_KEY_V1="MISSING_KEY_HERE"
```

### Error: "Invalid token for key version X"

**Cause**: Wrong key for that version (key was changed incorrectly).

**Solution**: Restore correct key for that version from backup.

### Error: "No encryption keys configured"

**Cause**: No keys set in environment variables.

**Solution**: Set at least one key:

```bash
BYOK_ENCRYPTION_KEY_V1="YOUR_KEY_HERE"
```

## Migration Path

### From Single Key to Versioned Keys

```bash
# 1. Current state (single key)
BYOK_ENCRYPTION_KEY="CURRENT_KEY"

# 2. Transition state (both legacy and V1)
BYOK_ENCRYPTION_KEY="CURRENT_KEY"       # Keep for backward compat
BYOK_ENCRYPTION_KEY_V1="CURRENT_KEY"    # Same key as V1
BYOK_ENCRYPTION_KEY_V2="NEW_KEY"        # New rotation key
BYOK_ENCRYPTION_KEY_CURRENT=2

# 3. Restart application

# 4. Run rotation script
python scripts/rotate_encryption_keys.py

# 5. Final state (versioned only)
BYOK_ENCRYPTION_KEY_V2="NEW_KEY"
# Remove BYOK_ENCRYPTION_KEY (no longer needed)
```

## Performance Considerations

- **Encryption overhead**: ~0.1ms per operation (negligible)
- **Rotation time**: ~100 keys/second (depends on database)
- **Batch processing**: Adjust `--batch-size` based on database load
- **Zero downtime**: Application continues serving requests during rotation

## Compliance

This encryption key rotation mechanism helps meet compliance requirements:

- **PCI-DSS**: Requires key rotation for card data encryption
- **HIPAA**: Recommends periodic key rotation for PHI
- **SOC 2**: Key rotation demonstrates security controls
- **GDPR**: Supports data protection by design principles

## References

- [Cryptography.io - Fernet](https://cryptography.io/en/latest/fernet/)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP - Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
