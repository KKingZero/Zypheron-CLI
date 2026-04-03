# Encryption Key Rotation - Quick Reference

## TL;DR

Versioned encryption prevents total data compromise if a single key leaks.

## Environment Setup

```bash
# Generate new key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set as V1
export BYOK_ENCRYPTION_KEY_V1="<generated_key>"

# Or add to .env
echo "BYOK_ENCRYPTION_KEY_V1=<generated_key>" >> .env
```

## Basic Usage

```python
from app.core.encryption import encrypt_api_key, decrypt_api_key

# Encrypt (uses current version)
encrypted = encrypt_api_key("sk-1234567890")

# Decrypt (auto-detects version)
plaintext = decrypt_api_key(encrypted)
```

## Key Rotation (90-180 days)

```bash
# 1. Generate new key
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. Add to environment (keep old keys!)
BYOK_ENCRYPTION_KEY_V1="<old_key>"  # Keep
BYOK_ENCRYPTION_KEY_V2="$NEW_KEY"   # New
BYOK_ENCRYPTION_KEY_CURRENT=2       # Use V2

# 3. Restart app

# 4. Re-encrypt existing data
python scripts/rotate_encryption_keys.py

# 5. Verify success
python scripts/rotate_encryption_keys.py --dry-run
```

## Emergency Rotation (Key Compromised)

```bash
# Generate new key immediately
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Add as next version
export BYOK_ENCRYPTION_KEY_V2="$NEW_KEY"
export BYOK_ENCRYPTION_KEY_CURRENT=2

# Restart and rotate NOW
python scripts/rotate_encryption_keys.py

# Remove compromised key after verification
```

## Version Format

```
v1:gAAAAABh...   (version 1)
v2:gAAAAABh...   (version 2)
gAAAAABh...      (legacy, assumes V1)
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BYOK_ENCRYPTION_KEY_V1` | Yes* | None | Version 1 key |
| `BYOK_ENCRYPTION_KEY_V2` | No | None | Version 2 key |
| `BYOK_ENCRYPTION_KEY_V3` | No | None | Version 3 key |
| `BYOK_ENCRYPTION_KEY_V4` | No | None | Version 4 key |
| `BYOK_ENCRYPTION_KEY_V5` | No | None | Version 5 key |
| `BYOK_ENCRYPTION_KEY_CURRENT` | No | Highest | Active version |
| `BYOK_ENCRYPTION_KEY` (legacy) | Yes* | None | Treated as V1 |

*At least one key required (V1 or legacy)

## Rotation Script Options

```bash
# Test without changes
python scripts/rotate_encryption_keys.py --dry-run

# Rotate with custom batch size
python scripts/rotate_encryption_keys.py --batch-size 50

# Full rotation
python scripts/rotate_encryption_keys.py
```

## Common Scenarios

### New Installation

```bash
# Generate V1 key
export BYOK_ENCRYPTION_KEY_V1="<generated_key>"
# Done!
```

### Migrate from Legacy

```bash
# Old
BYOK_ENCRYPTION_KEY="<old_key>"

# New (keep both during transition)
BYOK_ENCRYPTION_KEY="<old_key>"      # Legacy compat
BYOK_ENCRYPTION_KEY_V1="<old_key>"   # Same as V1
BYOK_ENCRYPTION_KEY_V2="<new_key>"   # New rotation
BYOK_ENCRYPTION_KEY_CURRENT=2

# Rotate, then remove legacy key
```

### Add New Version

```bash
# Current: V1, V2 active
# Add V3
BYOK_ENCRYPTION_KEY_V3="<new_key>"
BYOK_ENCRYPTION_KEY_CURRENT=3

# Restart + rotate
python scripts/rotate_encryption_keys.py
```

## Monitoring

```python
from app.core.encryption import get_encryption_service

service = get_encryption_service()

# Check active version
print(f"Current: {service.current_version}")

# Check available versions
print(f"Available: {service.available_versions}")

# Check if data needs rotation
needs_rotation = service.needs_re_encryption(encrypted_data)
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| "No encryption keys configured" | No keys set | Set `BYOK_ENCRYPTION_KEY_V1` |
| "version X not available" | Missing key version | Add missing `BYOK_ENCRYPTION_KEY_VX` |
| "Invalid token" | Wrong key | Restore correct key from backup |

## Security Checklist

- ✅ Store keys in secrets manager (not in code)
- ✅ Rotate keys every 90-180 days
- ✅ Keep old keys during rotation (for decryption)
- ✅ Test rotation with `--dry-run` first
- ✅ Monitor decryption failures
- ✅ Remove old keys only after full migration

## Links

- Full guide: `ENCRYPTION_KEY_ROTATION.md`
- Remediation docs: `CRITICAL-7-REMEDIATION.md`
- Tests: `tests/test_versioned_encryption.py`
- Rotation script: `scripts/rotate_encryption_keys.py`

---

**Remember**: Old keys must be available to decrypt historical data. Never remove a key version until all data is migrated.
