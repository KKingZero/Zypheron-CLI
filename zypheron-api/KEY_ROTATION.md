# Encryption Key Rotation

Zypheron API uses versioned Fernet encryption keys to protect stored BYOK API keys. Multiple key versions allow rotation without losing access to previously encrypted data.

## How It Works

Encrypted data is prefixed with its version:

```
v1:gAAAAABh...   (version 1)
v2:gAAAAABh...   (version 2)
gAAAAABh...      (legacy, treated as V1)
```

- New data is always encrypted with the current version
- Decryption auto-detects the version from the prefix
- Old key versions must remain available until all data is re-encrypted

## Configuration

```bash
# Versioned keys (up to 5)
BYOK_ENCRYPTION_KEY_V1="<fernet_key>"
BYOK_ENCRYPTION_KEY_V2="<fernet_key>"
BYOK_ENCRYPTION_KEY_CURRENT=2          # Use V2 for new encryptions

# Legacy single key (treated as V1)
BYOK_ENCRYPTION_KEY="<fernet_key>"
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BYOK_ENCRYPTION_KEY_V1` | Yes* | None | Version 1 key |
| `BYOK_ENCRYPTION_KEY_V2`-`V5` | No | None | Additional versions |
| `BYOK_ENCRYPTION_KEY_CURRENT` | No | Highest | Active version for encryption |
| `BYOK_ENCRYPTION_KEY` (legacy) | Yes* | None | Treated as V1 |

*At least one key (V1 or legacy) is required.

### Generate a Key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Rotation Procedure

### 1. Generate new key and add to environment

```bash
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Add to .env (keep old keys)
BYOK_ENCRYPTION_KEY_V1="<old_key>"
BYOK_ENCRYPTION_KEY_V2="$NEW_KEY"
BYOK_ENCRYPTION_KEY_CURRENT=2
```

### 2. Restart the application

New data will use V2. Old data still decryptable via V1.

### 3. Re-encrypt existing data

```bash
# Dry run first
python scripts/rotate_encryption_keys.py --dry-run

# Actual rotation
python scripts/rotate_encryption_keys.py

# Custom batch size
python scripts/rotate_encryption_keys.py --batch-size 50
```

### 4. Remove old key (only after all data is migrated)

Verify with `--dry-run` that no old-version data remains, then remove the old key from your environment.

## Emergency Rotation (Key Compromised)

```bash
# 1. Generate and deploy new key immediately
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export BYOK_ENCRYPTION_KEY_V2="$NEW_KEY"
export BYOK_ENCRYPTION_KEY_CURRENT=2

# 2. Restart application

# 3. Re-encrypt ALL data now
python scripts/rotate_encryption_keys.py

# 4. Remove compromised key after verification
```

## Python API

```python
from app.core.encryption import encrypt_api_key, decrypt_api_key, get_encryption_service

# Encrypt (uses current version)
encrypted = encrypt_api_key("sk-1234567890")

# Decrypt (auto-detects version)
plaintext = decrypt_api_key(encrypted)

# Check service state
service = get_encryption_service()
service.current_version      # e.g., 2
service.available_versions   # e.g., [1, 2]
service.needs_re_encryption(encrypted_data)  # True if not current version
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| "No encryption keys configured" | No keys in env | Set `BYOK_ENCRYPTION_KEY_V1` |
| "version X not available" | Missing key version | Add `BYOK_ENCRYPTION_KEY_VX` |
| "Invalid token for key version X" | Wrong key for version | Restore correct key from backup |

## Best Practices

- Rotate keys every 90-180 days
- Store keys in a secrets manager (not in code)
- Always test rotation with `--dry-run` first
- Keep old keys available until re-encryption is verified complete
- Monitor decryption failures in logs

## Key Files

- Encryption service: `app/core/encryption.py`
- Rotation script: `scripts/rotate_encryption_keys.py`
- Tests: `tests/test_versioned_encryption.py`
