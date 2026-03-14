"""Encryption utilities for securely storing sensitive data.

SECURITY FIX (CRYPTO-H1): Upgraded to AES-256-GCM from Fernet (AES-128-CBC).

Encryption methods:
- NEW: AES-256-GCM (authenticated encryption, stronger security)
- LEGACY: Fernet (AES-128-CBC) - read-only for backward compatibility

Format:
- NEW: "gcm:v{version}:{nonce_b64}:{ciphertext_b64}"
- LEGACY: "v{version}:{fernet_ciphertext}" or raw Fernet ciphertext

Key versioning:
- Supports up to 5 key versions for rotation without data loss
- Single key compromise only exposes data encrypted with that version
- Re-encryption can migrate legacy Fernet data to AES-256-GCM
"""

import base64
import structlog
import os
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

logger = structlog.get_logger()

# Maximum supported key versions for rotation
MAX_KEY_VERSIONS = 5

# AES-256-GCM constants
AES_GCM_KEY_SIZE = 32  # 256 bits
AES_GCM_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
AES_GCM_PREFIX = "gcm"  # Prefix to identify new encryption format


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""

    pass


class VersionedEncryptionService:
    """Encryption service with AES-256-GCM and legacy Fernet support.

    SECURITY FIX (CRYPTO-H1): Upgraded to AES-256-GCM from Fernet.

    Features:
    - NEW encryption uses AES-256-GCM (stronger, authenticated)
    - LEGACY decryption supports Fernet (AES-128-CBC) for backward compatibility
    - Key versioning (up to 5 versions) for safe rotation

    Key format in environment variables:
    - BYOK_ENCRYPTION_KEY_GCM_V1=<64-char hex string> (32 bytes = 256 bits)
    - BYOK_ENCRYPTION_KEY_V1=<fernet_key> (legacy, read-only)
    - BYOK_ENCRYPTION_KEY_CURRENT=1 (which version to use)

    Generate AES-256 key: python -c "import secrets; print(secrets.token_hex(32))"
    """

    _instance: Optional["VersionedEncryptionService"] = None

    def __new__(cls) -> "VersionedEncryptionService":
        """Singleton pattern to ensure single instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize encryption service with AES-256-GCM and legacy Fernet keys.

        Raises:
            EncryptionError: If no valid encryption keys are configured
        """
        if self._initialized:
            return

        settings = get_settings()

        # NEW: AES-256-GCM keys (used for encryption)
        self._gcm_keys: dict[int, AESGCM] = {}
        # LEGACY: Fernet keys (used only for decryption of old data)
        self._fernet_keys: dict[int, Fernet] = {}
        self._current_version: int = 1

        # Load AES-256-GCM keys (BYOK_ENCRYPTION_KEY_GCM_V1, V2, etc.)
        for version in range(1, MAX_KEY_VERSIONS + 1):
            gcm_key_attr = f"byok_encryption_key_gcm_v{version}"
            gcm_key_value = getattr(settings, gcm_key_attr, None)

            if gcm_key_value:
                try:
                    # Expect 64-char hex string (32 bytes = 256 bits)
                    key_bytes = bytes.fromhex(gcm_key_value)
                    if len(key_bytes) != AES_GCM_KEY_SIZE:
                        raise ValueError(
                            f"Key must be {AES_GCM_KEY_SIZE} bytes, got {len(key_bytes)}"
                        )
                    self._gcm_keys[version] = AESGCM(key_bytes)
                    logger.info(f"Loaded AES-256-GCM key version {version}")
                except Exception as e:
                    logger.error(f"Invalid AES-256-GCM key V{version}: {e}")
                    raise EncryptionError(
                        f"Invalid AES-256-GCM key format for V{version}: {e}. "
                        f"Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
                    )

        # Load legacy Fernet keys for backward compatibility (read-only)
        for version in range(1, MAX_KEY_VERSIONS + 1):
            fernet_key_attr = f"byok_encryption_key_v{version}"
            fernet_key_value = getattr(settings, fernet_key_attr, None)

            if fernet_key_value:
                try:
                    self._fernet_keys[version] = Fernet(fernet_key_value.encode())
                    logger.info(f"Loaded legacy Fernet key version {version} (read-only)")
                except Exception as e:
                    logger.warning(f"Invalid legacy Fernet key V{version}: {e}")

        # Fallback to legacy single key if no versioned keys
        if not self._fernet_keys and settings.byok_encryption_key:
            try:
                self._fernet_keys[1] = Fernet(settings.byok_encryption_key.encode())
                logger.info("Loaded legacy encryption key as Fernet V1 (read-only)")
            except Exception as e:
                logger.warning(f"Invalid legacy encryption key: {e}")

        # If no GCM keys but have Fernet keys, generate a new GCM key from Fernet key
        # This enables seamless upgrade without manual key generation
        if not self._gcm_keys and self._fernet_keys:
            logger.warning(
                "No AES-256-GCM keys configured. Deriving from Fernet key for upgrade. "
                "For production, set BYOK_ENCRYPTION_KEY_GCM_V1 explicitly."
            )
            # Derive a 256-bit key from the Fernet key using a simple hash
            # (In production, user should set a proper GCM key)
            import hashlib
            fernet_key_bytes = list(self._fernet_keys.values())[0]._signing_key
            derived_key = hashlib.sha256(fernet_key_bytes).digest()
            self._gcm_keys[1] = AESGCM(derived_key)
            logger.info("Derived AES-256-GCM key from Fernet key")

        # Require at least one key (GCM or Fernet)
        if not self._gcm_keys and not self._fernet_keys:
            raise EncryptionError(
                "No encryption keys configured. Set BYOK_ENCRYPTION_KEY_GCM_V1 (recommended) "
                "or BYOK_ENCRYPTION_KEY_V1 (legacy). "
                "Generate AES-256 key: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        # Determine current version
        current_version_setting = getattr(settings, "byok_encryption_key_current", None)
        if current_version_setting:
            try:
                self._current_version = int(current_version_setting)
            except (ValueError, TypeError):
                logger.warning(f"Invalid BYOK_ENCRYPTION_KEY_CURRENT: {current_version_setting}")
                self._current_version = max(self._gcm_keys.keys()) if self._gcm_keys else 1
        else:
            self._current_version = max(self._gcm_keys.keys()) if self._gcm_keys else 1

        # Validate current version has a GCM key
        if self._current_version not in self._gcm_keys:
            if self._gcm_keys:
                self._current_version = max(self._gcm_keys.keys())
            else:
                self._current_version = 1

        logger.info(
            f"Encryption service initialized: "
            f"{len(self._gcm_keys)} AES-256-GCM key(s), "
            f"{len(self._fernet_keys)} legacy Fernet key(s), "
            f"current version: {self._current_version}"
        )

        self._initialized = True

    @property
    def current_version(self) -> int:
        """Get the current encryption key version used for new encryptions."""
        return self._current_version

    @property
    def available_versions(self) -> list[int]:
        """Get list of available key versions for decryption."""
        all_versions = set(self._gcm_keys.keys()) | set(self._fernet_keys.keys())
        return sorted(all_versions)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using AES-256-GCM (current key version).

        Args:
            plaintext: String to encrypt (e.g., API key)

        Returns:
            Encrypted string in format "gcm:v{version}:{nonce_b64}:{ciphertext_b64}"

        Raises:
            EncryptionError: If encryption fails or plaintext is empty
        """
        if not plaintext:
            raise EncryptionError("Cannot encrypt empty string")

        if self._current_version not in self._gcm_keys:
            raise EncryptionError(
                f"AES-256-GCM key version {self._current_version} not available"
            )

        try:
            aesgcm = self._gcm_keys[self._current_version]

            # Generate random nonce (12 bytes for GCM)
            nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE)

            # Encrypt with AES-256-GCM (includes authentication tag)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

            # Encode to base64 for storage
            nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii")
            ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode("ascii")

            # Format: gcm:v{version}:{nonce}:{ciphertext}
            result = f"{AES_GCM_PREFIX}:v{self._current_version}:{nonce_b64}:{ciphertext_b64}"

            logger.debug(f"Encrypted data with AES-256-GCM version {self._current_version}")
            return result

        except Exception as e:
            logger.error(f"AES-256-GCM encryption failed: {e}")
            raise EncryptionError(f"Encryption failed: {e}")

    def decrypt(self, encrypted_text: str) -> str:
        """Decrypt ciphertext, automatically detecting format (GCM or Fernet).

        Supports (dual-read for migration):
        - NEW: "gcm:v{version}:{nonce_b64}:{ciphertext_b64}" (AES-256-GCM)
        - LEGACY: "v{version}:{fernet_ciphertext}" (Fernet)
        - LEGACY: raw Fernet ciphertext (assumes V1)

        Args:
            encrypted_text: Encrypted string (any supported format)

        Returns:
            Decrypted plaintext string

        Raises:
            EncryptionError: If decryption fails or required key not available
        """
        if not encrypted_text:
            raise EncryptionError("Cannot decrypt empty string")

        # Detect AES-256-GCM format: "gcm:v{version}:{nonce}:{ciphertext}"
        if encrypted_text.startswith(f"{AES_GCM_PREFIX}:"):
            return self._decrypt_gcm(encrypted_text)

        # Otherwise, treat as legacy Fernet format
        return self._decrypt_fernet(encrypted_text)

    def _decrypt_gcm(self, encrypted_text: str) -> str:
        """Decrypt AES-256-GCM formatted ciphertext."""
        try:
            # Parse format: gcm:v{version}:{nonce_b64}:{ciphertext_b64}
            parts = encrypted_text.split(":")
            if len(parts) != 4:
                raise EncryptionError(
                    f"Invalid AES-256-GCM format. Expected 4 parts, got {len(parts)}"
                )

            _, version_str, nonce_b64, ciphertext_b64 = parts
            version = int(version_str[1:])  # Remove 'v' prefix

            if version not in self._gcm_keys:
                raise EncryptionError(
                    f"AES-256-GCM key version {version} not available. "
                    f"Available GCM versions: {sorted(self._gcm_keys.keys())}"
                )

            # Decode from base64
            nonce = base64.urlsafe_b64decode(nonce_b64)
            ciphertext = base64.urlsafe_b64decode(ciphertext_b64)

            # Decrypt with AES-256-GCM
            aesgcm = self._gcm_keys[version]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            logger.debug(f"Decrypted AES-256-GCM data with version {version}")
            return plaintext.decode("utf-8")

        except EncryptionError:
            raise
        except Exception as e:
            logger.error(f"AES-256-GCM decryption failed: {e}")
            raise EncryptionError(f"AES-256-GCM decryption failed: {e}")

    def _decrypt_fernet(self, encrypted_text: str) -> str:
        """Decrypt legacy Fernet formatted ciphertext (backward compatibility)."""
        # Parse version from prefix
        version = 1  # Default for legacy data
        ciphertext = encrypted_text

        if encrypted_text.startswith("v") and ":" in encrypted_text:
            try:
                version_str, ciphertext = encrypted_text.split(":", 1)
                version = int(version_str[1:])  # Remove 'v' prefix
                logger.debug(f"Detected Fernet key version {version}")
            except (ValueError, IndexError):
                logger.warning("Malformed version prefix, treating as legacy V1")
                version = 1
                ciphertext = encrypted_text
        else:
            logger.debug("No version prefix, assuming legacy Fernet V1")

        # Validate key version is available
        if version not in self._fernet_keys:
            raise EncryptionError(
                f"Fernet key version {version} not available. "
                f"Available Fernet versions: {sorted(self._fernet_keys.keys())}. "
                f"Key may have been removed during rotation."
            )

        try:
            fernet = self._fernet_keys[version]
            plaintext = fernet.decrypt(ciphertext.encode()).decode()

            logger.debug(f"Decrypted legacy Fernet data with version {version}")
            return plaintext

        except InvalidToken:
            raise EncryptionError(
                f"Fernet decryption failed: Invalid token for version {version}. "
                f"Key may have been rotated or data corrupted."
            )
        except Exception as e:
            logger.error(f"Fernet decryption failed with version {version}: {e}")
            raise EncryptionError(f"Fernet decryption failed: {e}")

    def needs_re_encryption(self, encrypted_text: str) -> bool:
        """Check if ciphertext needs re-encryption with current key.

        Returns True if:
        - Legacy Fernet format (should migrate to AES-256-GCM)
        - Older AES-256-GCM version than current

        Args:
            encrypted_text: Encrypted string to check

        Returns:
            True if re-encryption recommended
        """
        # Legacy Fernet format should be migrated to AES-256-GCM
        if not encrypted_text.startswith(f"{AES_GCM_PREFIX}:"):
            return True

        # Check if AES-256-GCM version is current
        try:
            parts = encrypted_text.split(":")
            if len(parts) >= 2:
                version_str = parts[1]
                version = int(version_str[1:])  # Remove 'v' prefix
                return version < self._current_version
        except (ValueError, IndexError):
            pass

        return True  # Malformed, should be re-encrypted

    def re_encrypt(self, encrypted_text: str) -> str:
        """Re-encrypt data with AES-256-GCM (current key version).

        Useful for:
        - Migrating legacy Fernet data to AES-256-GCM
        - Key rotation: decrypt with old version, encrypt with new

        Args:
            encrypted_text: Existing encrypted string (any format/version)

        Returns:
            Re-encrypted string with AES-256-GCM current version

        Raises:
            EncryptionError: If decryption or encryption fails
        """
        plaintext = self.decrypt(encrypted_text)
        return self.encrypt(plaintext)

    def is_gcm_encrypted(self, encrypted_text: str) -> bool:
        """Check if ciphertext uses AES-256-GCM format."""
        return encrypted_text.startswith(f"{AES_GCM_PREFIX}:")

    def is_fernet_encrypted(self, encrypted_text: str) -> bool:
        """Check if ciphertext uses legacy Fernet format."""
        return not self.is_gcm_encrypted(encrypted_text)


# Global encryption service instance (singleton)
_encryption_service: Optional[VersionedEncryptionService] = None


def get_encryption_service() -> VersionedEncryptionService:
    """Get or create the global encryption service instance.

    Returns:
        Singleton VersionedEncryptionService instance

    Raises:
        EncryptionError: If service initialization fails
    """
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = VersionedEncryptionService()
    return _encryption_service


def encrypt_api_key(api_key: str) -> str:
    """Convenience function to encrypt an API key.

    Uses the current encryption key version.

    Args:
        api_key: Plaintext API key to encrypt

    Returns:
        Versioned encrypted API key string (format: "v{version}:{ciphertext}")

    Raises:
        EncryptionError: If encryption fails
    """
    service = get_encryption_service()
    return service.encrypt(api_key)


def decrypt_api_key(encrypted_key: str) -> str:
    """Convenience function to decrypt an API key.

    Automatically detects and uses the appropriate key version.

    Args:
        encrypted_key: Encrypted API key string (versioned or legacy format)

    Returns:
        Decrypted plaintext API key

    Raises:
        EncryptionError: If decryption fails
    """
    service = get_encryption_service()
    return service.decrypt(encrypted_key)
