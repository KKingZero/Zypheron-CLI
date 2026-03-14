"""Tests for versioned encryption key rotation functionality.

Tests cover:
- Versioned encryption/decryption
- Legacy format backward compatibility
- Key rotation simulation
- Multi-version support
- Error handling
"""

import pytest
from unittest.mock import Mock, patch

from app.core.encryption import (
    VersionedEncryptionService,
    EncryptionError,
    encrypt_api_key,
    decrypt_api_key,
    get_encryption_service,
    MAX_KEY_VERSIONS,
)


class TestVersionedEncryption:
    """Test versioned encryption service."""

    def test_single_version_encryption_decryption(self, mock_settings_v1):
        """Test basic encryption/decryption with single version."""
        service = VersionedEncryptionService()

        plaintext = "sk-1234567890abcdef"
        encrypted = service.encrypt(plaintext)

        # Should have version prefix
        assert encrypted.startswith("v1:")

        # Should decrypt correctly
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_multiple_version_support(self, mock_settings_multi_version):
        """Test encryption with multiple key versions."""
        service = VersionedEncryptionService()

        # Should use V3 as current (highest)
        assert service.current_version == 3
        assert service.available_versions == [1, 2, 3]

    def test_explicit_current_version(self, mock_settings_explicit_current):
        """Test explicit current version setting."""
        service = VersionedEncryptionService()

        # Should use V2 as explicitly set
        assert service.current_version == 2
        assert 2 in service.available_versions

    def test_decrypt_old_version(self, mock_settings_multi_version):
        """Test decrypting data encrypted with older version."""
        service = VersionedEncryptionService()

        # Manually create V1 encrypted data
        from cryptography.fernet import Fernet

        v1_fernet = service._keys[1]
        v1_ciphertext = v1_fernet.encrypt(b"test-api-key").decode()
        v1_encrypted = f"v1:{v1_ciphertext}"

        # Should decrypt with V1 key
        decrypted = service.decrypt(v1_encrypted)
        assert decrypted == "test-api-key"

    def test_legacy_format_backward_compatibility(self, mock_settings_v1):
        """Test decryption of legacy unversioned format."""
        service = VersionedEncryptionService()

        # Create legacy format (no version prefix)
        from cryptography.fernet import Fernet

        plaintext = "legacy-api-key"
        fernet = service._keys[1]
        legacy_encrypted = fernet.encrypt(plaintext.encode()).decode()

        # Should decrypt as V1
        decrypted = service.decrypt(legacy_encrypted)
        assert decrypted == plaintext

    def test_needs_re_encryption_detection(self, mock_settings_multi_version):
        """Test detection of data needing re-encryption."""
        service = VersionedEncryptionService()

        # V1 data needs re-encryption (current is V3)
        assert service.needs_re_encryption("v1:gAAAAABh...")

        # V2 data needs re-encryption
        assert service.needs_re_encryption("v2:gAAAAABh...")

        # V3 data (current) doesn't need re-encryption
        assert not service.needs_re_encryption("v3:gAAAAABh...")

        # Legacy format needs re-encryption
        assert service.needs_re_encryption("gAAAAABh...")

    def test_re_encryption(self, mock_settings_multi_version):
        """Test re-encrypting data with current version."""
        service = VersionedEncryptionService()

        # Create V1 encrypted data
        plaintext = "test-key"
        from cryptography.fernet import Fernet

        v1_fernet = service._keys[1]
        v1_ciphertext = v1_fernet.encrypt(plaintext.encode()).decode()
        v1_encrypted = f"v1:{v1_ciphertext}"

        # Re-encrypt to current version (V3)
        re_encrypted = service.re_encrypt(v1_encrypted)

        # Should now be V3
        assert re_encrypted.startswith("v3:")

        # Should still decrypt to same plaintext
        decrypted = service.decrypt(re_encrypted)
        assert decrypted == plaintext

    def test_missing_key_version_error(self, mock_settings_v1):
        """Test error when trying to decrypt with missing key version."""
        service = VersionedEncryptionService()

        # Try to decrypt V5 data when only V1 is available
        with pytest.raises(EncryptionError) as exc_info:
            service.decrypt("v5:gAAAAABh...")

        assert "version 5 not available" in str(exc_info.value).lower()

    def test_empty_plaintext_error(self, mock_settings_v1):
        """Test error when encrypting empty string."""
        service = VersionedEncryptionService()

        with pytest.raises(EncryptionError) as exc_info:
            service.encrypt("")

        assert "empty string" in str(exc_info.value).lower()

    def test_empty_ciphertext_error(self, mock_settings_v1):
        """Test error when decrypting empty string."""
        service = VersionedEncryptionService()

        with pytest.raises(EncryptionError) as exc_info:
            service.decrypt("")

        assert "empty string" in str(exc_info.value).lower()

    def test_invalid_ciphertext_error(self, mock_settings_v1):
        """Test error when decrypting invalid ciphertext."""
        service = VersionedEncryptionService()

        with pytest.raises(EncryptionError) as exc_info:
            service.decrypt("v1:invalid-ciphertext")

        assert "failed" in str(exc_info.value).lower()

    def test_no_keys_configured_error(self, mock_settings_no_keys):
        """Test error when no encryption keys are configured."""
        with pytest.raises(EncryptionError) as exc_info:
            VersionedEncryptionService()

        assert "no encryption keys" in str(exc_info.value).lower()

    def test_invalid_key_format_error(self, mock_settings_invalid_key):
        """Test error when key format is invalid."""
        with pytest.raises(EncryptionError) as exc_info:
            VersionedEncryptionService()

        assert "invalid" in str(exc_info.value).lower()

    def test_malformed_version_prefix(self, mock_settings_v1):
        """Test handling of malformed version prefix."""
        service = VersionedEncryptionService()

        # Create valid legacy encrypted data
        from cryptography.fernet import Fernet

        plaintext = "test-key"
        fernet = service._keys[1]
        ciphertext = fernet.encrypt(plaintext.encode()).decode()

        # Add malformed prefix
        malformed = f"vXX:{ciphertext}"

        # Should fall back to V1 and decrypt
        decrypted = service.decrypt(malformed)
        assert decrypted == plaintext

    def test_legacy_key_as_v1(self, mock_settings_legacy):
        """Test that legacy BYOK_ENCRYPTION_KEY is treated as V1."""
        service = VersionedEncryptionService()

        assert service.current_version == 1
        assert service.available_versions == [1]

        # Should encrypt with V1
        encrypted = service.encrypt("test-key")
        assert encrypted.startswith("v1:")

    def test_convenience_functions(self, mock_settings_v1):
        """Test convenience functions encrypt_api_key and decrypt_api_key."""
        plaintext = "sk-test-key-123"

        # Encrypt
        encrypted = encrypt_api_key(plaintext)
        assert encrypted.startswith("v1:")

        # Decrypt
        decrypted = decrypt_api_key(encrypted)
        assert decrypted == plaintext

    def test_singleton_pattern(self, mock_settings_v1):
        """Test that VersionedEncryptionService is a singleton."""
        service1 = VersionedEncryptionService()
        service2 = VersionedEncryptionService()

        assert service1 is service2

    def test_max_key_versions_limit(self):
        """Test that MAX_KEY_VERSIONS is set correctly."""
        assert MAX_KEY_VERSIONS == 5


# Pytest fixtures
@pytest.fixture
def mock_settings_v1():
    """Mock settings with single key version."""
    from cryptography.fernet import Fernet

    mock = Mock()
    mock.byok_encryption_key = None
    mock.byok_encryption_key_v1 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v2 = None
    mock.byok_encryption_key_v3 = None
    mock.byok_encryption_key_v4 = None
    mock.byok_encryption_key_v5 = None
    mock.byok_encryption_key_current = None

    with patch("app.core.encryption.get_settings", return_value=mock):
        # Reset singleton for each test
        VersionedEncryptionService._instance = None
        yield mock


@pytest.fixture
def mock_settings_multi_version():
    """Mock settings with multiple key versions."""
    from cryptography.fernet import Fernet

    mock = Mock()
    mock.byok_encryption_key = None
    mock.byok_encryption_key_v1 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v2 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v3 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v4 = None
    mock.byok_encryption_key_v5 = None
    mock.byok_encryption_key_current = None

    with patch("app.core.encryption.get_settings", return_value=mock):
        VersionedEncryptionService._instance = None
        yield mock


@pytest.fixture
def mock_settings_explicit_current():
    """Mock settings with explicit current version."""
    from cryptography.fernet import Fernet

    mock = Mock()
    mock.byok_encryption_key = None
    mock.byok_encryption_key_v1 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v2 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v3 = Fernet.generate_key().decode()
    mock.byok_encryption_key_v4 = None
    mock.byok_encryption_key_v5 = None
    mock.byok_encryption_key_current = 2  # Explicit V2

    with patch("app.core.encryption.get_settings", return_value=mock):
        VersionedEncryptionService._instance = None
        yield mock


@pytest.fixture
def mock_settings_legacy():
    """Mock settings with legacy single key."""
    from cryptography.fernet import Fernet

    mock = Mock()
    mock.byok_encryption_key = Fernet.generate_key().decode()
    mock.byok_encryption_key_v1 = None
    mock.byok_encryption_key_v2 = None
    mock.byok_encryption_key_v3 = None
    mock.byok_encryption_key_v4 = None
    mock.byok_encryption_key_v5 = None
    mock.byok_encryption_key_current = None

    with patch("app.core.encryption.get_settings", return_value=mock):
        VersionedEncryptionService._instance = None
        yield mock


@pytest.fixture
def mock_settings_no_keys():
    """Mock settings with no keys configured."""
    mock = Mock()
    mock.byok_encryption_key = None
    mock.byok_encryption_key_v1 = None
    mock.byok_encryption_key_v2 = None
    mock.byok_encryption_key_v3 = None
    mock.byok_encryption_key_v4 = None
    mock.byok_encryption_key_v5 = None
    mock.byok_encryption_key_current = None

    with patch("app.core.encryption.get_settings", return_value=mock):
        VersionedEncryptionService._instance = None
        yield mock


@pytest.fixture
def mock_settings_invalid_key():
    """Mock settings with invalid key format."""
    mock = Mock()
    mock.byok_encryption_key = None
    mock.byok_encryption_key_v1 = "invalid-key-format"
    mock.byok_encryption_key_v2 = None
    mock.byok_encryption_key_v3 = None
    mock.byok_encryption_key_v4 = None
    mock.byok_encryption_key_v5 = None
    mock.byok_encryption_key_current = None

    with patch("app.core.encryption.get_settings", return_value=mock):
        VersionedEncryptionService._instance = None
        yield mock
