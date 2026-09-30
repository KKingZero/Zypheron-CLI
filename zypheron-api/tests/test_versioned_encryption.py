"""Tests for versioned encryption key rotation functionality.

New data is encrypted with AES-256-GCM ("gcm:v{n}:{nonce}:{ct}"); legacy Fernet
data ("v{n}:{token}" or a bare token) stays readable.

Tests cover:
- Versioned encryption/decryption
- Legacy Fernet backward compatibility
- Key rotation simulation
- Multi-version support
- Error handling
"""

import base64
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from app.core import encryption
from app.core.encryption import (
    VersionedEncryptionService,
    EncryptionError,
    encrypt_api_key,
    decrypt_api_key,
    MAX_KEY_VERSIONS,
)


def _settings(**overrides):
    """Settings stub with every key slot unset unless overridden."""
    values = {"byok_encryption_key": None, "byok_encryption_key_current": None}
    for v in range(1, MAX_KEY_VERSIONS + 1):
        values[f"byok_encryption_key_gcm_v{v}"] = None
        values[f"byok_encryption_key_v{v}"] = None
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture
def use_settings():
    """Patch get_settings and reset both singletons so each test builds a fresh service."""
    patchers = []

    def _apply(**overrides):
        p = patch("app.core.encryption.get_settings", return_value=_settings(**overrides))
        p.start()
        patchers.append(p)
        VersionedEncryptionService._instance = None
        encryption._encryption_service = None

    yield _apply
    for p in patchers:
        p.stop()
    VersionedEncryptionService._instance = None
    encryption._encryption_service = None


def _gcm_key() -> str:
    return secrets.token_hex(32)


def _gcm_encrypt(service: VersionedEncryptionService, version: int, plaintext: str) -> str:
    """Encrypt with a specific (possibly non-current) GCM key version."""
    nonce = secrets.token_bytes(12)
    ct = service._gcm_keys[version].encrypt(nonce, plaintext.encode(), None)
    b64 = lambda b: base64.urlsafe_b64encode(b).decode()
    return f"gcm:v{version}:{b64(nonce)}:{b64(ct)}"


@pytest.fixture
def gcm_v1(use_settings):
    use_settings(byok_encryption_key_gcm_v1=_gcm_key())


@pytest.fixture
def gcm_multi(use_settings):
    use_settings(
        byok_encryption_key_gcm_v1=_gcm_key(),
        byok_encryption_key_gcm_v2=_gcm_key(),
        byok_encryption_key_gcm_v3=_gcm_key(),
    )


@pytest.fixture
def fernet_v1_key(use_settings):
    """GCM V1 for new writes plus a legacy Fernet V1 key for old data."""
    key = Fernet.generate_key().decode()
    use_settings(byok_encryption_key_gcm_v1=_gcm_key(), byok_encryption_key_v1=key)
    return Fernet(key.encode())


class TestVersionedEncryption:
    """Test versioned encryption service."""

    def test_single_version_encryption_decryption(self, gcm_v1):
        service = VersionedEncryptionService()

        encrypted = service.encrypt("sk-1234567890abcdef")

        assert encrypted.startswith("gcm:v1:")
        assert service.decrypt(encrypted) == "sk-1234567890abcdef"

    def test_multiple_version_support(self, gcm_multi):
        service = VersionedEncryptionService()

        # Highest configured version is current
        assert service.current_version == 3
        assert service.available_versions == [1, 2, 3]

    def test_explicit_current_version(self, use_settings):
        use_settings(
            byok_encryption_key_gcm_v1=_gcm_key(),
            byok_encryption_key_gcm_v2=_gcm_key(),
            byok_encryption_key_gcm_v3=_gcm_key(),
            byok_encryption_key_current=2,
        )
        service = VersionedEncryptionService()

        assert service.current_version == 2
        assert service.encrypt("x").startswith("gcm:v2:")

    def test_decrypt_old_version(self, gcm_multi):
        service = VersionedEncryptionService()

        assert service.decrypt(_gcm_encrypt(service, 1, "test-api-key")) == "test-api-key"

    def test_versioned_fernet_backward_compatibility(self, fernet_v1_key):
        service = VersionedEncryptionService()

        legacy = f"v1:{fernet_v1_key.encrypt(b'legacy-api-key').decode()}"
        assert service.decrypt(legacy) == "legacy-api-key"

    def test_unprefixed_fernet_backward_compatibility(self, fernet_v1_key):
        service = VersionedEncryptionService()

        legacy = fernet_v1_key.encrypt(b"legacy-api-key").decode()
        assert service.decrypt(legacy) == "legacy-api-key"

    def test_needs_re_encryption_detection(self, gcm_multi):
        service = VersionedEncryptionService()

        assert service.needs_re_encryption("gcm:v1:n:c")
        assert service.needs_re_encryption("gcm:v2:n:c")
        assert not service.needs_re_encryption("gcm:v3:n:c")
        # Any Fernet data should migrate to GCM
        assert service.needs_re_encryption("v3:gAAAAABh...")
        assert service.needs_re_encryption("gAAAAABh...")

    def test_re_encryption_rotates_gcm_version(self, gcm_multi):
        service = VersionedEncryptionService()

        re_encrypted = service.re_encrypt(_gcm_encrypt(service, 1, "test-key"))

        assert re_encrypted.startswith("gcm:v3:")
        assert service.decrypt(re_encrypted) == "test-key"

    def test_re_encryption_migrates_fernet_to_gcm(self, fernet_v1_key):
        service = VersionedEncryptionService()

        legacy = f"v1:{fernet_v1_key.encrypt(b'test-key').decode()}"
        re_encrypted = service.re_encrypt(legacy)

        assert re_encrypted.startswith("gcm:v1:")
        assert service.decrypt(re_encrypted) == "test-key"

    def test_missing_gcm_version_error(self, gcm_v1):
        service = VersionedEncryptionService()

        with pytest.raises(EncryptionError) as exc_info:
            service.decrypt("gcm:v5:AAAA:AAAA")

        assert "version 5 not available" in str(exc_info.value).lower()

    def test_missing_fernet_version_error(self, fernet_v1_key):
        service = VersionedEncryptionService()

        with pytest.raises(EncryptionError) as exc_info:
            service.decrypt("v5:gAAAAABh...")

        assert "version 5 not available" in str(exc_info.value).lower()

    def test_empty_plaintext_error(self, gcm_v1):
        with pytest.raises(EncryptionError) as exc_info:
            VersionedEncryptionService().encrypt("")

        assert "empty string" in str(exc_info.value).lower()

    def test_empty_ciphertext_error(self, gcm_v1):
        with pytest.raises(EncryptionError) as exc_info:
            VersionedEncryptionService().decrypt("")

        assert "empty string" in str(exc_info.value).lower()

    def test_tampered_ciphertext_error(self, gcm_v1):
        service = VersionedEncryptionService()
        prefix, version, nonce, ct = service.encrypt("secret").split(":")
        raw = bytearray(base64.urlsafe_b64decode(ct))
        raw[0] ^= 1
        tampered = ":".join([prefix, version, nonce, base64.urlsafe_b64encode(bytes(raw)).decode()])

        with pytest.raises(EncryptionError) as exc_info:
            service.decrypt(tampered)

        assert "failed" in str(exc_info.value).lower()

    def test_no_keys_configured_error(self, use_settings):
        use_settings()
        with pytest.raises(EncryptionError) as exc_info:
            VersionedEncryptionService()

        assert "no encryption keys" in str(exc_info.value).lower()

    def test_invalid_key_format_error(self, use_settings):
        use_settings(byok_encryption_key_gcm_v1="invalid-key-format")
        with pytest.raises(EncryptionError) as exc_info:
            VersionedEncryptionService()

        assert "invalid" in str(exc_info.value).lower()

    def test_malformed_version_prefix(self, fernet_v1_key):
        service = VersionedEncryptionService()

        malformed = f"vXX:{fernet_v1_key.encrypt(b'test-key').decode()}"

        # Corrupt prefix: rejected with EncryptionError, not an unhandled crash
        with pytest.raises(EncryptionError):
            service.decrypt(malformed)

    def test_legacy_key_as_v1(self, use_settings):
        """A lone legacy BYOK_ENCRYPTION_KEY becomes Fernet V1 and seeds GCM V1."""
        use_settings(byok_encryption_key=Fernet.generate_key().decode())
        service = VersionedEncryptionService()

        assert service.current_version == 1
        assert service.available_versions == [1]
        assert service.encrypt("test-key").startswith("gcm:v1:")

    def test_convenience_functions(self, gcm_v1):
        encrypted = encrypt_api_key("sk-test-key-123")

        assert encrypted.startswith("gcm:v1:")
        assert decrypt_api_key(encrypted) == "sk-test-key-123"

    def test_singleton_pattern(self, gcm_v1):
        assert VersionedEncryptionService() is VersionedEncryptionService()

    def test_max_key_versions_limit(self):
        assert MAX_KEY_VERSIONS == 5
