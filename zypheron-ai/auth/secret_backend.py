"""
Secret backend - thin wrapper over the OS keyring with a safe fallback.

SECURITY: this module exists so that discovered/generated secrets (test-account
passwords, captured credentials) are NEVER written to disk in plaintext (H-04,
M-07, C-01). Secrets go to the OS keyring when one is available. When no keyring
backend exists (e.g. a headless CI box), we fall back to a PROCESS-LIFETIME
in-memory map and refuse to persist the plaintext anywhere. Callers persist only
metadata + the reference key, then resolve the secret on demand.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:  # keyring is a declared dependency, but the backend may be missing at runtime
    import keyring
    _KEYRING_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    keyring = None
    _KEYRING_AVAILABLE = False

# Process-lifetime fallback. Never serialised to disk.
_MEMORY: Dict[str, str] = {}


def _mem_key(service: str, key: str) -> str:
    return f"{service}::{key}"


def keyring_available() -> bool:
    """True if a real OS keyring backend is usable."""
    return _KEYRING_AVAILABLE


def store_secret(service: str, key: str, value: str) -> bool:
    """
    Store a secret. Returns True if durably stored in the OS keyring,
    False if it only landed in the in-memory fallback (not persisted).
    """
    if _KEYRING_AVAILABLE:
        try:
            keyring.set_password(service, key, value)
            return True
        except Exception as e:  # pragma: no cover - environment dependent
            logger.warning(f"keyring store failed ({e}); using in-memory fallback")
    _MEMORY[_mem_key(service, key)] = value
    return False


def get_secret(service: str, key: str) -> Optional[str]:
    """Retrieve a secret from the keyring, or the in-memory fallback."""
    if _KEYRING_AVAILABLE:
        try:
            value = keyring.get_password(service, key)
            if value is not None:
                return value
        except Exception as e:  # pragma: no cover - environment dependent
            logger.warning(f"keyring get failed ({e})")
    return _MEMORY.get(_mem_key(service, key))


def delete_secret(service: str, key: str) -> None:
    """Best-effort delete from keyring and fallback."""
    if _KEYRING_AVAILABLE:
        try:
            keyring.delete_password(service, key)
        except Exception:
            pass
    _MEMORY.pop(_mem_key(service, key), None)
