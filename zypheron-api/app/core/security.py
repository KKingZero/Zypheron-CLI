"""Security utilities for authentication and authorization."""

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    return pwd_context.hash(password)


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token.

    Args:
        data: Claims to encode in the token
        expires_delta: Optional expiration time. If None and configured to 0, no expiry.

    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode["exp"] = expire
    elif settings.jwt_access_token_expire_minutes > 0:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt_access_token_expire_minutes
        )
        to_encode["exp"] = expire
    # If expire_minutes is 0, no expiry (until logout)

    to_encode["iat"] = datetime.now(timezone.utc)
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a JWT access token.

    Args:
        token: The JWT token to decode

    Returns:
        Decoded claims if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError:
        return None


def generate_device_id() -> str:
    """Generate a unique device identifier."""
    import secrets
    return secrets.token_urlsafe(32)


def generate_device_code() -> str:
    """Generate a 32-character device code for OAuth device flow.

    This is the secret code used by the device to poll for authorization.

    Returns:
        32-character random string (alphanumeric)
    """
    import secrets
    import string
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))


def generate_user_code() -> str:
    """Generate an 8-character user code in format XXXX-XXXX.

    This is the code displayed to the user for manual entry on another device.
    Format: 4 alphanumeric characters, hyphen, 4 alphanumeric characters.

    Returns:
        8-character code with hyphen (e.g., "ABCD-1234")
    """
    import secrets
    import string
    alphabet = string.ascii_uppercase + string.digits
    part1 = ''.join(secrets.choice(alphabet) for _ in range(4))
    part2 = ''.join(secrets.choice(alphabet) for _ in range(4))
    return f"{part1}-{part2}"
