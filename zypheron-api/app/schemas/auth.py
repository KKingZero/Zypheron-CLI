"""Authentication schemas for user registration, login, and token management.

Includes validation for email format, password strength, and OAuth fields.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    """User registration request with email/password.

    Validates email format and password strength.
    """

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (minimum 8 characters)",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password contains variety of characters.

        Requirements:
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit

        Args:
            v: Password string to validate

        Returns:
            Validated password

        Raises:
            ValueError: If password doesn't meet requirements
        """
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    """User login request with email/password."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int | None = Field(
        None,
        description="Token expiration in seconds (null for no expiry)",
    )


class UserResponse(BaseModel):
    """User profile response.

    Returns user information without sensitive fields.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    tier: Literal["free", "starter", "pro", "enterprise"] = Field(
        default="free",
        description="Subscription tier",
    )
    github_id: str | None = Field(None, description="GitHub user ID")
    github_username: str | None = Field(None, description="GitHub username")
    github_avatar_url: str | None = Field(None, description="GitHub avatar URL")
    is_active: bool = Field(default=True, description="Account active status")
    is_verified: bool = Field(default=False, description="Email verified status")
    created_at: datetime
    last_login: datetime | None = None


class LoginResponse(BaseModel):
    """Combined login response with token and user info."""

    user: UserResponse
    access_token: str
    token_type: str = "bearer"
    expires_in: int | None = None


class GitHubOAuthCallback(BaseModel):
    """GitHub OAuth callback parameters."""

    code: str = Field(..., description="Authorization code from GitHub")
    state: str | None = Field(None, description="CSRF protection state")


class GitHubUserInfo(BaseModel):
    """GitHub user information from OAuth."""

    id: int = Field(..., description="GitHub user ID")
    login: str = Field(..., description="GitHub username")
    email: str | None = Field(None, description="GitHub email (may be null)")
    avatar_url: str | None = Field(None, description="GitHub avatar URL")
    name: str | None = Field(None, description="GitHub display name")
