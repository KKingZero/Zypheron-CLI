"""Device Code Authentication schemas for OAuth 2.0 Device Authorization Grant.

Implements RFC 8628 flow for CLI and limited-input devices.
"""

from typing import Literal

from pydantic import BaseModel, Field


class DeviceCodeRequest(BaseModel):
    """Request to initiate device code authentication flow.

    The CLI sends device information to receive codes for authentication.
    """

    device_info: dict = Field(
        ...,
        description="Device metadata (OS, version, hostname, etc.)",
        examples=[
            {
                "os": "Linux",
                "os_version": "6.14.0-37-generic",
                "hostname": "dev-machine",
                "cli_version": "1.0.0",
            }
        ],
    )


class DeviceCodeResponse(BaseModel):
    """Response containing device code and user code for authentication.

    The CLI displays the user_code and verification_url to the user,
    then polls the token endpoint with the device_code.
    """

    device_code: str = Field(
        ...,
        description="Secret code for polling the token endpoint (32 characters)",
        min_length=32,
        max_length=32,
    )
    user_code: str = Field(
        ...,
        description="Short code for user to enter (8 characters, e.g., ABCD-1234)",
        min_length=9,
        max_length=9,
        pattern="^[A-Z0-9]{4}-[A-Z0-9]{4}$",
    )
    verification_url: str = Field(
        ...,
        description="URL where user enters the user_code",
        examples=["http://localhost:3000/device?code=ABCD-1234"],
    )
    expires_in: int = Field(
        ...,
        description="Number of seconds until the device code expires",
        gt=0,
        examples=[300],
    )
    interval: int = Field(
        default=5,
        description="Recommended polling interval in seconds",
        gt=0,
        examples=[5],
    )


class DeviceTokenRequest(BaseModel):
    """Request to poll for device code authorization status.

    The CLI sends this request repeatedly until the user authorizes
    or the device code expires.
    """

    device_code: str = Field(
        ...,
        description="The device_code received from /auth/device/code",
        min_length=32,
        max_length=32,
    )
    device_info: dict = Field(
        ...,
        description="Device metadata (same as initial request)",
    )


class DeviceTokenResponse(BaseModel):
    """Response for device token polling requests.

    Status indicates the current state of authorization.
    Tokens are only provided when status is 'authorized'.
    """

    status: Literal["pending", "authorized", "expired", "denied"] = Field(
        ...,
        description="Current authorization status",
    )
    access_token: str | None = Field(
        None,
        description="JWT access token (only present when authorized)",
    )
    refresh_token: str | None = Field(
        None,
        description="Refresh token for token renewal (reserved for future use)",
    )
    user_id: str | None = Field(
        None,
        description="Authenticated user ID (only present when authorized)",
    )
    email: str | None = Field(
        None,
        description="User email address (only present when authorized)",
    )
    tier: str | None = Field(
        None,
        description="User subscription tier (only present when authorized)",
    )
    token_type: str = Field(
        default="bearer",
        description="Token type for Authorization header",
    )
    expires_in: int | None = Field(
        None,
        description="Token expiration in seconds (null for no expiry)",
    )


class DeviceAuthorizeRequest(BaseModel):
    """Request from web app to authorize a device code.

    Called after the user logs in on the web and confirms the device code.
    This endpoint requires the user to be authenticated (JWT token).
    """

    user_code: str = Field(
        ...,
        description="The user_code to authorize (e.g., ABCD-1234)",
        min_length=9,
        max_length=9,
        pattern="^[A-Z0-9]{4}-[A-Z0-9]{4}$",
    )


class DeviceAuthorizeResponse(BaseModel):
    """Response after authorizing a device code."""

    success: bool = Field(
        ...,
        description="Whether the authorization was successful",
    )
    message: str = Field(
        ...,
        description="Human-readable message about the authorization result",
        examples=["Device authorized successfully"],
    )
    device_info: dict | None = Field(
        None,
        description="Information about the authorized device",
    )
