"""BYOK (Bring Your Own Key) router for managing user API keys.

Allows users to add, list, validate, and delete their own API keys for AI providers.
Users with valid BYOK keys bypass token limits and use their own keys directly.
"""

from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.encryption import EncryptionError, decrypt_api_key, encrypt_api_key
from app.models.user import User
from app.models.user_api_key import UserAPIKey
from app.routers.auth import get_current_user
from app.schemas.byok import (
    BYOKKeyCreate,
    BYOKKeyDeleteResponse,
    BYOKKeyList,
    BYOKKeyResponse,
    BYOKKeyValidateResponse,
)

router = APIRouter(prefix="/byok", tags=["BYOK"])

# Type alias for current user dependency
CurrentUser = Annotated[User, Depends(get_current_user)]


async def validate_api_key_with_provider(provider: str, api_key: str) -> tuple[bool, str]:
    """Validate an API key by making a test request to the provider.

    Makes a minimal API request to verify the key is valid and has proper permissions.

    Args:
        provider: Provider name (openai, anthropic, gemini, deepseek, grok)
        api_key: API key to validate

    Returns:
        Tuple of (is_valid, message)
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if provider == "openai":
                # Test with models list endpoint (lightweight)
                response = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "OpenAI API key validated successfully"
                elif response.status_code == 401:
                    return False, "Invalid OpenAI API key"
                else:
                    return False, f"OpenAI API returned status {response.status_code}"

            elif provider == "anthropic":
                # Test with a minimal completion request
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-3-haiku-20240307",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "test"}],
                    },
                )
                if response.status_code == 200:
                    return True, "Anthropic API key validated successfully"
                elif response.status_code == 401:
                    return False, "Invalid Anthropic API key"
                else:
                    return False, f"Anthropic API returned status {response.status_code}"

            elif provider == "gemini":
                # Test with models list endpoint
                response = await client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
                )
                if response.status_code == 200:
                    return True, "Gemini API key validated successfully"
                elif response.status_code in (400, 403):
                    return False, "Invalid Gemini API key"
                else:
                    return False, f"Gemini API returned status {response.status_code}"

            elif provider == "deepseek":
                # Test with models list endpoint
                response = await client.get(
                    "https://api.deepseek.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "DeepSeek API key validated successfully"
                elif response.status_code == 401:
                    return False, "Invalid DeepSeek API key"
                else:
                    return False, f"DeepSeek API returned status {response.status_code}"

            elif provider == "grok":
                # Test with models or similar endpoint (adjust based on actual Grok API)
                response = await client.get(
                    "https://api.x.ai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "Grok API key validated successfully"
                elif response.status_code == 401:
                    return False, "Invalid Grok API key"
                else:
                    return False, f"Grok API returned status {response.status_code}"

            else:
                return False, f"Unknown provider: {provider}"

    except httpx.TimeoutException:
        return False, f"Timeout validating {provider} API key"
    except httpx.RequestError as e:
        return False, f"Network error validating {provider} API key: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error validating {provider} API key: {str(e)}"


@router.post("/keys", response_model=BYOKKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_byok_key(
    request: BYOKKeyCreate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> BYOKKeyResponse:
    """Add a new API key for a provider.

    Encrypts the API key before storing and validates the format.
    Users can only have one key per provider (will replace existing).

    Args:
        request: BYOK key creation request with provider and API key
        current_user: Currently authenticated user
        db: Database session

    Returns:
        BYOKKeyResponse with masked key information

    Raises:
        HTTPException: If encryption fails or database error occurs
    """
    try:
        # Encrypt the API key before storage
        encrypted_key = encrypt_api_key(request.api_key)
    except EncryptionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption error: {str(e)}",
        )

    # Create masked version for display
    key_masked = UserAPIKey.mask_key(request.api_key)

    # Check if user already has a key for this provider
    stmt = select(UserAPIKey).where(
        UserAPIKey.user_id == current_user.id,
        UserAPIKey.provider == request.provider,
    )
    result = await db.execute(stmt)
    existing_key = result.scalar_one_or_none()

    if existing_key:
        # Update existing key
        existing_key.encrypted_key = encrypted_key
        existing_key.key_masked = key_masked
        existing_key.is_valid = False  # Reset validation status
        existing_key.last_validated_at = None
        existing_key.updated_at = datetime.now(timezone.utc)
        user_api_key = existing_key
    else:
        # Create new key
        user_api_key = UserAPIKey(
            user_id=current_user.id,
            provider=request.provider,
            encrypted_key=encrypted_key,
            key_masked=key_masked,
            is_valid=False,  # Not validated yet
        )
        db.add(user_api_key)

    try:
        await db.commit()
        await db.refresh(user_api_key)
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Database error: {str(e)}",
        )

    return BYOKKeyResponse.model_validate(user_api_key)


@router.get("/keys", response_model=BYOKKeyList)
async def list_byok_keys(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> BYOKKeyList:
    """List all API keys for the current user.

    Returns masked keys showing only the last 4 characters for security.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        BYOKKeyList with all user's API keys (masked)
    """
    # Query all keys for the current user
    stmt = (
        select(UserAPIKey)
        .where(UserAPIKey.user_id == current_user.id)
        .order_by(UserAPIKey.created_at.desc())
    )
    result = await db.execute(stmt)
    user_keys = result.scalars().all()

    return BYOKKeyList(
        keys=[BYOKKeyResponse.model_validate(key) for key in user_keys],
        total=len(user_keys),
    )


@router.delete("/keys/{key_id}", response_model=BYOKKeyDeleteResponse)
async def delete_byok_key(
    key_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> BYOKKeyDeleteResponse:
    """Delete a stored API key.

    Only allows deletion of keys owned by the current user.

    Args:
        key_id: ID of the key to delete
        current_user: Currently authenticated user
        db: Database session

    Returns:
        BYOKKeyDeleteResponse with deletion status

    Raises:
        HTTPException: If key not found or not owned by user
    """
    # Find the key
    stmt = select(UserAPIKey).where(
        UserAPIKey.id == key_id,
        UserAPIKey.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    user_key = result.scalar_one_or_none()

    if not user_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or you don't have permission to delete it",
        )

    # Delete the key
    await db.delete(user_key)
    await db.commit()

    return BYOKKeyDeleteResponse(
        success=True,
        message=f"{user_key.provider} API key deleted successfully",
    )


@router.post("/keys/{key_id}/validate", response_model=BYOKKeyValidateResponse)
async def validate_byok_key(
    key_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> BYOKKeyValidateResponse:
    """Validate a stored API key by making a test request to the provider.

    Decrypts the key, makes a minimal API call to verify it works,
    and updates the validation status in the database.

    Args:
        key_id: ID of the key to validate
        current_user: Currently authenticated user
        db: Database session

    Returns:
        BYOKKeyValidateResponse with validation result

    Raises:
        HTTPException: If key not found, decryption fails, or not owned by user
    """
    # Find the key
    stmt = select(UserAPIKey).where(
        UserAPIKey.id == key_id,
        UserAPIKey.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    user_key = result.scalar_one_or_none()

    if not user_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or you don't have permission to validate it",
        )

    # Decrypt the API key
    try:
        decrypted_key = decrypt_api_key(user_key.encrypted_key)
    except EncryptionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption error: {str(e)}",
        )

    # Validate with the provider
    is_valid, message = await validate_api_key_with_provider(user_key.provider, decrypted_key)

    # Update validation status in database
    if is_valid:
        user_key.mark_as_valid()
    else:
        user_key.mark_as_invalid()

    await db.commit()
    await db.refresh(user_key)

    validated_at = user_key.last_validated_at or datetime.now(timezone.utc)

    return BYOKKeyValidateResponse(
        is_valid=is_valid,
        message=message,
        provider=user_key.provider,
        validated_at=validated_at,
    )
