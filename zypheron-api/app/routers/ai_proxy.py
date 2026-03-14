"""AI Proxy router with unified multi-provider chat endpoints.

Security features:
- API key sanitization (never logged)
- Input validation and size limits
- Rate limiting per user
- Request timeout enforcement
- Prompt sanitization for logging
- Error message sanitization (no key leakage)
"""

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.encryption import decrypt_api_key
from app.core.redis_client import get_redis_client
from app.models.license import License
from app.models.token_usage import TokenUsage, UserQuota
from app.models.user import User
from app.models.user_api_key import UserAPIKey
from app.services.cache import get_cache_service, CacheService
from app.schemas.ai_proxy import (
    AvailableProvidersResponse,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ErrorResponse,
    ProviderInfo,
    StreamChunkResponse,
    ValidateKeyRequest,
    ValidateKeyResponse,
)
from app.services.ai_providers import (
    AIProviderError,
    InvalidKeyError,
    ProviderType,
    QuotaExceededError,
    RateLimitError,
    StreamChunk,
)
from app.services.load_balancer import AILoadBalancer
from app.services.metrics import (
    ai_request_duration,
    ai_requests_total,
    ai_tokens_used_total,
    rate_limit_exceeded_total,
)
from app.services.token_reservation import TokenReservationService

logger = structlog.get_logger()

router = APIRouter(prefix="/ai", tags=["AI Proxy"])

# Global load balancer instance (initialized on startup)
_load_balancer: AILoadBalancer | None = None

# Per-provider rate limits (requests per minute)
# Format: {provider: {tier: limit}}
# BYOK users get 2x the normal rate limit
PROVIDER_RATE_LIMITS = {
    "ollama": {
        "free": -1,  # Unlimited (local, no cost)
        "starter": -1,
        "pro": -1,
        "enterprise": -1,
    },
    "openai_gpt4": {  # GPT-4o and similar expensive models
        "free": 0,  # Free tier can't use cloud providers
        "starter": 30,
        "pro": 60,
        "enterprise": 120,
    },
    "openai_gpt35": {  # GPT-3.5 and cheaper models
        "free": 0,
        "starter": 60,
        "pro": 120,
        "enterprise": 240,
    },
    "anthropic": {  # All Claude models
        "free": 0,
        "starter": 30,
        "pro": 60,
        "enterprise": 120,
    },
    "deepseek": {
        "free": 0,
        "starter": 60,
        "pro": 120,
        "enterprise": 240,
    },
    "grok": {
        "free": 0,
        "starter": 30,
        "pro": 60,
        "enterprise": 120,
    },
}

# Model tier classification
# Used to determine which rate limit bucket to use
MODEL_TIERS = {
    # OpenAI - GPT-4 tier (expensive)
    "gpt-4o": "openai_gpt4",
    "gpt-4o-mini": "openai_gpt4",
    "gpt-4-turbo": "openai_gpt4",
    "gpt-4": "openai_gpt4",
    # OpenAI - GPT-3.5 tier (cheaper)
    "gpt-3.5-turbo": "openai_gpt35",
    "gpt-3.5-turbo-16k": "openai_gpt35",
    # Anthropic
    "claude-opus-4-6": "anthropic",
    "claude-sonnet-4-6": "anthropic",
    "claude-haiku-4-5-20251001": "anthropic",
    # DeepSeek
    "deepseek-r1": "deepseek",
    "deepseek-chat": "deepseek",
    # Kimi
    "kimi-k2": "kimi",
    "moonshot-v1-128k": "kimi",
}

# Sliding window size for provider rate limiting (in seconds)
PROVIDER_RATE_LIMIT_WINDOW = 60  # 1 minute

# Atomic rate limiting Lua script for Redis
# This script provides atomic check-and-increment to prevent race conditions
# where concurrent requests can bypass rate limits.
#
# Security: This prevents CRITICAL race condition where two requests at 59/60
# both see count=59, both pass, both increment = 61 total (bypass).
#
# How it works:
# 1. Remove old entries outside sliding window (atomic cleanup)
# 2. Get current count with ZCARD (atomic read)
# 3. Check limit - if exceeded, return denial with reset time
# 4. If allowed, add new entry and set expiration (atomic increment)
# 5. All operations in single Lua script = atomic execution
#
# Returns: [allowed, count, reset_time]
# - allowed: 1 if approved, 0 if denied
# - count: current count after operation (or at denial)
# - reset_time: Unix timestamp when limit resets
ATOMIC_RATE_LIMIT_LUA = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local current_time = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local window_size = tonumber(ARGV[5])

-- Remove old entries outside window (cleanup)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- Get current count in window
local count = redis.call('ZCARD', key)

-- Check if at or over limit
if count >= limit then
    -- Denied - calculate reset time
    -- Get oldest entry to determine when window started
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_time = current_time + window_size
    if oldest and #oldest > 0 then
        -- Reset when oldest entry expires
        reset_time = tonumber(oldest[2]) + window_size
    end
    return {0, count, reset_time}  -- Denied
end

-- Approved - add new entry atomically
redis.call('ZADD', key, current_time, member)

-- Set expiration to prevent memory leak
redis.call('EXPIRE', key, window_size * 2)

-- Return approval with updated count and reset time
return {1, count + 1, current_time + window_size}
"""


def get_load_balancer(settings: Settings = Depends(get_settings)) -> AILoadBalancer:
    """Get or create load balancer instance.

    Args:
        settings: Application settings

    Returns:
        Load balancer instance
    """
    global _load_balancer

    if _load_balancer is None:
        _load_balancer = AILoadBalancer(
            openai_keys=settings.openai_api_keys,
            anthropic_keys=settings.anthropic_api_keys,
            grok_keys=settings.grok_api_keys,
            deepseek_keys=settings.deepseek_api_keys,
            enable_ollama=settings.enable_ollama,
            ollama_base_url=settings.ollama_base_url,
        )
        logger.info("load_balancer_initialized")

    return _load_balancer


async def check_provider_rate_limit(
    user_id: int,
    provider_type: ProviderType,
    model: str,
    tier: str,
    is_byok: bool,
) -> tuple[bool, int, int, str]:
    """Check per-provider rate limit for a user using atomic Redis operations.

    SECURITY: Uses Lua script for atomic check-and-increment to prevent race conditions.
    Previous implementation had CRITICAL vulnerability where concurrent requests could
    bypass rate limits (e.g., two requests at 59/60 both see 59, both pass, total=61).

    Uses Redis sliding window algorithm to track requests per provider per user.
    BYOK users get 2x the normal rate limit since they're paying for their own API calls.

    Args:
        user_id: User ID
        provider_type: AI provider being accessed
        model: Model being used (determines rate limit tier)
        tier: User's subscription tier (free, starter, pro, enterprise)
        is_byok: Whether user is using Bring Your Own Key

    Returns:
        Tuple of (allowed, remaining, reset_at, provider_tier)
        - allowed: True if request is allowed, False if rate limited
        - remaining: Number of requests remaining in current window
        - reset_at: Unix timestamp when rate limit resets
        - provider_tier: The provider tier used for rate limiting (e.g., "openai_gpt4")

    Raises:
        HTTPException: If Redis is unavailable (fail closed for security)
    """
    # Get Redis client
    try:
        redis_client = await get_redis_client()
    except Exception as e:
        logger.error(
            "redis_unavailable_for_provider_rate_limit",
            error=str(e),
            user_id=user_id,
            provider=provider_type.value,
        )
        # For provider-specific rate limiting, we fail closed (deny request)
        # This prevents abuse if Redis goes down
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service temporarily unavailable. Please try again shortly.",
        )

    if not redis_client.is_available:
        logger.error(
            "redis_not_available_for_provider_rate_limit",
            user_id=user_id,
            provider=provider_type.value,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service temporarily unavailable. Please try again shortly.",
        )

    # Determine provider tier based on model
    # Default to provider name if model not in mapping
    if provider_type == ProviderType.OLLAMA:
        provider_tier = "ollama"
    else:
        provider_tier = MODEL_TIERS.get(model, provider_type.value)

    # Get base rate limit for this provider tier and user tier
    base_limit = PROVIDER_RATE_LIMITS.get(provider_tier, {}).get(tier, 0)

    # Unlimited access (Ollama)
    if base_limit == -1:
        logger.debug(
            "provider_rate_limit_unlimited",
            user_id=user_id,
            provider=provider_type.value,
            provider_tier=provider_tier,
        )
        return True, -1, 0, provider_tier

    # Apply 2x multiplier for BYOK users
    rate_limit = base_limit * 2 if is_byok else base_limit

    # Redis key format: ai_ratelimit:{user_id}:{provider_tier}
    redis_key = f"ai_ratelimit:{user_id}:{provider_tier}"

    current_time = int(time.time())
    window_start = current_time - PROVIDER_RATE_LIMIT_WINDOW

    # SECURITY: Generate cryptographically secure unique member ID
    # This prevents collision attacks and timing attacks
    # Using secrets.token_hex() instead of random.randint() for cryptographic security
    member = f"{current_time}:{secrets.token_hex(8)}"

    try:
        # ATOMIC OPERATION: Execute Lua script for race-condition-free rate limiting
        # This ensures check-and-increment happens atomically, preventing bypass
        if hasattr(redis_client, "_client") and redis_client._client:
            result = await redis_client._client.eval(
                ATOMIC_RATE_LIMIT_LUA,
                1,  # Number of keys
                redis_key,  # KEYS[1]
                window_start,  # ARGV[1]
                current_time,  # ARGV[2]
                rate_limit,  # ARGV[3]
                member,  # ARGV[4]
                PROVIDER_RATE_LIMIT_WINDOW,  # ARGV[5]
            )

            # Parse result from Lua script
            # result = [allowed, count, reset_time]
            allowed = bool(result[0])
            current_count = int(result[1])
            reset_time = int(result[2])
            remaining = max(0, rate_limit - current_count)

            if not allowed:
                # Rate limit exceeded
                logger.warning(
                    "provider_rate_limit_exceeded",
                    user_id=user_id,
                    provider=provider_type.value,
                    provider_tier=provider_tier,
                    tier=tier,
                    is_byok=is_byok,
                    limit=rate_limit,
                    current_count=current_count,
                    reset_at=reset_time,
                )
                return False, 0, reset_time, provider_tier

            # Request allowed
            logger.debug(
                "provider_rate_limit_checked",
                user_id=user_id,
                provider=provider_type.value,
                provider_tier=provider_tier,
                tier=tier,
                is_byok=is_byok,
                limit=rate_limit,
                remaining=remaining,
                reset_at=reset_time,
            )

            return True, remaining, reset_time, provider_tier

        else:
            # Redis client not properly initialized
            logger.error(
                "redis_client_not_initialized",
                user_id=user_id,
                provider=provider_type.value,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limiting service error. Please try again shortly.",
            )

    except Exception as e:
        logger.error(
            "provider_rate_limit_check_error",
            error=str(e),
            user_id=user_id,
            provider=provider_type.value,
            provider_tier=provider_tier,
        )
        # On error, fail closed (deny request) to prevent abuse
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service error. Please try again shortly.",
        )


async def get_current_user_optional(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Get current user from JWT token (optional - returns None if not authenticated).

    Args:
        request: FastAPI request object
        db: Database session

    Returns:
        Current authenticated user or None
    """
    # Import here to avoid circular dependency
    from app.routers.auth import get_current_user

    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None


async def check_license_and_byok(
    user: User,
    provider_type: ProviderType,
    db: AsyncSession,
) -> tuple[str | None, bool]:
    """Check user's license tier and BYOK status for the requested provider.

    Business logic:
    1. Free tier: Can ONLY use Ollama (local), NO cloud AI providers
    2. Paid tiers (Starter/Pro/Enterprise): Can use all cloud providers
    3. BYOK: If user has valid BYOK key, use it instead of platform keys (no token deduction)

    Args:
        user: Authenticated user
        provider_type: Requested AI provider
        db: Database session

    Returns:
        Tuple of (decrypted_user_api_key, is_byok)
        - If BYOK: returns (decrypted_key, True)
        - If platform key: returns (None, False)

    Raises:
        HTTPException: If tier restrictions prevent access or insufficient tokens
    """
    # Ollama is free for everyone (no tier restrictions)
    if provider_type == ProviderType.OLLAMA:
        logger.info("ollama_access", user_id=user.id, tier=user.tier)
        return None, False

    # Cloud providers require Starter tier or higher
    # Free tier can ONLY use Ollama
    if user.tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Cloud AI providers require Starter tier or higher. "
                "Free tier can only use Ollama (local models). "
                "Upgrade your plan to access OpenAI, Anthropic, Grok, and DeepSeek."
            ),
        )

    # User has paid tier - check for BYOK key
    stmt = select(UserAPIKey).where(
        UserAPIKey.user_id == user.id,
        UserAPIKey.provider == provider_type.value,
        UserAPIKey.is_valid == True,
    )
    result = await db.execute(stmt)
    user_api_key = result.scalar_one_or_none()

    if user_api_key:
        # User has valid BYOK key - decrypt and use it
        try:
            decrypted_key = decrypt_api_key(user_api_key.encrypted_key)
            logger.info(
                "byok_key_found",
                user_id=user.id,
                provider=provider_type.value,
                key_masked=user_api_key.key_masked,
            )
            return decrypted_key, True
        except Exception as e:
            logger.error(
                "byok_key_decryption_failed",
                user_id=user.id,
                provider=provider_type.value,
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt your API key. Please contact support.",
            )

    # No BYOK key - will use platform keys, need to check token quota
    # Get or create user quota
    stmt = select(UserQuota).where(UserQuota.user_id == user.id)
    result = await db.execute(stmt)
    quota = result.scalar_one_or_none()

    if not quota:
        # Create default quota for user's tier
        quota = await _create_default_quota(user, db)

    # Check if user has tokens remaining
    if quota.tokens_used_period >= quota.token_limit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                f"Insufficient tokens. You've used {quota.tokens_used_period:,} of your "
                f"{quota.token_limit:,} monthly tokens. "
                "Add a BYOK (Bring Your Own Key) to bypass token limits, or upgrade your plan."
            ),
        )

    logger.info(
        "platform_key_access",
        user_id=user.id,
        tier=user.tier,
        tokens_remaining=quota.token_limit - quota.tokens_used_period,
        provider=provider_type.value,
    )

    return None, False


async def _create_default_quota(user: User, db: AsyncSession) -> UserQuota:
    """Create default quota for user based on their tier.

    Tier limits:
    - free: 0 tokens (Ollama only)
    - starter: 1M tokens/month
    - pro: 3M tokens/month
    - enterprise: 15M tokens/month

    Args:
        user: User to create quota for
        db: Database session

    Returns:
        Created UserQuota instance
    """
    tier_limits = {
        "free": 0,
        "starter": 1_000_000,
        "pro": 3_000_000,
        "enterprise": 15_000_000,
    }

    now = datetime.now(timezone.utc)
    # Calculate period end (next month)
    if now.month == 12:
        period_end = now.replace(year=now.year + 1, month=1, day=1)
    else:
        period_end = now.replace(month=now.month + 1, day=1)

    quota = UserQuota(
        user_id=user.id,
        tier=user.tier,
        period_start=now,
        period_end=period_end,
        tokens_used_period=0,
        token_limit=tier_limits.get(user.tier, 0),
        byok_enabled=False,
    )
    db.add(quota)
    await db.commit()
    await db.refresh(quota)

    logger.info(
        "quota_created",
        user_id=user.id,
        tier=user.tier,
        token_limit=quota.token_limit,
    )

    return quota


async def update_token_usage(
    user: User,
    provider_type: ProviderType,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    db: AsyncSession,
    prompt_hash: str | None = None,
) -> None:
    """Update user's token usage after API call using TokenSyncService.

    Only called when using platform keys (not BYOK).

    Args:
        user: User who made the request
        provider_type: Provider used
        model: Model used
        prompt_tokens: Number of prompt tokens consumed
        completion_tokens: Number of completion tokens consumed
        db: Database session
        prompt_hash: SHA-256 hash of prompt (for deduplication)
    """
    from app.services.token_sync import TokenSyncService

    # Use TokenSyncService for comprehensive tracking
    sync_service = TokenSyncService(db)

    try:
        usage_record, normalized_tokens = await sync_service.record_usage(
            user_id=user.id,
            provider=provider_type.value,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            prompt_hash=prompt_hash,
            endpoint="/ai/chat",
        )

        await db.commit()

        logger.info(
            "token_usage_updated",
            user_id=user.id,
            provider=provider_type.value,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            normalized_tokens=normalized_tokens,
            usage_id=usage_record.id,
        )

    except Exception as e:
        logger.error(
            "token_usage_update_failed",
            user_id=user.id,
            provider=provider_type.value,
            error=str(e),
        )
        await db.rollback()
        raise


async def update_byok_last_used(
    user: User,
    provider_type: ProviderType,
    db: AsyncSession,
) -> None:
    """Update last_used timestamp for BYOK key.

    Args:
        user: User who made the request
        provider_type: Provider used
        db: Database session
    """
    stmt = select(UserAPIKey).where(
        UserAPIKey.user_id == user.id,
        UserAPIKey.provider == provider_type.value,
    )
    result = await db.execute(stmt)
    user_api_key = result.scalar_one_or_none()

    if user_api_key:
        user_api_key.update_last_used()
        await db.commit()

        logger.debug(
            "byok_last_used_updated",
            user_id=user.id,
            provider=provider_type.value,
        )


def _sanitize_error_message(message: str) -> str:
    """Sanitize error message to prevent API key leakage.

    Args:
        message: Original error message

    Returns:
        Sanitized error message
    """
    # Remove potential API key patterns
    # Pattern: sk-... (OpenAI), x-api-key, Bearer tokens, etc.
    import re

    patterns = [
        r"sk-[a-zA-Z0-9]{20,}",  # OpenAI keys
        r"x-api-key:\s*[a-zA-Z0-9-_]+",  # x-api-key headers
        r"Bearer\s+[a-zA-Z0-9-_\.]+",  # Bearer tokens
        r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9-_]+",  # Generic API keys
    ]

    sanitized = message
    for pattern in patterns:
        sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)

    return sanitized


def _compute_cache_key(request: ChatCompletionRequest) -> str:
    """Compute cache key for request.

    Args:
        request: Chat completion request

    Returns:
        Cache key (SHA-256 hash)
    """
    # Include provider and model in cache key
    cache_data = {
        "provider": request.provider,
        "model": request.model,
        "messages": [msg.model_dump() for msg in request.messages],
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
    }

    cache_str = json.dumps(cache_data, sort_keys=True)
    return hashlib.sha256(cache_str.encode("utf-8")).hexdigest()


def _detect_cache_ttl(messages: list[dict[str, str]], settings: Settings) -> int:
    """Detect appropriate cache TTL based on prompt content.

    Uses aggressive caching strategy:
    - CVE/vulnerability lookups: 24 hours
    - General security questions: 6 hours
    - Other prompts: 1 hour

    Args:
        messages: Chat messages
        settings: Application settings

    Returns:
        TTL in seconds
    """
    # Get the last user message content
    content = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "").lower()
            break

    # CVE and vulnerability patterns - cache for 24 hours
    # Using partial matches to catch plurals and variations
    vuln_patterns = [
        "cve-", "cve ", "vulnerabil",  # catches vulnerability/vulnerabilities
        "exploit", "what is cve", "describe cve", "nvd", "cvss",
        "remote code execution", "rce", "privilege escalation",
        "zero day", "0day", "poc ", "proof of concept",
    ]
    if any(pattern in content for pattern in vuln_patterns):
        return settings.cache_ttl_vuln_desc  # 24 hours

    # General security info - cache for 6 hours
    # Only security-specific patterns (removed overly broad ones like "how to", "explain")
    general_patterns = [
        "sql injection", "sqli", "xss", "csrf", "ssrf",
        "buffer overflow", "bof", "pentest", "penetration test",
        "owasp", "attack vector", "defense in depth",
        "encrypt", "decrypt", "hash", "crack", "brute force",
        "nmap", "recon", "enumerat",  # catches enumerate/enumeration
        "payload", "shellcode", "reverse shell", "bind shell",
        "metasploit", "burp suite", "wireshark", "nikto",
        "privilege escalation", "lateral movement", "persistence",
    ]
    if any(pattern in content for pattern in general_patterns):
        return settings.cache_ttl_general  # 6 hours

    # Default: identical prompt caching for 1 hour
    return settings.cache_ttl_prompt


async def _check_cache(cache_key: str, settings: Settings) -> dict[str, Any] | None:
    """Check cache for existing response.

    Args:
        cache_key: Cache key (SHA-256 hash of prompt)
        settings: Application settings

    Returns:
        Cached response or None if not found
    """
    cache_service = get_cache_service()
    return await cache_service.get_cached_response(cache_key)


async def _store_cache(
    cache_key: str,
    response_data: dict[str, Any],
    settings: Settings,
    ttl: int | None = None,
) -> None:
    """Store response in cache with aggressive TTL.

    Args:
        cache_key: Cache key (SHA-256 hash of prompt)
        response_data: Response data to cache
        settings: Application settings
        ttl: Time-to-live in seconds (auto-detected if None)
    """
    cache_service = get_cache_service()
    await cache_service.cache_response(cache_key, response_data, ttl)


@router.post(
    "/chat",
    response_model=ChatCompletionResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        402: {"model": ErrorResponse, "description": "Insufficient tokens"},
        403: {"model": ErrorResponse, "description": "Tier upgrade required"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        503: {"model": ErrorResponse, "description": "Service unavailable"},
    },
    summary="Chat completion with AI provider",
    description="""
    Unified chat completion endpoint supporting multiple AI providers.

    **Authentication:**
    - Required: Must include JWT token in Authorization header
    - Get token from /auth/login or /auth/register

    **Tier-Based Access:**
    - Free tier: Ollama (local models) ONLY
    - Starter/Pro/Enterprise: All providers (OpenAI, Anthropic, Grok, DeepSeek, Ollama)

    **Token Consumption:**
    - BYOK (Bring Your Own Key): Use your own API keys, NO token deduction
    - Platform keys: Uses your plan's monthly token allowance
    - Add BYOK keys via /byok/keys endpoint to bypass token limits

    **Supported providers:**
    - OpenAI (GPT-4, GPT-3.5, etc.) - Paid tiers only
    - Anthropic (Claude) - Paid tiers only
    - Grok (xAI) - Paid tiers only
    - DeepSeek - Paid tiers only
    - Ollama (Local LLMs) - All tiers including Free

    **Caching:**
    - Identical prompts cached for 1-24 hours depending on content
    - Cache based on full prompt hash (exact match only)
    - BYOK requests are not cached

    **Rate Limits:**

    Global limits (all endpoints):
    - Free: 10 requests/minute
    - Starter: 60 requests/minute
    - Pro: 120 requests/minute
    - Enterprise: 300 requests/minute

    Per-provider limits (per user, per minute):
    - Ollama: Unlimited (local, no cost)
    - OpenAI GPT-4: Starter=30, Pro=60, Enterprise=120
    - OpenAI GPT-3.5: Starter=60, Pro=120, Enterprise=240
    - Anthropic Claude: Starter=30, Pro=60, Enterprise=120
    - DeepSeek: Starter=60, Pro=120, Enterprise=240
    - Grok: Starter=30, Pro=60, Enterprise=120
    - BYOK users get 2x the normal provider limit

    Response headers:
    - X-Provider-RateLimit-Limit: Your provider-specific rate limit
    - X-Provider-RateLimit-Remaining: Remaining requests for this provider
    - X-Provider-RateLimit-Reset: Unix timestamp when limit resets
    """,
)
async def chat_completion(
    request: ChatCompletionRequest,
    http_request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    load_balancer: AILoadBalancer = Depends(get_load_balancer),
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
) -> ChatCompletionResponse | StreamingResponse:
    """Handle chat completion request with automatic provider selection and caching."""
    # Authentication required for all requests
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please login to access AI providers.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Log request (sanitized)
    logger.info(
        "ai_chat_request",
        user_id=current_user.id,
        tier=current_user.tier,
        provider=request.provider,
        model=request.model,
        message_count=len(request.messages),
        stream=request.stream,
        has_user_key=request.user_api_key is not None,
        client_ip=http_request.client.host if http_request.client else None,
    )

    # SECURITY FIX (PROXY-H1): Filter available providers by tier BEFORE auto-selection
    # This prevents free tier users from being auto-assigned a cloud provider
    # Free tier can ONLY use Ollama (local models)
    if request.provider is None:
        available = load_balancer.get_available_providers()
        if not available:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No AI providers available",
            )

        # Filter providers based on user tier
        if current_user.tier.lower() == "free":
            # Free tier can ONLY use Ollama
            allowed_providers = [p for p in available if p.lower() == "ollama"]
            if not allowed_providers:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Free tier can only use Ollama (local models). "
                        "Ollama is not currently available. "
                        "Please start Ollama locally or upgrade to Starter tier for cloud AI."
                    ),
                )
            available = allowed_providers

        # Default to first available (tier-filtered) provider
        request.provider = available[0]  # type: ignore
        logger.info(
            "auto_selected_provider",
            provider=request.provider,
            user_id=current_user.id,
            tier=current_user.tier,
            filtered_by_tier=current_user.tier.lower() == "free",
        )

    # Convert provider string to enum
    try:
        provider_type = ProviderType(request.provider)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {request.provider}",
        )

    # Check license tier and BYOK status
    # This will raise HTTPException if tier doesn't allow the provider
    # or if insufficient tokens (when not using BYOK)
    decrypted_user_key, is_byok = await check_license_and_byok(
        user=current_user,
        provider_type=provider_type,
        db=db,
    )

    # Determine which API key to use
    # Priority: decrypted BYOK key > request.user_api_key > platform key
    final_user_key = decrypted_user_key or request.user_api_key

    # Get provider instance to determine model if not specified
    # This is needed for accurate rate limiting
    provider = await load_balancer.get_provider(
        provider_type=provider_type,
        user_api_key=final_user_key,
    )
    try:
        # Use default model if not specified
        effective_model = request.model if request.model else provider._get_default_model()

        # Check per-provider rate limit BEFORE making the API call
        # This prevents expensive API calls from being made when rate limited
        allowed, remaining, reset_at, provider_tier = await check_provider_rate_limit(
            user_id=current_user.id,
            provider_type=provider_type,
            model=effective_model,
            tier=current_user.tier,
            is_byok=is_byok,
        )

        if not allowed:
            # Rate limit exceeded - return 429 with helpful error message
            retry_after_seconds = max(1, reset_at - int(time.time()))

            # Get list of available alternative providers
            available_providers = load_balancer.get_available_providers()
            alternative_providers = [p for p in available_providers if p != request.provider]

            error_detail = (
                f"Rate limit exceeded for {provider_type.value} ({provider_tier}). "
                f"Your {current_user.tier} tier allows {PROVIDER_RATE_LIMITS.get(provider_tier, {}).get(current_user.tier, 0)} "
                f"requests per minute for this provider"
                f"{' (2x limit applied for BYOK)' if is_byok else ''}. "
                f"Try again in {retry_after_seconds} seconds."
            )

            if alternative_providers:
                error_detail += f" Consider using an alternative provider: {', '.join(alternative_providers)}."

            logger.warning(
                "provider_rate_limit_rejected",
                user_id=current_user.id,
                provider=provider_type.value,
                provider_tier=provider_tier,
                tier=current_user.tier,
                is_byok=is_byok,
                reset_at=reset_at,
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=error_detail,
                headers={
                    "X-Provider-RateLimit-Limit": str(PROVIDER_RATE_LIMITS.get(provider_tier, {}).get(current_user.tier, 0) * (2 if is_byok else 1)),
                    "X-Provider-RateLimit-Remaining": "0",
                    "X-Provider-RateLimit-Reset": str(reset_at),
                    "Retry-After": str(retry_after_seconds),
                },
            )

    finally:
        await provider.close()

    # Add provider rate limit headers to response
    # These headers inform the client about their provider-specific rate limits
    rate_limit = PROVIDER_RATE_LIMITS.get(provider_tier, {}).get(current_user.tier, 0)
    effective_limit = rate_limit * 2 if is_byok else rate_limit

    # Only add headers if not unlimited (Ollama)
    if effective_limit > 0:
        response.headers["X-Provider-RateLimit-Limit"] = str(effective_limit)
        response.headers["X-Provider-RateLimit-Remaining"] = str(remaining)
        response.headers["X-Provider-RateLimit-Reset"] = str(reset_at)

    # Check cache for non-streaming requests (only if not using BYOK)
    cache_key = None
    if not request.stream and not is_byok and not request.user_api_key:
        cache_key = _compute_cache_key(request)
        cached_response = await _check_cache(cache_key, settings)
        if cached_response:
            logger.info("cache_hit", cache_key=cache_key[:16], user_id=current_user.id)
            # Return cached response with headers already set above
            return ChatCompletionResponse(**cached_response)

    # Convert messages to dict format
    messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]

    # Handle streaming vs non-streaming
    if request.stream:
        # For streaming, add headers directly to the StreamingResponse
        streaming_response = await _handle_streaming_chat(
            load_balancer=load_balancer,
            provider_type=provider_type,
            messages=messages,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            user_api_key=final_user_key,
            current_user=current_user,
            is_byok=is_byok,
            db=db,
        )
        # Add provider rate limit headers to streaming response
        if effective_limit > 0:
            streaming_response.headers["X-Provider-RateLimit-Limit"] = str(effective_limit)
            streaming_response.headers["X-Provider-RateLimit-Remaining"] = str(remaining)
            streaming_response.headers["X-Provider-RateLimit-Reset"] = str(reset_at)
        return streaming_response
    else:
        return await _handle_complete_chat(
            load_balancer=load_balancer,
            provider_type=provider_type,
            messages=messages,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            user_api_key=final_user_key,
            cache_key=cache_key,
            settings=settings,
            current_user=current_user,
            is_byok=is_byok,
            db=db,
        )


async def _handle_complete_chat(
    load_balancer: AILoadBalancer,
    provider_type: ProviderType,
    messages: list[dict[str, str]],
    model: str | None,
    temperature: float,
    max_tokens: int | None,
    user_api_key: str | None,
    cache_key: str | None,
    settings: Settings,
    current_user: User,
    is_byok: bool,
    db: AsyncSession,
) -> ChatCompletionResponse:
    """Handle non-streaming chat completion.

    Args:
        load_balancer: Load balancer instance
        provider_type: Provider to use
        messages: Chat messages
        model: Model to use (None for default)
        temperature: Sampling temperature
        max_tokens: Max tokens to generate
        user_api_key: User's API key (BYOK)
        cache_key: Cache key for response
        settings: Application settings
        current_user: Authenticated user
        is_byok: Whether using BYOK key
        db: Database session

    Returns:
        Chat completion response

    Raises:
        HTTPException: On errors
    """
    # CRITICAL SECURITY FIX - CRITICAL-2: Atomic token reservation
    # Reserve tokens BEFORE API call to prevent race condition quota bypass
    reservation_id = None
    reservation_service = None

    try:
        # Get provider instance
        provider = await load_balancer.get_provider(
            provider_type=provider_type,
            user_api_key=user_api_key,
        )

        # Use default model if not specified
        if model is None:
            model = provider._get_default_model()

        # STEP 1: Reserve tokens BEFORE API call (only for platform keys, not BYOK)
        if not is_byok:
            # Get user quota for limit
            stmt = select(UserQuota).where(UserQuota.user_id == current_user.id)
            result_quota = await db.execute(stmt)
            quota = result_quota.scalar_one_or_none()

            if not quota:
                # This shouldn't happen as quota is checked earlier, but be defensive
                quota = await _create_default_quota(current_user, db)

            # Estimate tokens conservatively (use max_tokens if provided, else default)
            # Add prompt tokens estimate (rough approximation: 4 chars per token)
            prompt_chars = sum(len(msg.get("content", "")) for msg in messages)
            estimated_prompt_tokens = prompt_chars // 4 + 100  # +100 safety margin
            estimated_completion_tokens = max_tokens if max_tokens else 1000  # Default 1000
            estimated_total = estimated_prompt_tokens + estimated_completion_tokens

            # Reserve tokens atomically
            try:
                reservation_service = TokenReservationService()
                success, reservation_id, current_usage = await reservation_service.reserve_tokens(
                    user_id=current_user.id,
                    estimated_tokens=estimated_total,
                    token_limit=quota.token_limit,
                )

                if not success:
                    # Quota exceeded - deny request
                    raise HTTPException(
                        status_code=status.HTTP_402_PAYMENT_REQUIRED,
                        detail=(
                            f"Insufficient tokens. Current usage: {current_usage:,} / {quota.token_limit:,}. "
                            f"This request needs approximately {estimated_total:,} tokens. "
                            "Add a BYOK (Bring Your Own Key) to bypass token limits, or upgrade your plan."
                        ),
                    )

            except RuntimeError as e:
                # Redis unavailable - fail closed for security
                logger.error(
                    "token_reservation_failed",
                    user_id=current_user.id,
                    error=str(e),
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Token reservation service temporarily unavailable. Please try again shortly.",
                )

        try:
            # STEP 2: Execute chat completion (tokens are already reserved)
            response = await provider.chat_completion(
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False,
            )

            # Convert to response schema
            result = ChatCompletionResponse(
                provider=response.provider.value,
                model=response.model,
                content=response.content,
                usage={
                    "prompt_tokens": response.prompt_tokens,
                    "completion_tokens": response.completion_tokens,
                    "total_tokens": response.total_tokens,
                },
                latency_ms=response.latency_ms,
                cached=False,
                finish_reason=response.finish_reason,
                metadata=response.metadata,
            )

            # Record Prometheus metrics
            ai_requests_total.labels(
                provider=response.provider.value,
                model=response.model,
                tier=current_user.tier,
                is_byok=str(is_byok),
            ).inc()
            ai_request_duration.labels(
                provider=response.provider.value,
            ).observe(response.latency_ms / 1000.0)
            ai_tokens_used_total.labels(
                provider=response.provider.value,
                model=response.model,
                token_type="prompt",
            ).inc(response.prompt_tokens)
            ai_tokens_used_total.labels(
                provider=response.provider.value,
                model=response.model,
                token_type="completion",
            ).inc(response.completion_tokens)

            # STEP 3: Finalize token usage
            if is_byok:
                # Using BYOK - just update last_used timestamp
                await update_byok_last_used(
                    user=current_user,
                    provider_type=provider_type,
                    db=db,
                )
                logger.info(
                    "ai_chat_success_byok",
                    user_id=current_user.id,
                    provider=response.provider.value,
                    model=response.model,
                    tokens=response.total_tokens,
                    latency_ms=response.latency_ms,
                )
            else:
                # Using platform key - finalize reservation with actual usage
                actual_tokens = response.total_tokens

                # Finalize reservation (adjust for actual vs estimated)
                if reservation_service and reservation_id:
                    try:
                        await reservation_service.finalize_reservation(
                            user_id=current_user.id,
                            reservation_id=reservation_id,
                            actual_tokens=actual_tokens,
                        )
                        reservation_id = None  # Prevent double-finalization in finally block
                    except Exception as e:
                        logger.error(
                            "reservation_finalization_failed",
                            user_id=current_user.id,
                            reservation_id=reservation_id,
                            error=str(e),
                        )
                        # Continue - reservation will expire, but log the issue

                # Update database with actual usage
                await update_token_usage(
                    user=current_user,
                    provider_type=provider_type,
                    model=response.model,
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    db=db,
                    prompt_hash=cache_key,
                )
                logger.info(
                    "ai_chat_success_platform",
                    user_id=current_user.id,
                    tier=current_user.tier,
                    provider=response.provider.value,
                    model=response.model,
                    tokens=response.total_tokens,
                    latency_ms=response.latency_ms,
                )

            # Store in cache if applicable (with detected TTL)
            # Only cache when using platform keys (not BYOK)
            if cache_key and not is_byok:
                ttl = _detect_cache_ttl(messages, settings)
                await _store_cache(cache_key, result.model_dump(), settings, ttl)
                logger.debug("cache_stored", cache_key=cache_key[:16], ttl=ttl, user_id=current_user.id)

            return result

        except Exception as e:
            # CRITICAL: Release reservation on any error
            if reservation_service and reservation_id and not is_byok:
                try:
                    await reservation_service.release_reservation(
                        user_id=current_user.id,
                        reservation_id=reservation_id,
                    )
                    reservation_id = None  # Prevent double-release
                    logger.info(
                        "reservation_released_on_error",
                        user_id=current_user.id,
                        error_type=type(e).__name__,
                    )
                except Exception as release_error:
                    logger.error(
                        "reservation_release_failed",
                        user_id=current_user.id,
                        error=str(release_error),
                    )
                    # Don't mask original error
            raise

        finally:
            await provider.close()

    except InvalidKeyError as e:
        logger.error(
            "ai_invalid_key",
            provider=provider_type.value,
            is_byok=user_api_key is not None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_sanitize_error_message(str(e)),
        )

    except RateLimitError as e:
        logger.warning(
            "ai_rate_limit",
            provider=provider_type.value,
            retry_after=e.retry_after,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_sanitize_error_message(str(e)),
            headers={"Retry-After": str(e.retry_after)} if e.retry_after else None,
        )

    except QuotaExceededError as e:
        logger.error(
            "ai_quota_exceeded",
            provider=provider_type.value,
        )
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=_sanitize_error_message(str(e)),
        )

    except AIProviderError as e:
        logger.error(
            "ai_provider_error",
            provider=provider_type.value,
            retryable=e.retryable,
            error=_sanitize_error_message(str(e)),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE if e.retryable else status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_message(str(e)),
        )

    except ValueError as e:
        logger.warning("ai_validation_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    except Exception as e:
        logger.error(
            "ai_unexpected_error",
            error=str(e),
            error_type=type(e).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


async def _handle_streaming_chat(
    load_balancer: AILoadBalancer,
    provider_type: ProviderType,
    messages: list[dict[str, str]],
    model: str | None,
    temperature: float,
    max_tokens: int | None,
    user_api_key: str | None,
    current_user: User,
    is_byok: bool,
    db: AsyncSession,
) -> StreamingResponse:
    """Handle streaming chat completion.

    Args:
        load_balancer: Load balancer instance
        provider_type: Provider to use
        messages: Chat messages
        model: Model to use (None for default)
        temperature: Sampling temperature
        max_tokens: Max tokens to generate
        user_api_key: User's API key (BYOK)
        current_user: Authenticated user
        is_byok: Whether using BYOK key
        db: Database session

    Returns:
        Streaming response

    Raises:
        HTTPException: On errors
    """
    # CRITICAL SECURITY FIX - CRITICAL-2: Reserve tokens for streaming too
    reservation_id = None
    reservation_service = None

    # STEP 1: Reserve tokens BEFORE streaming starts (only for platform keys)
    if not is_byok:
        try:
            # Get user quota for limit
            stmt = select(UserQuota).where(UserQuota.user_id == current_user.id)
            result_quota = await db.execute(stmt)
            quota = result_quota.scalar_one_or_none()

            if not quota:
                quota = await _create_default_quota(current_user, db)

            # Estimate tokens conservatively
            prompt_chars = sum(len(msg.get("content", "")) for msg in messages)
            estimated_prompt_tokens = prompt_chars // 4 + 100
            estimated_completion_tokens = max_tokens if max_tokens else 1000
            estimated_total = estimated_prompt_tokens + estimated_completion_tokens

            # Reserve tokens atomically
            reservation_service = TokenReservationService()
            success, reservation_id, current_usage = await reservation_service.reserve_tokens(
                user_id=current_user.id,
                estimated_tokens=estimated_total,
                token_limit=quota.token_limit,
            )

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=(
                        f"Insufficient tokens. Current usage: {current_usage:,} / {quota.token_limit:,}. "
                        f"This request needs approximately {estimated_total:,} tokens. "
                        "Add a BYOK (Bring Your Own Key) to bypass token limits, or upgrade your plan."
                    ),
                )

        except HTTPException:
            raise
        except RuntimeError as e:
            logger.error(
                "token_reservation_failed_streaming",
                user_id=current_user.id,
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Token reservation service temporarily unavailable. Please try again shortly.",
            )

    async def stream_generator():
        """Generator for streaming response."""
        provider = None
        total_tokens_accumulated = 0
        prompt_tokens_accumulated = 0
        completion_tokens_accumulated = 0
        stream_error_occurred = False

        try:
            # Get provider instance
            provider = await load_balancer.get_provider(
                provider_type=provider_type,
                user_api_key=user_api_key,
            )

            # Use default model if not specified
            nonlocal model
            if model is None:
                model = provider._get_default_model()

            # STEP 2: Execute streaming chat completion (tokens already reserved)
            stream = await provider.chat_completion(
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )

            # Stream chunks
            async for chunk in stream:  # type: ignore
                chunk_data = StreamChunkResponse(
                    type=chunk.type.value,
                    content=chunk.content,
                    metadata=chunk.metadata,
                    error=chunk.error,
                )

                # Track token usage from metadata
                if chunk.metadata:
                    if "total_tokens" in chunk.metadata:
                        total_tokens_accumulated = chunk.metadata["total_tokens"]
                    if "prompt_tokens" in chunk.metadata:
                        prompt_tokens_accumulated = chunk.metadata["prompt_tokens"]
                    if "completion_tokens" in chunk.metadata:
                        completion_tokens_accumulated = chunk.metadata["completion_tokens"]

                # SSE format
                yield f"data: {chunk_data.model_dump_json()}\n\n"

            # STEP 3: After streaming completes successfully, finalize usage
            if is_byok:
                # Using BYOK - just update last_used timestamp
                await update_byok_last_used(
                    user=current_user,
                    provider_type=provider_type,
                    db=db,
                )
                logger.info(
                    "ai_stream_success_byok",
                    user_id=current_user.id,
                    provider=provider_type.value,
                    model=model,
                    tokens=total_tokens_accumulated,
                )
            else:
                # Using platform key - finalize reservation and update database
                if total_tokens_accumulated > 0:
                    # If prompt/completion tokens not separately tracked, split evenly
                    if prompt_tokens_accumulated == 0 and completion_tokens_accumulated == 0:
                        prompt_tokens_accumulated = total_tokens_accumulated // 2
                        completion_tokens_accumulated = total_tokens_accumulated - prompt_tokens_accumulated

                    # Finalize reservation with actual usage
                    if reservation_service and reservation_id:
                        try:
                            await reservation_service.finalize_reservation(
                                user_id=current_user.id,
                                reservation_id=reservation_id,
                                actual_tokens=total_tokens_accumulated,
                            )
                        except Exception as e:
                            logger.error(
                                "reservation_finalization_failed_streaming",
                                user_id=current_user.id,
                                reservation_id=reservation_id,
                                error=str(e),
                            )

                    # Update database
                    await update_token_usage(
                        user=current_user,
                        provider_type=provider_type,
                        model=model,
                        prompt_tokens=prompt_tokens_accumulated,
                        completion_tokens=completion_tokens_accumulated,
                        db=db,
                    )

                logger.info(
                    "ai_stream_success_platform",
                    user_id=current_user.id,
                    tier=current_user.tier,
                    provider=provider_type.value,
                    model=model,
                    tokens=total_tokens_accumulated,
                )

        except Exception as e:
            stream_error_occurred = True

            # CRITICAL: Release reservation on error
            if reservation_service and reservation_id and not is_byok:
                try:
                    await reservation_service.release_reservation(
                        user_id=current_user.id,
                        reservation_id=reservation_id,
                    )
                    logger.info(
                        "reservation_released_on_stream_error",
                        user_id=current_user.id,
                        error_type=type(e).__name__,
                    )
                except Exception as release_error:
                    logger.error(
                        "reservation_release_failed_streaming",
                        user_id=current_user.id,
                        error=str(release_error),
                    )

            # Send error chunk
            error_msg = _sanitize_error_message(str(e))
            error_chunk = StreamChunkResponse(
                type="error",
                error=error_msg,
            )
            yield f"data: {error_chunk.model_dump_json()}\n\n"

            logger.error(
                "ai_stream_error",
                user_id=current_user.id,
                provider=provider_type.value,
                error=error_msg,
                error_type=type(e).__name__,
            )

        finally:
            if provider:
                await provider.close()

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get(
    "/providers",
    response_model=AvailableProvidersResponse,
    summary="List available AI providers",
    description="""
    Get list of available AI providers and their models.

    Providers are only listed if server keys are configured.
    """,
)
async def list_providers(
    load_balancer: AILoadBalancer = Depends(get_load_balancer),
) -> AvailableProvidersResponse:
    """List available AI providers."""
    # Get available providers from load balancer
    available_names = load_balancer.get_available_providers()

    # Model information for each provider
    provider_models = {
        "openai": ["gpt-5.4", "gpt-5.2", "gpt-4.1"],
        "anthropic": [
            "claude-opus-4-6",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
        ],
        "deepseek": ["deepseek-r1", "deepseek-chat"],
        "kimi": ["kimi-k2", "moonshot-v1-128k"],
        "gemini": ["gemini-3.1-pro-preview", "gemini-3-flash-preview"],
        "ollama": ["qwen3-coder", "llama3.2:3b", "mistral:latest"],
    }

    # Build provider info list
    providers = [
        ProviderInfo(
            name=name,
            available=True,
            models=provider_models.get(name, []),
            supports_streaming=True,
        )
        for name in available_names
    ]

    logger.info("providers_listed", count=len(providers))

    return AvailableProvidersResponse(
        providers=providers,
        total_count=len(providers),
    )


@router.post(
    "/validate-key",
    response_model=ValidateKeyResponse,
    summary="Validate user's API key",
    description="""
    Validate a user's API key for a specific provider (BYOK).

    This makes a minimal API call to verify the key is valid.
    """,
)
async def validate_key(
    request: ValidateKeyRequest,
    load_balancer: AILoadBalancer = Depends(get_load_balancer),
) -> ValidateKeyResponse:
    """Validate a user's API key for a provider."""
    # Convert provider string to enum
    try:
        provider_type = ProviderType(request.provider)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {request.provider}",
        )

    logger.info(
        "key_validation_requested",
        provider=request.provider,
    )

    # Validate key
    is_valid = await load_balancer.validate_user_key(
        provider_type=provider_type,
        api_key=request.api_key,
    )

    return ValidateKeyResponse(
        provider=request.provider,
        valid=is_valid,
        message="API key is valid" if is_valid else "API key is invalid",
    )


@router.get(
    "/health",
    summary="Health check for AI proxy",
    description="Get health status of AI provider key pools.",
)
async def health_check(
    load_balancer: AILoadBalancer = Depends(get_load_balancer),
) -> dict[str, Any]:
    """Get health status of AI proxy service."""
    stats = load_balancer.get_pool_stats()

    return {
        "status": "healthy",
        "providers": stats,
    }


@router.get(
    "/cache/stats",
    summary="Cache statistics",
    description="Get cache performance metrics including hit rate, compression savings, and latency.",
)
async def cache_stats() -> dict[str, Any]:
    """Get cache statistics and metrics."""
    cache_service = get_cache_service()
    stats = await cache_service.get_stats()

    return {
        "status": "ok",
        "cache": stats,
    }
