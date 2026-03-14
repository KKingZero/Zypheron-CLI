"""Pydantic schemas for request/response validation.

All schemas use Pydantic v2 patterns with proper validation.
"""

from app.schemas.ai_proxy import (
    AvailableProvidersResponse,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    ErrorResponse,
    ProviderInfo,
    StreamChunkResponse,
    TokenUsage,
    ValidateKeyRequest,
    ValidateKeyResponse,
)
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.schemas.device import (
    DeviceCreate,
    DeviceResponse,
    DeviceUpdate,
)
from app.schemas.device_auth import (
    DeviceAuthorizeRequest,
    DeviceAuthorizeResponse,
    DeviceCodeRequest,
    DeviceCodeResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)
from app.schemas.license import (
    LicenseFeatures,
    LicenseRefreshResponse,
    LicenseResponse,
    LicenseValidateResponse,
)
from app.schemas.teams import (
    TeamCreate,
    TeamInvitationCreate,
    TeamInvitationResponse,
    TeamListResponse,
    TeamMember,
    TeamMemberAdd,
    TeamMemberListResponse,
    TeamResponse,
    TeamUpdate,
)
from app.schemas.tokens import (
    QuotaInfoResponse,
    RemainingTokensResponse,
    TokenUsageResponse,
    UsageHistoryResponse,
    UsageSummaryResponse,
)

__all__ = [
    # Auth schemas
    "LoginRequest",
    "RegisterRequest",
    "LoginResponse",
    "TokenResponse",
    "UserResponse",
    # Device schemas
    "DeviceCreate",
    "DeviceResponse",
    "DeviceUpdate",
    # Device auth schemas
    "DeviceCodeRequest",
    "DeviceCodeResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    "DeviceAuthorizeRequest",
    "DeviceAuthorizeResponse",
    # License schemas
    "LicenseResponse",
    "LicenseValidateResponse",
    "LicenseFeatures",
    "LicenseRefreshResponse",
    # Team schemas
    "TeamCreate",
    "TeamUpdate",
    "TeamResponse",
    "TeamMember",
    "TeamMemberAdd",
    "TeamListResponse",
    "TeamMemberListResponse",
    "TeamInvitationCreate",
    "TeamInvitationResponse",
    # Token usage schemas
    "TokenUsageResponse",
    "UsageSummaryResponse",
    "QuotaInfoResponse",
    "UsageHistoryResponse",
    "RemainingTokensResponse",
    # AI Proxy schemas
    "ChatMessage",
    "ChatCompletionRequest",
    "ChatCompletionResponse",
    "StreamChunkResponse",
    "TokenUsage",
    "ProviderInfo",
    "AvailableProvidersResponse",
    "ValidateKeyRequest",
    "ValidateKeyResponse",
    "ErrorResponse",
]
