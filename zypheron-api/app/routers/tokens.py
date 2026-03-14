"""Token usage tracking router for quota monitoring and analytics.

Provides endpoints to:
- Get current token usage and quota information
- View usage history with pagination
- Check remaining tokens
- Get usage breakdowns by provider
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.token_usage import TokenUsage
from app.routers.auth import CurrentUser
from app.schemas.tokens import (
    QuotaInfoResponse,
    RemainingTokensResponse,
    TokenUsageResponse,
    UsageHistoryResponse,
    UsageSummaryResponse,
    UsageBreakdownResponse,
    MonthlyHistoryResponse,
)
from app.services.token_tracking import TokenTrackingService
from app.services.token_sync import TokenSyncService

router = APIRouter(prefix="/tokens", tags=["Token Usage"])


@router.get("/usage", response_model=UsageSummaryResponse)
async def get_usage(
    current_user: CurrentUser,
    period: Literal["day", "week", "month", "all"] = Query(
        default="month",
        description="Time period for usage summary",
    ),
    db: AsyncSession = Depends(get_db),
) -> UsageSummaryResponse:
    """Get token usage summary for the current user.

    Returns total tokens used and breakdown by provider for the specified period.

    Args:
        current_user: Currently authenticated user
        period: Time period to query ("day", "week", "month", "all")
        db: Database session

    Returns:
        Usage summary with total tokens and provider breakdown
    """
    service = TokenTrackingService(db)

    # Get total usage for period
    total_tokens = await service.get_usage(current_user.id, period)

    # Get usage breakdown by provider
    by_provider = await service.get_usage_by_provider(current_user.id, period)

    return UsageSummaryResponse(
        total_tokens=total_tokens,
        period=period,
        by_provider=by_provider,
    )


@router.get("/remaining", response_model=RemainingTokensResponse)
async def get_remaining(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> RemainingTokensResponse:
    """Get remaining token quota for the current user.

    Returns the number of tokens remaining in the current billing period.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Remaining tokens information including quota and tier
    """
    service = TokenTrackingService(db)

    # Get quota info
    quota_info = await service.get_quota_info(current_user.id)

    return RemainingTokensResponse(
        tokens_remaining=quota_info["tokens_remaining"],
        token_limit=quota_info["token_limit"],
        tier=quota_info["tier"],
        byok_enabled=quota_info["byok_enabled"],
    )


@router.get("/quota", response_model=QuotaInfoResponse)
async def get_quota(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> QuotaInfoResponse:
    """Get comprehensive quota information for the current user.

    Returns detailed quota information including usage, limits, and billing period.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Comprehensive quota information
    """
    service = TokenTrackingService(db)
    quota_info = await service.get_quota_info(current_user.id)

    return QuotaInfoResponse(**quota_info)


@router.get("/history", response_model=UsageHistoryResponse)
async def get_history(
    current_user: CurrentUser,
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(
        default=50,
        ge=1,
        le=100,
        description="Number of items per page (max 100)",
    ),
    provider: str | None = Query(
        default=None,
        description="Filter by provider (openai, anthropic, grok, deepseek)",
    ),
    db: AsyncSession = Depends(get_db),
) -> UsageHistoryResponse:
    """Get paginated token usage history for the current user.

    Returns a list of token usage records with pagination support.

    Args:
        current_user: Currently authenticated user
        page: Page number (1-indexed)
        page_size: Number of items per page (max 100)
        provider: Optional provider filter
        db: Database session

    Returns:
        Paginated usage history with metadata
    """
    # Build query
    stmt = (
        select(TokenUsage)
        .where(TokenUsage.user_id == current_user.id)
        .order_by(TokenUsage.created_at.desc())
    )

    # Apply provider filter if specified
    if provider:
        stmt = stmt.where(TokenUsage.provider == provider)

    # Get total count
    count_stmt = (
        select(func.count())
        .select_from(TokenUsage)
        .where(TokenUsage.user_id == current_user.id)
    )
    if provider:
        count_stmt = count_stmt.where(TokenUsage.provider == provider)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    # Calculate pagination
    offset = (page - 1) * page_size
    total_pages = (total + page_size - 1) // page_size  # Ceiling division

    # Get paginated results
    stmt = stmt.offset(offset).limit(page_size)
    result = await db.execute(stmt)
    usage_records = result.scalars().all()

    # Convert to response models
    items = [TokenUsageResponse.model_validate(record) for record in usage_records]

    return UsageHistoryResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/breakdown", response_model=UsageBreakdownResponse)
async def get_breakdown(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> UsageBreakdownResponse:
    """Get token usage breakdown by provider and model for current billing period.

    Returns detailed breakdown showing usage per provider and model combination.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Usage breakdown with provider and model details
    """
    service = TokenSyncService(db)

    # Get breakdown for current billing period
    breakdown = await service.get_usage_breakdown(current_user.id)

    # Get quota info for totals
    quota_info = await service.get_quota_with_alerts(current_user.id)

    return UsageBreakdownResponse(
        by_provider=breakdown,
        total_tokens=quota_info["tokens_used"],
        period_start=quota_info["period_start"],
        period_end=quota_info["period_end"],
    )


@router.get("/monthly-history", response_model=list[MonthlyHistoryResponse])
async def get_monthly_history(
    current_user: CurrentUser,
    months: int = Query(
        default=12,
        ge=1,
        le=24,
        description="Number of months to retrieve (max 24)",
    ),
    db: AsyncSession = Depends(get_db),
) -> list[MonthlyHistoryResponse]:
    """Get historical token usage by month.

    Returns monthly aggregated usage data for trend analysis.

    Args:
        current_user: Currently authenticated user
        months: Number of months to retrieve (1-24)
        db: Database session

    Returns:
        List of monthly usage records
    """
    service = TokenSyncService(db)

    # Get historical usage
    history = await service.get_historical_usage(current_user.id, months)

    # Convert to response model
    return [MonthlyHistoryResponse(**record) for record in history]


@router.get("/quota-detailed", response_model=dict)
async def get_quota_detailed(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get detailed quota information with alert status.

    Returns comprehensive quota information including usage alerts
    and warning indicators for response headers.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Detailed quota information with alert flags
    """
    service = TokenSyncService(db)
    return await service.get_quota_with_alerts(current_user.id)
