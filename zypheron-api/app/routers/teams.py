"""Team management router (Enterprise feature - Coming Soon).

This router contains stub endpoints for team collaboration features
that will be available to Enterprise tier customers.

All endpoints currently return HTTP 501 Not Implemented to indicate
that this feature is planned but not yet available. The schemas and
endpoint structure define the future API contract.

Features planned:
- Team creation and management
- Member invitations and role management
- Shared resource access across team members
- Team-level analytics and reporting
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.license import License
from app.models.user import User
from app.routers.auth import CurrentUser
from app.schemas.teams import (
    TeamCreate,
    TeamInvitationCreate,
    TeamInvitationResponse,
    TeamListResponse,
    TeamMemberAdd,
    TeamMemberListResponse,
    TeamResponse,
    TeamUpdate,
)

router = APIRouter(prefix="/teams", tags=["Teams"])


async def require_enterprise_tier(
    current_user: User,
    db: AsyncSession,
) -> None:
    """Verify that the current user has an Enterprise tier license.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Raises:
        HTTPException: If user doesn't have Enterprise tier (403 Forbidden)
    """
    # Get user's active license
    stmt = (
        select(License)
        .where(License.user_id == current_user.id)
        .order_by(License.created_at.desc())
    )
    result = await db.execute(stmt)
    license = result.scalar_one_or_none()

    # Check if license exists and is enterprise tier
    if not license or license.tier != "enterprise":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Enterprise tier required",
                "message": "This feature is only available to Enterprise tier customers.",
                "current_tier": license.tier if license else "free",
                "upgrade_url": "/license/tiers",
            },
        )


# Type alias for enterprise tier dependency
EnterpriseUser = Annotated[User, Depends(require_enterprise_tier)]


@router.post(
    "",
    response_model=TeamResponse,
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Create a team",
    description="Create a new team (Enterprise feature - Coming Soon)",
)
async def create_team(
    team_data: TeamCreate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a new team (Stub endpoint).

    This endpoint will allow Enterprise users to create teams for collaboration.

    Args:
        team_data: Team creation data (name, description)
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Team creation response

    Raises:
        HTTPException: 403 if not Enterprise tier, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "team_creation",
            "status": "planned",
        },
    )


@router.get(
    "",
    response_model=TeamListResponse,
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="List user's teams",
    description="Get all teams the user is a member of (Enterprise feature - Coming Soon)",
)
async def list_teams(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List all teams the user is a member of (Stub endpoint).

    This endpoint will return all teams where the user is an owner, admin, or member.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        List of teams

    Raises:
        HTTPException: 403 if not Enterprise tier, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "list_teams",
            "status": "planned",
        },
    )


@router.get(
    "/{team_id}",
    response_model=TeamResponse,
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Get team details",
    description="Get detailed information about a specific team (Enterprise feature - Coming Soon)",
)
async def get_team(
    team_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get detailed information about a team (Stub endpoint).

    This endpoint will return full team details including metadata and member count.

    Args:
        team_id: Team ID to retrieve
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Team details

    Raises:
        HTTPException: 403 if not Enterprise tier, 404 if team not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "get_team",
            "status": "planned",
        },
    )


@router.put(
    "/{team_id}",
    response_model=TeamResponse,
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Update team",
    description="Update team information (Enterprise feature - Coming Soon)",
)
async def update_team(
    team_id: int,
    team_data: TeamUpdate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update team information (Stub endpoint).

    This endpoint will allow team owners/admins to update team details.

    Args:
        team_id: Team ID to update
        team_data: Updated team data
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Updated team details

    Raises:
        HTTPException: 403 if not Enterprise tier or not authorized, 404 if team not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "update_team",
            "status": "planned",
        },
    )


@router.delete(
    "/{team_id}",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Delete team",
    description="Delete a team (Enterprise feature - Coming Soon)",
)
async def delete_team(
    team_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a team (Stub endpoint).

    This endpoint will allow team owners to delete teams.
    This action will be irreversible and will remove all team data.

    Args:
        team_id: Team ID to delete
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Deletion confirmation

    Raises:
        HTTPException: 403 if not Enterprise tier or not owner, 404 if team not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "delete_team",
            "status": "planned",
        },
    )


@router.post(
    "/{team_id}/members",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Add team member",
    description="Add a member to the team (Enterprise feature - Coming Soon)",
)
async def add_team_member(
    team_id: int,
    member_data: TeamMemberAdd,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Add a member to the team (Stub endpoint).

    This endpoint will allow team owners/admins to add new members by user ID or email.

    Args:
        team_id: Team ID to add member to
        member_data: Member data (user_id or email, role)
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Added member details

    Raises:
        HTTPException: 403 if not Enterprise tier or not authorized, 404 if team/user not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "add_team_member",
            "status": "planned",
        },
    )


@router.delete(
    "/{team_id}/members/{user_id}",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Remove team member",
    description="Remove a member from the team (Enterprise feature - Coming Soon)",
)
async def remove_team_member(
    team_id: int,
    user_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Remove a member from the team (Stub endpoint).

    This endpoint will allow team owners/admins to remove members from the team.

    Args:
        team_id: Team ID to remove member from
        user_id: User ID of the member to remove
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Removal confirmation

    Raises:
        HTTPException: 403 if not Enterprise tier or not authorized, 404 if team/user not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "remove_team_member",
            "status": "planned",
        },
    )


@router.get(
    "/{team_id}/members",
    response_model=TeamMemberListResponse,
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="List team members",
    description="Get all members of a team (Enterprise feature - Coming Soon)",
)
async def list_team_members(
    team_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List all members of a team (Stub endpoint).

    This endpoint will return all members with their roles and join dates.

    Args:
        team_id: Team ID to list members for
        current_user: Currently authenticated user
        db: Database session

    Returns:
        List of team members

    Raises:
        HTTPException: 403 if not Enterprise tier, 404 if team not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "list_team_members",
            "status": "planned",
        },
    )


@router.post(
    "/{team_id}/invitations",
    response_model=TeamInvitationResponse,
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Create team invitation",
    description="Invite a user to join the team (Enterprise feature - Coming Soon)",
)
async def create_team_invitation(
    team_id: int,
    invitation_data: TeamInvitationCreate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create an invitation to join the team (Stub endpoint).

    This endpoint will send an email invitation to join the team.

    Args:
        team_id: Team ID to invite user to
        invitation_data: Invitation data (email, role, message)
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Created invitation details

    Raises:
        HTTPException: 403 if not Enterprise tier or not authorized, 404 if team not found, 501 if feature not implemented
    """
    # Verify Enterprise tier
    await require_enterprise_tier(current_user, db)

    # Return not implemented response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": "Team management coming soon. Stay tuned!",
            "feature": "create_team_invitation",
            "status": "planned",
        },
    )
