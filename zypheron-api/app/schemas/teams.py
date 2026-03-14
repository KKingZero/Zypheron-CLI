"""Team management schemas for Enterprise tier.

Defines the API contract for team collaboration features including:
- Team creation and management
- Member invitations and management
- Role-based access control within teams

These schemas represent the future implementation of Enterprise features.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class TeamCreate(BaseModel):
    """Request schema for creating a new team.

    Teams allow Enterprise users to collaborate and share resources.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Team name",
        examples=["Engineering Team", "Security Ops"],
    )
    description: str | None = Field(
        None,
        max_length=500,
        description="Optional team description",
        examples=["Main engineering team for product development"],
    )


class TeamUpdate(BaseModel):
    """Request schema for updating team information.

    All fields are optional - only provided fields will be updated.
    """

    name: str | None = Field(
        None,
        min_length=1,
        max_length=100,
        description="Updated team name",
    )
    description: str | None = Field(
        None,
        max_length=500,
        description="Updated team description",
    )


class TeamMember(BaseModel):
    """Team member information with role.

    Represents a user's membership in a team with their assigned role.
    """

    user_id: int = Field(..., description="User ID of the team member")
    email: str = Field(..., description="Email address of the team member")
    role: Literal["owner", "admin", "member"] = Field(
        ...,
        description="Member's role in the team",
    )
    joined_at: datetime = Field(..., description="When the member joined the team")

    model_config = {"from_attributes": True}


class TeamResponse(BaseModel):
    """Response schema for team information.

    Includes team details and basic metadata.
    """

    id: int = Field(..., description="Team ID")
    name: str = Field(..., description="Team name")
    description: str | None = Field(None, description="Team description")
    owner_id: int = Field(..., description="User ID of the team owner")
    created_at: datetime = Field(..., description="Team creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    member_count: int = Field(
        default=0,
        description="Number of members in the team",
    )

    model_config = {"from_attributes": True}


class TeamMemberAdd(BaseModel):
    """Request schema for adding a member to a team.

    Can add by user_id (if already registered) or email (send invitation).
    """

    user_id: int | None = Field(
        None,
        description="User ID to add (for existing users)",
    )
    email: EmailStr | None = Field(
        None,
        description="Email address to invite (for new users)",
    )
    role: Literal["admin", "member"] = Field(
        default="member",
        description="Role to assign (owner role cannot be assigned)",
    )


class TeamInvitationCreate(BaseModel):
    """Request schema for creating a team invitation.

    Invitations are sent to users who haven't joined the team yet.
    """

    email: EmailStr = Field(
        ...,
        description="Email address to send invitation to",
    )
    role: Literal["admin", "member"] = Field(
        default="member",
        description="Role to assign when invitation is accepted",
    )
    message: str | None = Field(
        None,
        max_length=500,
        description="Optional custom message to include in invitation",
    )


class TeamInvitationResponse(BaseModel):
    """Response schema for team invitation information.

    Represents a pending invitation to join a team.
    """

    id: int = Field(..., description="Invitation ID")
    team_id: int = Field(..., description="Team ID")
    team_name: str = Field(..., description="Team name")
    email: str = Field(..., description="Invited email address")
    role: Literal["admin", "member"] = Field(..., description="Assigned role")
    status: Literal["pending", "accepted", "expired"] = Field(
        ...,
        description="Invitation status",
    )
    created_at: datetime = Field(..., description="Invitation creation timestamp")
    expires_at: datetime = Field(..., description="Invitation expiration timestamp")

    model_config = {"from_attributes": True}


class TeamListResponse(BaseModel):
    """Response schema for listing teams.

    Returns a list of teams the user is a member of.
    """

    teams: list[TeamResponse] = Field(..., description="List of teams")
    total: int = Field(..., description="Total number of teams")


class TeamMemberListResponse(BaseModel):
    """Response schema for listing team members.

    Returns all members of a specific team.
    """

    members: list[TeamMember] = Field(..., description="List of team members")
    total: int = Field(..., description="Total number of members")
