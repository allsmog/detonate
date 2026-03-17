import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from detonate.api.deps import get_current_user, get_db
from detonate.models.team import Team, TeamMember
from detonate.models.user import User
from detonate.schemas.team import (
    AddMemberRequest,
    TeamCreateRequest,
    TeamDetailResponse,
    TeamListResponse,
    TeamMemberResponse,
    TeamResponse,
    TeamUpdateRequest,
)

logger = logging.getLogger("detonate.api.routes.teams")

router = APIRouter(prefix="/teams", tags=["teams"])


async def _get_member_role(
    db: AsyncSession, team_id: UUID, user_id: UUID
) -> str | None:
    """Return the role of a user in a team, or None if not a member."""
    result = await db.execute(
        select(TeamMember.role).where(
            TeamMember.team_id == team_id,
            TeamMember.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


async def _require_team_admin(
    db: AsyncSession, team_id: UUID, user: User
) -> str:
    """Verify the user is an owner or admin of the team. Returns the role."""
    if user.role == "admin":
        # Global admins can manage any team
        return "admin"
    role = await _get_member_role(db, team_id, user.id)
    if role not in ("owner", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Only team owners and admins can perform this action",
        )
    return role


@router.post("", response_model=TeamResponse, status_code=201)
async def create_team(
    body: TeamCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TeamResponse:
    """Create a new team. The authenticated user becomes the owner."""
    team = Team(
        name=body.name,
        description=body.description,
    )
    db.add(team)
    await db.flush()

    # Add creator as owner
    owner_member = TeamMember(
        team_id=team.id,
        user_id=current_user.id,
        role="owner",
    )
    db.add(owner_member)
    await db.flush()

    logger.info("Team '%s' created by user %s", team.name, current_user.id)

    return TeamResponse(
        id=str(team.id),
        name=team.name,
        description=team.description,
        is_active=team.is_active,
        created_at=team.created_at,
        member_count=1,
    )


@router.get("", response_model=TeamListResponse)
async def list_teams(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TeamListResponse:
    """List all teams the current user belongs to."""
    # Subquery to count members per team
    member_count_sq = (
        select(
            TeamMember.team_id,
            func.count(TeamMember.id).label("member_count"),
        )
        .group_by(TeamMember.team_id)
        .subquery()
    )

    if current_user.role == "admin":
        # Global admins see all active teams
        query = (
            select(Team, func.coalesce(member_count_sq.c.member_count, 0))
            .outerjoin(member_count_sq, Team.id == member_count_sq.c.team_id)
            .where(Team.is_active.is_(True))
            .order_by(Team.created_at.desc())
        )
    else:
        # Regular users see only their teams
        query = (
            select(Team, func.coalesce(member_count_sq.c.member_count, 0))
            .join(TeamMember, TeamMember.team_id == Team.id)
            .outerjoin(member_count_sq, Team.id == member_count_sq.c.team_id)
            .where(
                TeamMember.user_id == current_user.id,
                Team.is_active.is_(True),
            )
            .order_by(Team.created_at.desc())
        )

    result = await db.execute(query)
    rows = result.all()

    items = []
    for team, count in rows:
        items.append(
            TeamResponse(
                id=str(team.id),
                name=team.name,
                description=team.description,
                is_active=team.is_active,
                created_at=team.created_at,
                member_count=count,
            )
        )

    return TeamListResponse(items=items, total=len(items))


@router.get("/{team_id}", response_model=TeamDetailResponse)
async def get_team(
    team_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TeamDetailResponse:
    """Get team details including member list."""
    result = await db.execute(
        select(Team)
        .options(selectinload(Team.members).selectinload(TeamMember.user))
        .where(Team.id == team_id, Team.is_active.is_(True))
    )
    team = result.scalar_one_or_none()
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")

    # Verify access: must be a member or global admin
    if current_user.role != "admin":
        is_member = any(m.user_id == current_user.id for m in team.members)
        if not is_member:
            raise HTTPException(status_code=403, detail="Not a member of this team")

    members = [
        TeamMemberResponse(
            id=str(m.id),
            user_id=str(m.user_id),
            email=m.user.email,
            display_name=m.user.display_name,
            role=m.role,
            joined_at=m.joined_at,
        )
        for m in team.members
    ]

    return TeamDetailResponse(
        id=str(team.id),
        name=team.name,
        description=team.description,
        is_active=team.is_active,
        created_at=team.created_at,
        member_count=len(members),
        members=members,
    )


@router.patch("/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: UUID,
    body: TeamUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TeamResponse:
    """Update team name or description. Requires owner or admin role."""
    await _require_team_admin(db, team_id, current_user)

    result = await db.execute(
        select(Team).where(Team.id == team_id, Team.is_active.is_(True))
    )
    team = result.scalar_one_or_none()
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")

    if body.name is not None:
        team.name = body.name.strip()
    if body.description is not None:
        team.description = body.description
    await db.flush()

    # Get member count
    count_result = await db.execute(
        select(func.count(TeamMember.id)).where(TeamMember.team_id == team_id)
    )
    member_count = count_result.scalar_one()

    return TeamResponse(
        id=str(team.id),
        name=team.name,
        description=team.description,
        is_active=team.is_active,
        created_at=team.created_at,
        member_count=member_count,
    )


@router.post("/{team_id}/members", response_model=TeamMemberResponse, status_code=201)
async def add_member(
    team_id: UUID,
    body: AddMemberRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TeamMemberResponse:
    """Add a member to the team by email. Requires owner or admin role."""
    await _require_team_admin(db, team_id, current_user)

    # Verify team exists
    team_result = await db.execute(
        select(Team).where(Team.id == team_id, Team.is_active.is_(True))
    )
    if team_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Team not found")

    # Look up user by email
    user_result = await db.execute(
        select(User).where(
            User.email == body.user_email.lower().strip(),
            User.is_active.is_(True),
        )
    )
    target_user = user_result.scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if already a member
    existing = await _get_member_role(db, team_id, target_user.id)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="User is already a member of this team",
        )

    member = TeamMember(
        team_id=team_id,
        user_id=target_user.id,
        role=body.role,
    )
    db.add(member)
    await db.flush()

    logger.info(
        "User %s added to team %s with role '%s' by %s",
        target_user.id,
        team_id,
        body.role,
        current_user.id,
    )

    return TeamMemberResponse(
        id=str(member.id),
        user_id=str(target_user.id),
        email=target_user.email,
        display_name=target_user.display_name,
        role=member.role,
        joined_at=member.joined_at,
    )


@router.delete("/{team_id}/members/{user_id}", status_code=204)
async def remove_member(
    team_id: UUID,
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Remove a member from the team. Requires owner or admin role.

    Owners cannot be removed (they must delete the team instead).
    Users can also remove themselves from a team.
    """
    # Allow self-removal without admin check
    is_self_removal = user_id == current_user.id
    if not is_self_removal:
        caller_role = await _require_team_admin(db, team_id, current_user)
    else:
        caller_role = await _get_member_role(db, team_id, current_user.id)

    # Find the member to remove
    result = await db.execute(
        select(TeamMember).where(
            TeamMember.team_id == team_id,
            TeamMember.user_id == user_id,
        )
    )
    member = result.scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")

    # Prevent removing an owner (unless a global admin is doing it)
    if member.role == "owner" and current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Cannot remove the team owner. Delete the team instead.",
        )

    # Non-global-admin team admins cannot remove other admins
    if (
        member.role == "admin"
        and caller_role == "admin"
        and current_user.role != "admin"
        and not is_self_removal
    ):
        raise HTTPException(
            status_code=403,
            detail="Team admins cannot remove other admins. Only the owner can.",
        )

    await db.delete(member)
    await db.flush()

    logger.info(
        "User %s removed from team %s by %s",
        user_id,
        team_id,
        current_user.id,
    )
    return Response(status_code=204)


@router.delete("/{team_id}", status_code=204)
async def delete_team(
    team_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Soft-delete a team. Only the team owner or a global admin can do this."""
    if current_user.role != "admin":
        role = await _get_member_role(db, team_id, current_user.id)
        if role != "owner":
            raise HTTPException(
                status_code=403,
                detail="Only the team owner can delete the team",
            )

    result = await db.execute(
        select(Team).where(Team.id == team_id, Team.is_active.is_(True))
    )
    team = result.scalar_one_or_none()
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")

    team.is_active = False
    await db.flush()

    logger.info("Team %s deleted by user %s", team_id, current_user.id)
    return Response(status_code=204)
