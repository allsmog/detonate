"""Submission sharing and visibility service.

Visibility rules:
- Submissions are private by default (only the owner can see them when auth is enabled).
- Global admins can see all submissions.
- Team members can see submissions owned by any member of their shared teams.
- A submission with a non-null ``share_token`` is accessible to anyone with that token.
"""

import logging
import secrets

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.submission import Submission
from detonate.models.team import TeamMember
from detonate.models.user import User

logger = logging.getLogger("detonate.services.sharing")

_SHARE_TOKEN_LENGTH = 22  # URL-safe, ~131 bits of entropy


async def get_visible_submissions(
    db: AsyncSession,
    user: User,
    *,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[Submission], int]:
    """Return submissions visible to *user* with pagination.

    Visibility is the union of:
    1. Submissions owned by the user.
    2. Submissions owned by any member of the user's teams.
    3. All submissions if the user is a global admin.

    Returns ``(items, total_count)``.
    """
    if user.role == "admin":
        # Admins see everything
        count_result = await db.execute(select(func.count(Submission.id)))
        total = count_result.scalar_one()

        query = (
            select(Submission)
            .order_by(Submission.submitted_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await db.execute(query)
        return list(result.scalars().all()), total

    # IDs of users who share a team with the current user
    teammate_ids_sq = (
        select(TeamMember.user_id)
        .where(
            TeamMember.team_id.in_(
                select(TeamMember.team_id).where(
                    TeamMember.user_id == user.id
                )
            )
        )
        .distinct()
        .subquery()
    )

    visibility_filter = or_(
        Submission.user_id == user.id,
        Submission.user_id.in_(select(teammate_ids_sq.c.user_id)),
    )

    count_result = await db.execute(
        select(func.count(Submission.id)).where(visibility_filter)
    )
    total = count_result.scalar_one()

    query = (
        select(Submission)
        .where(visibility_filter)
        .order_by(Submission.submitted_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(query)
    return list(result.scalars().all()), total


async def can_view_submission(
    db: AsyncSession,
    submission: Submission,
    user: User | None,
) -> bool:
    """Check whether *user* is allowed to view *submission*.

    Returns ``True`` if any of the following hold:
    - ``user`` is None (auth is disabled, everything is public).
    - ``user`` is a global admin.
    - ``user`` owns the submission.
    - ``user`` and the submission owner share a team.
    """
    if user is None:
        # Auth disabled - everything is visible
        return True

    if user.role == "admin":
        return True

    if submission.user_id is None:
        # Anonymous submissions (pre-auth) are visible to everyone
        return True

    if submission.user_id == user.id:
        return True

    # Check team overlap
    if await _share_team(db, user.id, submission.user_id):
        return True

    return False


async def _share_team(
    db: AsyncSession,
    user_id_a,
    user_id_b,
) -> bool:
    """Return True if both users share at least one active team."""
    teams_a = select(TeamMember.team_id).where(TeamMember.user_id == user_id_a)
    teams_b = select(TeamMember.team_id).where(TeamMember.user_id == user_id_b)

    result = await db.execute(
        select(func.count()).select_from(
            teams_a.intersect(teams_b).subquery()
        )
    )
    return result.scalar_one() > 0


async def create_share_link(
    db: AsyncSession,
    submission: Submission,
    user: User,
) -> str:
    """Generate a URL-safe share token for a submission.

    The token is stored on the submission's ``share_token`` column.
    Only the submission owner or a global admin can generate a link.

    Returns the generated token string.
    """
    if user.role != "admin" and submission.user_id != user.id:
        raise PermissionError("Only the submission owner or an admin can create a share link")

    # If a token already exists, return it rather than generating a new one
    if hasattr(submission, "share_token") and submission.share_token:
        return submission.share_token

    token = secrets.token_urlsafe(_SHARE_TOKEN_LENGTH)

    # Store the token on the submission
    if hasattr(submission, "share_token"):
        submission.share_token = token
        await db.flush()
    else:
        # Fallback: store in threat_intel JSONB (repurpose existing column)
        # until a migration adds share_token column
        if submission.threat_intel is None:
            submission.threat_intel = {}
        submission.threat_intel = {**submission.threat_intel, "_share_token": token}
        await db.flush()

    logger.info(
        "Share link created for submission %s by user %s",
        submission.id,
        user.id,
    )
    return token


async def get_by_share_token(
    db: AsyncSession,
    token: str,
) -> Submission | None:
    """Look up a submission by its share token.

    Checks both the dedicated ``share_token`` column (if present) and the
    ``threat_intel._share_token`` JSONB fallback.
    """
    # Try dedicated column first
    try:
        result = await db.execute(
            select(Submission).where(Submission.share_token == token)  # type: ignore[attr-defined]
        )
        submission = result.scalar_one_or_none()
        if submission is not None:
            return submission
    except Exception:
        # Column doesn't exist yet; fall through to JSONB lookup
        pass

    # Fallback: check JSONB field
    result = await db.execute(
        select(Submission).where(
            Submission.threat_intel["_share_token"].astext == token
        )
    )
    return result.scalar_one_or_none()


async def revoke_share_link(
    db: AsyncSession,
    submission: Submission,
    user: User,
) -> None:
    """Remove the share token from a submission."""
    if user.role != "admin" and submission.user_id != user.id:
        raise PermissionError("Only the submission owner or an admin can revoke a share link")

    if hasattr(submission, "share_token") and submission.share_token:
        submission.share_token = None

    if (
        submission.threat_intel
        and isinstance(submission.threat_intel, dict)
        and "_share_token" in submission.threat_intel
    ):
        updated = {k: v for k, v in submission.threat_intel.items() if k != "_share_token"}
        submission.threat_intel = updated

    await db.flush()
    logger.info(
        "Share link revoked for submission %s by user %s",
        submission.id,
        user.id,
    )
