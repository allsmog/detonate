import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_current_user_optional, get_db
from detonate.models.challenge import Challenge, ChallengeSolve
from detonate.schemas.challenge import (
    ChallengeListResponse,
    ChallengeSummary,
    FlagSubmitRequest,
    FlagSubmitResponse,
    LeaderboardEntry,
    LeaderboardResponse,
)
from detonate.services.challenge import (
    has_solved,
    seed_default_challenges,
    solve_count,
    verify_flag,
)

logger = logging.getLogger("detonate.api.routes.challenges")

router = APIRouter(prefix="/challenges", tags=["challenges"])


def _resolve_player(user, requested: str | None) -> str:
    """Identify the player for solve tracking: the authenticated user's email
    when available, otherwise the supplied handle, otherwise 'anonymous'."""
    if user is not None:
        return getattr(user, "email", None) or str(getattr(user, "id", "user"))
    handle = (requested or "").strip()
    return handle[:64] if handle else "anonymous"


async def _all_challenges(db: AsyncSession) -> list[Challenge]:
    # Lazily seed the built-in masterclass challenges on first access.
    await seed_default_challenges(db)
    result = await db.execute(select(Challenge).order_by(Challenge.order_index, Challenge.slug))
    return list(result.scalars())


@router.get("", response_model=ChallengeListResponse)
async def list_challenges(
    player: str | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    challenges = await _all_challenges(db)
    who = _resolve_player(user, player)

    summaries: list[ChallengeSummary] = []
    for c in challenges:
        summaries.append(
            ChallengeSummary(
                slug=c.slug,
                title=c.title,
                description=c.description,
                category=c.category,
                difficulty=c.difficulty,
                points=c.points,
                hints=c.hints or [],
                module_ref=c.module_ref,
                solved=await has_solved(db, c.id, who),
                solve_count=await solve_count(db, c.id),
            )
        )
    return ChallengeListResponse(
        challenges=summaries,
        total=len(summaries),
        total_points=sum(c.points for c in challenges),
    )


@router.get("/leaderboard", response_model=LeaderboardResponse)
async def leaderboard(db: AsyncSession = Depends(get_db)):
    await _all_challenges(db)  # ensure seeded
    # Sum points per player across their solves.
    stmt = (
        select(
            ChallengeSolve.player,
            func.coalesce(func.sum(Challenge.points), 0).label("points"),
            func.count(ChallengeSolve.id).label("solves"),
        )
        .join(Challenge, Challenge.id == ChallengeSolve.challenge_id)
        .group_by(ChallengeSolve.player)
        .order_by(func.coalesce(func.sum(Challenge.points), 0).desc())
        .limit(100)
    )
    result = await db.execute(stmt)
    entries = [
        LeaderboardEntry(player=row.player, points=int(row.points), solves=int(row.solves))
        for row in result
    ]
    return LeaderboardResponse(entries=entries)


@router.get("/{slug}", response_model=ChallengeSummary)
async def get_challenge(
    slug: str,
    player: str | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    await seed_default_challenges(db)
    result = await db.execute(select(Challenge).where(Challenge.slug == slug))
    c = result.scalar_one_or_none()
    if c is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    who = _resolve_player(user, player)
    return ChallengeSummary(
        slug=c.slug,
        title=c.title,
        description=c.description,
        category=c.category,
        difficulty=c.difficulty,
        points=c.points,
        hints=c.hints or [],
        module_ref=c.module_ref,
        solved=await has_solved(db, c.id, who),
        solve_count=await solve_count(db, c.id),
    )


@router.post("/{slug}/submit", response_model=FlagSubmitResponse)
async def submit_flag(
    slug: str,
    payload: FlagSubmitRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    await seed_default_challenges(db)
    result = await db.execute(select(Challenge).where(Challenge.slug == slug))
    c = result.scalar_one_or_none()
    if c is None:
        raise HTTPException(status_code=404, detail="Challenge not found")

    who = _resolve_player(user, payload.player)

    if not verify_flag(c, payload.flag):
        return FlagSubmitResponse(
            correct=False, slug=slug, message="Incorrect flag — keep digging."
        )

    already = await has_solved(db, c.id, who)
    if already:
        return FlagSubmitResponse(
            correct=True,
            slug=slug,
            points_awarded=0,
            first_solve=False,
            message=f"Correct — already solved by {who}.",
        )

    db.add(
        ChallengeSolve(
            challenge_id=c.id,
            user_id=getattr(user, "id", None),
            player=who,
        )
    )
    await db.flush()
    return FlagSubmitResponse(
        correct=True,
        slug=slug,
        points_awarded=c.points,
        first_solve=True,
        message=f"Correct! +{c.points} points.",
    )
