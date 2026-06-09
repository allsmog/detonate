from pydantic import BaseModel, Field


class ChallengeSummary(BaseModel):
    """Public challenge info — never includes the flag."""

    slug: str
    title: str
    description: str
    category: str
    difficulty: str
    points: int
    hints: list[str] = []
    module_ref: str | None = None
    solved: bool = False
    solve_count: int = 0


class ChallengeListResponse(BaseModel):
    challenges: list[ChallengeSummary]
    total: int
    total_points: int


class FlagSubmitRequest(BaseModel):
    flag: str = Field(..., min_length=1, max_length=512)
    # Anonymous leaderboard handle, used when auth is disabled.
    player: str | None = Field(default=None, max_length=64)


class FlagSubmitResponse(BaseModel):
    correct: bool
    slug: str
    points_awarded: int = 0
    first_solve: bool = False
    message: str


class LeaderboardEntry(BaseModel):
    player: str
    points: int
    solves: int


class LeaderboardResponse(BaseModel):
    entries: list[LeaderboardEntry]
