"""Pydantic schemas for search, dashboard, and analytics endpoints."""

from pydantic import BaseModel, Field


class SubmissionSearchItem(BaseModel):
    """A single submission in search results."""

    id: str
    filename: str | None = None
    file_hash_sha256: str
    file_hash_md5: str | None = None
    file_hash_sha1: str | None = None
    file_type: str | None = None
    mime_type: str | None = None
    verdict: str = "unknown"
    score: int = 0
    tags: list[str] = Field(default_factory=list)
    submitted_at: str | None = None
    file_size: int | None = None


class SearchFilters(BaseModel):
    """Active filters applied to a search query."""

    verdict: str | None = None
    file_type: str | None = None
    tag: str | None = None
    score_min: int | None = None
    score_max: int | None = None
    date_from: str | None = None
    date_to: str | None = None
    has_analysis: bool | None = None


class SearchResult(BaseModel):
    """Paginated search results with filter metadata."""

    items: list[SubmissionSearchItem]
    total: int
    limit: int
    offset: int
    query: str = ""
    filters: SearchFilters


class HashLookupResult(BaseModel):
    """Result of a hash lookup query."""

    items: list[SubmissionSearchItem]
    total: int


# -- Dashboard schemas --


class TypeCount(BaseModel):
    """A type or tag with its occurrence count."""

    type: str
    count: int


class AnalysisStatusBreakdown(BaseModel):
    """Breakdown of analysis statuses."""

    completed: int = 0
    failed: int = 0
    running: int = 0
    queued: int = 0


class DashboardStats(BaseModel):
    """Aggregate statistics for the dashboard overview."""

    total_submissions: int
    total_analyses: int
    verdicts: dict[str, int] = Field(
        default_factory=lambda: {
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "unknown": 0,
        }
    )
    submissions_today: int = 0
    submissions_this_week: int = 0
    submissions_this_month: int = 0
    average_score: float = 0.0
    top_file_types: list[TypeCount] = Field(default_factory=list)
    top_tags: list[TypeCount] = Field(default_factory=list)
    analysis_status_breakdown: AnalysisStatusBreakdown = Field(
        default_factory=AnalysisStatusBreakdown
    )


class TimelinePoint(BaseModel):
    """A single point on the submission timeline."""

    date: str
    count: int
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0


class TimelineResponse(BaseModel):
    """Timeline data for submission charts."""

    points: list[TimelinePoint]
    days: int
    granularity: str = "day"


class IOCEntry(BaseModel):
    """A single IOC (IP or domain) with its occurrence count."""

    value: str
    count: int


class TopIOCs(BaseModel):
    """Most frequently observed IOCs from analysis results."""

    ips: list[IOCEntry] = Field(default_factory=list)
    domains: list[IOCEntry] = Field(default_factory=list)
