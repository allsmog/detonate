"""Search and advanced filtering routes for submissions."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.schemas.search import (
    HashLookupResult,
    SearchFilters,
    SearchResult,
    SubmissionSearchItem,
)

logger = logging.getLogger("detonate.api.routes.search")

router = APIRouter(tags=["search"])


def _serialize_submission(s: Submission) -> SubmissionSearchItem:
    """Convert a Submission ORM object to a search result item."""
    return SubmissionSearchItem(
        id=str(s.id),
        filename=s.filename,
        file_hash_sha256=s.file_hash_sha256,
        file_hash_md5=s.file_hash_md5,
        file_hash_sha1=s.file_hash_sha1,
        file_type=s.file_type,
        mime_type=s.mime_type,
        verdict=s.verdict,
        score=s.score,
        tags=s.tags or [],
        submitted_at=str(s.submitted_at) if s.submitted_at else None,
        file_size=s.file_size,
    )


def _parse_iso_date(value: str, field_name: str) -> datetime:
    """Parse an ISO date string, raising HTTPException on failure."""
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid date format for '{field_name}': {value}. "
                "Use ISO 8601 format (e.g. 2024-01-15)."
            ),
        ) from exc


SORTABLE_COLUMNS = {"submitted_at", "score", "filename", "verdict"}
SORT_ORDERS = {"asc", "desc"}


@router.get("/search", response_model=SearchResult)
async def search_submissions(
    q: str = Query(default="", description="Search query (hash, filename, tag, IOC)"),
    verdict: str | None = Query(default=None, description="Filter by verdict"),
    file_type: str | None = Query(default=None, description="Filter by file type"),
    tag: str | None = Query(default=None, description="Filter by tag"),
    score_min: int | None = Query(default=None, ge=0, le=100, description="Minimum score"),
    score_max: int | None = Query(default=None, ge=0, le=100, description="Maximum score"),
    date_from: str | None = Query(default=None, description="Start date (ISO 8601)"),
    date_to: str | None = Query(default=None, description="End date (ISO 8601)"),
    has_analysis: bool | None = Query(default=None, description="Filter by analysis presence"),
    sort_by: str = Query(default="submitted_at", description="Sort field"),
    sort_order: str = Query(default="desc", description="Sort direction (asc/desc)"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> SearchResult:
    """Advanced search across submissions.

    Supports:
    - Full-text search by hash (SHA256, MD5, SHA1), filename, and tags
    - Filter by verdict (malicious, suspicious, clean, unknown)
    - Filter by file_type (partial match)
    - Filter by tag (exact match in array)
    - Score range filtering (0-100)
    - Date range filtering (ISO 8601)
    - Has-analysis filter (submissions with at least one analysis)
    - Sorting by submitted_at, score, filename, or verdict
    - Pagination with limit/offset
    """
    # Validate sort parameters
    if sort_by not in SORTABLE_COLUMNS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid sort_by: '{sort_by}'. "
            f"Must be one of: {', '.join(sorted(SORTABLE_COLUMNS))}",
        )
    if sort_order not in SORT_ORDERS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid sort_order: '{sort_order}'. Must be 'asc' or 'desc'.",
        )

    query = select(Submission)
    count_query = select(func.count(Submission.id))

    conditions = []

    # Full-text / hash search
    if q:
        q_lower = q.strip().lower()
        if q_lower:
            text_conditions = [
                func.lower(Submission.file_hash_sha256).contains(q_lower),
                func.lower(cast(Submission.file_hash_md5, String)).contains(q_lower),
                func.lower(cast(Submission.file_hash_sha1, String)).contains(q_lower),
                func.lower(cast(Submission.filename, String)).contains(q_lower),
            ]
            # Search within tags array
            text_conditions.append(Submission.tags.any(q_lower))
            conditions.append(or_(*text_conditions))

    # Verdict filter
    if verdict:
        valid_verdicts = {"malicious", "suspicious", "clean", "unknown"}
        if verdict.lower() not in valid_verdicts:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid verdict: '{verdict}'. "
                f"Must be one of: {', '.join(sorted(valid_verdicts))}",
            )
        conditions.append(func.lower(Submission.verdict) == verdict.lower())

    # File type filter (partial, case-insensitive)
    if file_type:
        conditions.append(
            func.lower(cast(Submission.file_type, String)).contains(file_type.lower())
        )

    # Tag filter (exact match in array)
    if tag:
        conditions.append(Submission.tags.any(tag))

    # Score range
    if score_min is not None:
        conditions.append(Submission.score >= score_min)
    if score_max is not None:
        conditions.append(Submission.score <= score_max)

    # Date range
    if date_from:
        parsed_from = _parse_iso_date(date_from, "date_from")
        conditions.append(Submission.submitted_at >= parsed_from)
    if date_to:
        parsed_to = _parse_iso_date(date_to, "date_to")
        conditions.append(Submission.submitted_at <= parsed_to)

    # Apply all conditions
    for cond in conditions:
        query = query.where(cond)
        count_query = count_query.where(cond)

    # Has-analysis subquery filter
    if has_analysis is not None:
        analysis_sub = select(Analysis.submission_id).distinct()
        if has_analysis:
            query = query.where(Submission.id.in_(analysis_sub))
            count_query = count_query.where(Submission.id.in_(analysis_sub))
        else:
            query = query.where(Submission.id.notin_(analysis_sub))
            count_query = count_query.where(Submission.id.notin_(analysis_sub))

    # Sorting
    sort_col = getattr(Submission, sort_by, Submission.submitted_at)
    if sort_order == "desc":
        query = query.order_by(desc(sort_col))
    else:
        query = query.order_by(sort_col.asc())

    # Execute count
    count_result = await db.execute(count_query)
    total = count_result.scalar_one()

    # Execute paginated query
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    submissions = result.scalars().all()

    return SearchResult(
        items=[_serialize_submission(s) for s in submissions],
        total=total,
        limit=limit,
        offset=offset,
        query=q,
        filters=SearchFilters(
            verdict=verdict,
            file_type=file_type,
            tag=tag,
            score_min=score_min,
            score_max=score_max,
            date_from=date_from,
            date_to=date_to,
            has_analysis=has_analysis,
        ),
    )


@router.get("/search/hash/{hash_value}", response_model=HashLookupResult)
async def lookup_hash(
    hash_value: str,
    db: AsyncSession = Depends(get_db),
) -> HashLookupResult:
    """Look up submissions by any hash (SHA256, MD5, or SHA1).

    Accepts full or partial hashes. Returns up to 10 matching submissions.
    """
    h = hash_value.strip().lower()
    if not h:
        raise HTTPException(status_code=422, detail="Hash value cannot be empty")

    # Determine hash type by length for exact matches
    conditions = [
        func.lower(Submission.file_hash_sha256).contains(h),
        func.lower(cast(Submission.file_hash_md5, String)).contains(h),
        func.lower(cast(Submission.file_hash_sha1, String)).contains(h),
    ]

    result = await db.execute(
        select(Submission)
        .where(or_(*conditions))
        .order_by(Submission.submitted_at.desc())
        .limit(10)
    )
    items = result.scalars().all()

    return HashLookupResult(
        items=[_serialize_submission(s) for s in items],
        total=len(items),
    )
