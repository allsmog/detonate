import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, get_storage
from detonate.models.submission import Submission
from detonate.schemas.static_analysis import (
    PEAnalysisResult,
    StaticAnalysisResponse,
    StringsSearchResponse,
)
from detonate.services.static_analysis import run_static_analysis
from detonate.services.storage import StorageService

logger = logging.getLogger("detonate.api.routes.static_analysis")

router = APIRouter(tags=["static-analysis"])


async def _get_submission(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


async def _run_or_get_cached(
    submission: Submission,
    storage: StorageService,
) -> dict:
    """Fetch file data from storage and run static analysis.

    Results are returned directly each time since caching depends on a
    ``static_analysis`` JSONB column that may not exist on the model yet.
    When the column is added, this helper can be updated to read/write it.
    """
    try:
        file_data = storage.get_file(submission.storage_path)
    except Exception as exc:
        logger.error("Failed to retrieve file from storage: %s", exc)
        raise HTTPException(
            status_code=404,
            detail="File not found in storage",
        )

    filename = submission.filename or "unknown"
    return await run_static_analysis(file_data, filename)


@router.get(
    "/submissions/{submission_id}/static",
    response_model=StaticAnalysisResponse,
)
async def get_static_analysis(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
) -> StaticAnalysisResponse:
    """Run full static analysis on a submission's file.

    Returns entropy, extracted strings, PE analysis (if applicable),
    and ELF analysis (if applicable).
    """
    submission = await _get_submission(db, submission_id)
    results = await _run_or_get_cached(submission, storage)
    return StaticAnalysisResponse.model_validate(results)


@router.get(
    "/submissions/{submission_id}/strings",
    response_model=StringsSearchResponse,
)
async def get_strings(
    submission_id: UUID,
    search: str = Query(default="", description="Filter strings containing this text"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=100, ge=1, le=500, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
) -> StringsSearchResponse:
    """Return extracted strings with optional search filter and pagination."""
    submission = await _get_submission(db, submission_id)
    results = await _run_or_get_cached(submission, storage)
    strings_data = results.get("strings", {})

    ascii_strings: list[str] = strings_data.get("ascii_strings", [])
    wide_strings: list[str] = strings_data.get("wide_strings", [])
    interesting = strings_data.get("interesting", {})

    # Apply search filter across all string lists
    if search:
        search_lower = search.lower()
        ascii_strings = [s for s in ascii_strings if search_lower in s.lower()]
        wide_strings = [s for s in wide_strings if search_lower in s.lower()]
        # Also filter interesting strings
        interesting = {
            k: [s for s in v if search_lower in s.lower()]
            for k, v in interesting.items()
        }

    total_results = len(ascii_strings) + len(wide_strings)

    # Paginate ASCII strings (wide strings appended after)
    start = (page - 1) * page_size
    end = start + page_size
    paged_ascii = ascii_strings[start:end]
    # If we have room left after ASCII, include wide strings
    remaining = page_size - len(paged_ascii)
    wide_start = max(0, start - len(ascii_strings))
    paged_wide = wide_strings[wide_start : wide_start + remaining] if remaining > 0 else []

    return StringsSearchResponse(
        total_ascii=strings_data.get("total_ascii", 0),
        total_wide=strings_data.get("total_wide", 0),
        interesting=interesting,
        ascii_strings=paged_ascii,
        wide_strings=paged_wide,
        page=page,
        page_size=page_size,
        total_results=total_results,
    )


@router.get(
    "/submissions/{submission_id}/pe",
    response_model=PEAnalysisResult,
)
async def get_pe_analysis(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
) -> PEAnalysisResult:
    """Return PE analysis results. Returns 404 if the file is not a PE."""
    submission = await _get_submission(db, submission_id)
    results = await _run_or_get_cached(submission, storage)

    pe_data = results.get("pe")
    if pe_data is None:
        raise HTTPException(
            status_code=404,
            detail="File is not a PE executable or PE analysis failed",
        )

    return PEAnalysisResult.model_validate(pe_data)
