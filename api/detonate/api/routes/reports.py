"""Report generation and auto-tagging routes.

Provides endpoints for:
- HTML threat report generation (view and download)
- CSV IOC export
- Automatic tag inference from analysis results
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.models.submission import Submission
from detonate.services.auto_tagger import auto_tag_submission
from detonate.services.pdf_report import (
    build_csv_iocs,
    build_html_report,
    get_latest_analysis,
)

logger = logging.getLogger("detonate.api.routes.reports")

router = APIRouter(tags=["reports"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_submission(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


async def _build_report(
    db: AsyncSession,
    submission: Submission,
) -> str:
    """Fetch latest analysis + AI summary and build the HTML report."""
    analysis = await get_latest_analysis(db, submission.id)

    # Use the cached AI summary as the AI report section (if available)
    ai_report = submission.ai_summary

    return build_html_report(submission, analysis, ai_report)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "/submissions/{submission_id}/report/html",
    response_class=HTMLResponse,
    summary="View HTML threat report",
    description=(
        "Generate and return a self-contained HTML threat report for the "
        "submission.  Includes file metadata, dynamic analysis results, "
        "IDS alerts, YARA matches, and the AI summary if available."
    ),
)
async def get_html_report(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Generate and return an HTML report for inline viewing."""
    submission = await _get_submission(db, submission_id)
    html_content = await _build_report(db, submission)
    return HTMLResponse(content=html_content)


@router.get(
    "/submissions/{submission_id}/report/download",
    summary="Download HTML threat report",
    description=(
        "Generate an HTML threat report and return it as a downloadable file.  "
        "The browser will prompt the user to save the file."
    ),
    responses={
        200: {
            "content": {"text/html": {}},
            "description": "HTML report file download",
        },
        404: {"description": "Submission not found"},
    },
)
async def download_html_report(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Generate an HTML report and return it as a file download."""
    submission = await _get_submission(db, submission_id)
    html_content = await _build_report(db, submission)

    safe_name = (submission.filename or "unknown").replace('"', "")
    filename = f"detonate-report-{safe_name}.html"

    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get(
    "/submissions/{submission_id}/report/iocs",
    summary="Download CSV IOCs",
    description=(
        "Export indicators of compromise (hashes, IPs, domains, dropped files) "
        "from the submission and its latest analysis as a CSV file."
    ),
    responses={
        200: {
            "content": {"text/csv": {}},
            "description": "CSV IOC export",
        },
        404: {"description": "Submission not found"},
    },
)
async def download_csv_iocs(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a downloadable CSV file."""
    submission = await _get_submission(db, submission_id)
    analysis = await get_latest_analysis(db, submission.id)
    csv_content = build_csv_iocs(submission, analysis)

    safe_name = (submission.filename or "unknown").replace('"', "")
    filename = f"detonate-iocs-{safe_name}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post(
    "/submissions/{submission_id}/auto-tag",
    summary="Auto-tag submission",
    description=(
        "Run automatic tag inference on the submission.  Examines file type, "
        "analysis results, verdict, and score to apply descriptive tags.  "
        "Existing tags are preserved."
    ),
)
async def auto_tag(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Run auto-tagging on a submission and return the updated tags."""
    submission = await _get_submission(db, submission_id)
    analysis = await get_latest_analysis(db, submission.id)

    tags = await auto_tag_submission(db, submission, analysis)

    return {
        "submission_id": str(submission_id),
        "tags": tags,
        "count": len(tags),
    }
