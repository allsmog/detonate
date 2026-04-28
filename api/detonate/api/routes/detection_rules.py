"""Auto-generated detection-rule endpoints.

YARA / Sigma / Suricata rules derived from the most-recent completed
analysis for a submission. All endpoints stream pure text where useful
and JSON otherwise. The rules are deterministic for a given input so a
caller can re-fetch without side-effects.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, get_storage
from detonate.config import settings
from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.services.sigma_generator import generate_sigma_rule
from detonate.services.static_analysis import run_static_analysis
from detonate.services.storage import StorageService
from detonate.services.suricata_generator import generate_suricata_rules
from detonate.services.yara_generator import generate_yara_rule

logger = logging.getLogger("detonate.api.routes.detection_rules")
router = APIRouter(tags=["detection-rules"])


async def _submission_or_404(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(select(Submission).where(Submission.id == submission_id))
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


async def _latest_completed_analysis(db: AsyncSession, submission_id: UUID) -> Analysis | None:
    result = await db.execute(
        select(Analysis)
        .where(Analysis.submission_id == submission_id)
        .order_by(Analysis.created_at.desc())
    )
    for analysis in result.scalars().all():
        if (analysis.result or {}):
            return analysis
    return None


@router.get("/submissions/{submission_id}/yara-rule", response_class=PlainTextResponse)
async def get_yara_rule(
    submission_id: UUID,
    threshold: int = Query(default=3, ge=1, le=12),
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
) -> PlainTextResponse:
    """Generate a YARA rule from the sample's static-analysis strings."""
    if not settings.yara_generator_enabled:
        raise HTTPException(status_code=503, detail="YARA generator disabled")
    submission = await _submission_or_404(db, submission_id)
    try:
        data = storage.get_file(submission.storage_path)
    except Exception:
        raise HTTPException(status_code=404, detail="File not found in storage")
    static = await run_static_analysis(
        data, submission.filename or "sample", mime=getattr(submission, "mime_type", None)
    )
    static["sha256"] = submission.file_hash_sha256 or ""
    rule = generate_yara_rule(static, threshold=threshold)
    if not rule.get("yara"):
        raise HTTPException(
            status_code=422,
            detail=rule.get("warning") or "Could not generate a rule",
        )
    return PlainTextResponse(rule["yara"], media_type="text/plain; charset=utf-8")


@router.get("/submissions/{submission_id}/sigma")
async def get_sigma_rule(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Generate a Sigma rule from the latest completed dynamic analysis."""
    if not settings.sigma_generator_enabled:
        raise HTTPException(status_code=503, detail="Sigma generator disabled")
    submission = await _submission_or_404(db, submission_id)
    analysis = await _latest_completed_analysis(db, submission_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No completed analysis found for submission",
        )
    return generate_sigma_rule(
        analysis.result or {},
        sample_sha256=submission.file_hash_sha256 or "",
    )


@router.get("/submissions/{submission_id}/suricata", response_class=PlainTextResponse)
async def get_suricata_rules(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    """Generate Suricata rules from the latest completed PCAP analysis."""
    if not settings.suricata_generator_enabled:
        raise HTTPException(status_code=503, detail="Suricata generator disabled")
    submission = await _submission_or_404(db, submission_id)
    analysis = await _latest_completed_analysis(db, submission_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No completed analysis found for submission",
        )
    rules = generate_suricata_rules(
        analysis.result or {},
        sample_sha256=submission.file_hash_sha256 or "",
    )
    if not rules.get("rules"):
        raise HTTPException(
            status_code=422,
            detail="No network indicators in analysis result",
        )
    return PlainTextResponse(rules["rules"], media_type="text/plain; charset=utf-8")
