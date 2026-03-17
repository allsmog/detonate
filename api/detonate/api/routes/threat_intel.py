import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.schemas.threat_intel import (
    ThreatIntelAggregateResponse,
    ThreatIntelHashResponse,
    ThreatIntelIPResponse,
    ThreatIntelProviderResult,
    ThreatIntelProviderStatus,
    ThreatIntelStatusResponse,
)
from detonate.services.threat_intel.service import ThreatIntelService

logger = logging.getLogger("detonate.api.routes.threat_intel")

router = APIRouter(tags=["threat-intel"])

# Module-level singleton so provider init happens once.
_service: ThreatIntelService | None = None


def _get_service() -> ThreatIntelService:
    global _service
    if _service is None:
        _service = ThreatIntelService()
    return _service


@router.get(
    "/submissions/{submission_id}/threat-intel",
    response_model=ThreatIntelAggregateResponse,
)
async def get_submission_threat_intel(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelAggregateResponse:
    """Run threat-intel enrichment for a submission.

    Looks up the file hash across all configured providers and, if a
    completed dynamic analysis exists, also looks up network indicators
    (IPs, domains) extracted from the analysis results.
    """
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Get latest completed analysis (if any)
    analysis_result = await db.execute(
        select(Analysis)
        .where(
            Analysis.submission_id == submission.id,
            Analysis.status == "completed",
        )
        .order_by(Analysis.completed_at.desc())
        .limit(1)
    )
    analysis = analysis_result.scalar_one_or_none()

    service = _get_service()
    enrichment = await service.enrich_submission(db, submission, analysis)

    return ThreatIntelAggregateResponse(
        hash_results=[
            ThreatIntelProviderResult(**r) for r in enrichment.get("hash_results", [])
        ],
        ip_results={
            ip: [ThreatIntelProviderResult(**r) for r in results]
            for ip, results in enrichment.get("ip_results", {}).items()
        },
        domain_results={
            domain: [ThreatIntelProviderResult(**r) for r in results]
            for domain, results in enrichment.get("domain_results", {}).items()
        },
    )


@router.get(
    "/threat-intel/hash/{sha256}",
    response_model=ThreatIntelHashResponse,
)
async def lookup_hash(sha256: str) -> ThreatIntelHashResponse:
    """Direct file-hash lookup across all configured providers."""
    service = _get_service()
    results = await service.lookup_hash(sha256)
    return ThreatIntelHashResponse(
        sha256=sha256,
        results=[ThreatIntelProviderResult(**r) for r in results],
    )


@router.get(
    "/threat-intel/ip/{ip}",
    response_model=ThreatIntelIPResponse,
)
async def lookup_ip(ip: str) -> ThreatIntelIPResponse:
    """Direct IP-address lookup across all configured providers."""
    service = _get_service()
    results = await service.lookup_ip(ip)
    return ThreatIntelIPResponse(
        ip=ip,
        results=[ThreatIntelProviderResult(**r) for r in results],
    )


@router.get(
    "/threat-intel/status",
    response_model=ThreatIntelStatusResponse,
)
async def threat_intel_status() -> ThreatIntelStatusResponse:
    """Return which threat-intel providers are configured."""
    service = _get_service()
    statuses = service.get_status()
    return ThreatIntelStatusResponse(
        providers=[ThreatIntelProviderStatus(**s) for s in statuses],
    )
