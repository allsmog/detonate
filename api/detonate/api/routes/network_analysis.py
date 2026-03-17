"""Routes for advanced network analysis enrichment and IOC extraction."""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.schemas.network_analysis import (
    NetworkAnalysisResponse,
    NetworkIOCsResponse,
)
from detonate.services.analysis import get_analysis
from detonate.services.network_analysis import (
    enrich_network_data,
    extract_network_iocs,
)

logger = logging.getLogger("detonate.api.routes.network_analysis")

router = APIRouter(tags=["network-analysis"])


async def _get_analysis_result(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession,
) -> dict:
    """Load an analysis and return its result dict, or raise 404."""
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    result = analysis.result
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Analysis has no results yet (still running or failed)",
        )
    return result


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/network",
    response_model=NetworkAnalysisResponse,
)
async def get_network_analysis(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> NetworkAnalysisResponse:
    """Return enriched network analysis data for a completed analysis.

    Enhances raw connection and PCAP data with service names, private/public
    classification, DNS breakdown, and suspicious indicator detection.
    """
    result = await _get_analysis_result(submission_id, analysis_id, db)
    enriched = enrich_network_data(result)
    return NetworkAnalysisResponse(**enriched)


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/network/iocs",
    response_model=NetworkIOCsResponse,
)
async def get_network_iocs(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> NetworkIOCsResponse:
    """Extract network IOCs (IPs, domains, URLs) from analysis results.

    Private IPs are reported separately so callers can decide whether to
    include them.
    """
    result = await _get_analysis_result(submission_id, analysis_id, db)
    iocs = extract_network_iocs(result)
    return NetworkIOCsResponse(**iocs)
