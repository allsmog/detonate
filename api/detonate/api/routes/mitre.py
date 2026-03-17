"""FastAPI routes for MITRE ATT&CK mapping."""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, require_ai_enabled
from detonate.schemas.mitre import (
    MITREAnalysisResponse,
    MITRETechniqueDetail,
    MITRETechniqueMatch,
)
from detonate.services.analysis import get_analysis
from detonate.services.llm import BaseLLMProvider
from detonate.services.mitre.data import get_technique, load_techniques, search_techniques
from detonate.services.mitre.service import _build_tactics_coverage, analyze_mitre

logger = logging.getLogger("detonate.api.routes.mitre")

router = APIRouter(tags=["mitre"])


# ---- Analysis-level endpoints ----


@router.post(
    "/submissions/{submission_id}/analyses/{analysis_id}/mitre",
    response_model=MITREAnalysisResponse,
)
async def run_mitre_mapping(
    submission_id: UUID,
    analysis_id: UUID,
    use_ai: bool = Query(False, description="Use LLM for enhanced classification"),
    db: AsyncSession = Depends(get_db),
) -> MITREAnalysisResponse:
    """Run MITRE ATT&CK mapping on a completed analysis.

    The rule engine always runs.  Set ``use_ai=true`` to additionally use
    the configured LLM provider for AI-enhanced technique detection.
    """
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if analysis.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Analysis is not completed (status={analysis.status})",
        )

    llm: BaseLLMProvider | None = None
    if use_ai:
        try:
            llm = require_ai_enabled()
        except HTTPException:
            raise HTTPException(
                status_code=503,
                detail="AI features are not available; running rule-only mapping",
            )

    techniques = await analyze_mitre(db, analysis, llm=llm)

    technique_matches = [
        MITRETechniqueMatch(**t) for t in techniques
    ]
    tactics_coverage = _build_tactics_coverage(techniques)

    return MITREAnalysisResponse(
        techniques=technique_matches,
        tactics_coverage=tactics_coverage,
    )


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/mitre",
    response_model=MITREAnalysisResponse,
)
async def get_mitre_mapping(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> MITREAnalysisResponse:
    """Return cached MITRE ATT&CK mapping for an analysis.

    Returns the techniques previously computed and stored on the analysis
    record.  If no mapping has been run yet, returns an empty response.
    """
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    result = analysis.result or {}
    techniques_raw = result.get("mitre_techniques", [])
    tactics_coverage = result.get("mitre_tactics_coverage", {})

    technique_matches = []
    for t in techniques_raw:
        try:
            technique_matches.append(MITRETechniqueMatch(**t))
        except Exception:
            logger.debug("Skipping malformed technique entry: %s", t)
            continue

    return MITREAnalysisResponse(
        techniques=technique_matches,
        tactics_coverage=tactics_coverage,
    )


# ---- Technique catalog endpoints ----


@router.get(
    "/mitre/techniques",
    response_model=list[MITRETechniqueDetail],
)
async def list_techniques(
    search: str = Query("", description="Search query (name, ID, or description)"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> list[MITRETechniqueDetail]:
    """List all MITRE ATT&CK techniques, with optional search filtering."""
    if search:
        results = search_techniques(search)
    else:
        results = list(load_techniques().values())

    # Sort by technique_id for deterministic ordering
    results.sort(key=lambda t: t.get("technique_id", ""))

    # Paginate
    page = results[offset : offset + limit]

    return [
        MITRETechniqueDetail(
            technique_id=t["technique_id"],
            name=t["name"],
            description=t.get("description", ""),
            tactics=t.get("tactics", []),
            platforms=t.get("platforms", []),
            url=t.get("url", ""),
        )
        for t in page
    ]


@router.get(
    "/mitre/techniques/{technique_id}",
    response_model=MITRETechniqueDetail,
)
async def get_technique_detail(
    technique_id: str,
) -> MITRETechniqueDetail:
    """Return details for a single MITRE ATT&CK technique."""
    tech = get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found")

    return MITRETechniqueDetail(
        technique_id=tech["technique_id"],
        name=tech["name"],
        description=tech.get("description", ""),
        tactics=tech.get("tactics", []),
        platforms=tech.get("platforms", []),
        url=tech.get("url", ""),
    )
