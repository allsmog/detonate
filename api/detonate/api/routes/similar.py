"""Similar-sample lookup.

Computes the requested submission's similarity hashes (imphash, ssdeep,
TLSH) and returns other submissions whose stored hashes match closely.

For SHA-256 we do exact equality; for ssdeep / TLSH we score against
every other sample's stored similarity dict and threshold. Stored
similarity hashes live alongside ``submission.threat_intel`` JSONB
under the ``"similarity"`` key (set during static analysis).
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, get_storage
from detonate.config import settings
from detonate.models.submission import Submission
from detonate.services.similarity import (
    compute_similarity_hashes,
    ssdeep_compare,
    tlsh_distance,
)
from detonate.services.static_analysis import run_static_analysis
from detonate.services.storage import StorageService

logger = logging.getLogger("detonate.api.routes.similar")
router = APIRouter(tags=["similarity"])


def _stored_similarity(s: Submission) -> dict[str, Any]:
    ti = s.threat_intel or {}
    if isinstance(ti, dict):
        sim = ti.get("similarity")
        if isinstance(sim, dict):
            return sim
    return {}


@router.get("/submissions/{submission_id}/similar")
async def get_similar(
    submission_id: UUID,
    ssdeep_threshold: int = Query(default=60, ge=0, le=100),
    tlsh_threshold: int = Query(default=70, ge=0, le=400),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
) -> dict[str, Any]:
    if not settings.similarity_enabled:
        raise HTTPException(status_code=503, detail="Similarity disabled")

    target = (await db.execute(select(Submission).where(Submission.id == submission_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Submission not found")

    target_sim = _stored_similarity(target)
    if not target_sim:
        try:
            data = storage.get_file(target.storage_path)
            target_static = await run_static_analysis(
                data, target.filename or "sample", mime=target.mime_type,
            )
            target_sim = compute_similarity_hashes(data, target_static)
        except Exception as exc:
            logger.warning("Could not compute similarity for target: %s", exc)
            raise HTTPException(status_code=500, detail="Could not compute target hashes")

    # Pull candidates: other submissions with at least one similarity hash stored
    rows = (await db.execute(select(Submission).where(Submission.id != target.id))).scalars().all()

    matches: list[dict[str, Any]] = []
    for cand in rows:
        cand_sim = _stored_similarity(cand)
        if not cand_sim:
            continue
        match: dict[str, Any] = {
            "submission_id": str(cand.id),
            "filename": cand.filename,
            "sha256": cand.file_hash_sha256,
            "verdict": cand.verdict,
            "scores": {},
        }
        if target_sim.get("imphash") and target_sim["imphash"] == cand_sim.get("imphash"):
            match["scores"]["imphash"] = "exact"
        if target_sim.get("rich_pe_hash") and target_sim["rich_pe_hash"] == cand_sim.get("rich_pe_hash"):
            match["scores"]["rich_pe_hash"] = "exact"
        if target_sim.get("behavior_vhash") and target_sim["behavior_vhash"] == cand_sim.get("behavior_vhash"):
            match["scores"]["behavior_vhash"] = "exact"
        if target_sim.get("ssdeep") and cand_sim.get("ssdeep"):
            score = ssdeep_compare(target_sim["ssdeep"], cand_sim["ssdeep"])
            if score is not None and score >= ssdeep_threshold:
                match["scores"]["ssdeep"] = score
        if target_sim.get("tlsh") and cand_sim.get("tlsh"):
            dist = tlsh_distance(target_sim["tlsh"], cand_sim["tlsh"])
            if dist is not None and dist <= tlsh_threshold:
                match["scores"]["tlsh_distance"] = dist
        if match["scores"]:
            matches.append(match)

    # Rank: more matched algorithms first, then by ssdeep score, then by inverse tlsh distance
    def _rank(m: dict[str, Any]) -> tuple:
        s = m["scores"]
        return (
            -len(s),
            -(s.get("ssdeep", 0) if isinstance(s.get("ssdeep"), int) else 0),
            s.get("tlsh_distance", 999),
        )

    matches.sort(key=_rank)
    return {
        "target": {
            "submission_id": str(target.id),
            "filename": target.filename,
            "sha256": target.file_hash_sha256,
            "similarity": target_sim,
        },
        "matches": matches[:limit],
        "match_count": len(matches),
    }
