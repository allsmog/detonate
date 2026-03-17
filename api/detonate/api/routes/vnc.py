"""VNC interactive session routes.

Provides endpoints to start, stop, and check the status of VNC sessions
that bridge a browser WebSocket connection to the VNC server running
inside a sandbox container.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.services.vnc import VNCManager

logger = logging.getLogger("detonate.api.routes.vnc")

router = APIRouter(tags=["vnc"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class VNCStartRequest(BaseModel):
    """Optional overrides when starting a VNC session."""
    vnc_host: str | None = None
    vnc_port: int = 5900
    timeout: int = 300


class VNCStartResponse(BaseModel):
    """Returned after a VNC session is started."""
    ws_url: str
    ws_port: int
    timeout: int


class VNCStatusResponse(BaseModel):
    """Current state of a VNC session for an analysis."""
    active: bool
    ws_url: str | None = None
    ws_port: int | None = None
    timeout: int | None = None
    elapsed_seconds: int | None = None


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


async def _get_analysis(
    db: AsyncSession, submission_id: UUID, analysis_id: UUID
) -> Analysis:
    result = await db.execute(
        select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.submission_id == submission_id,
        )
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/submissions/{submission_id}/analyses/{analysis_id}/vnc/start",
    response_model=VNCStartResponse,
)
async def start_vnc_session(
    submission_id: UUID,
    analysis_id: UUID,
    body: VNCStartRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> VNCStartResponse:
    """Start a VNC interactive session for the given analysis.

    Launches a ``websockify`` bridge process that proxies a browser
    WebSocket connection to the VNC server inside the sandbox container.
    If a session already exists for this analysis, returns its info
    without creating a duplicate.

    The session auto-terminates after ``timeout`` seconds (default 300).
    """
    await _get_submission(db, submission_id)
    analysis = await _get_analysis(db, submission_id, analysis_id)

    if analysis.status not in ("running", "queued"):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Analysis is in '{analysis.status}' state. "
                "VNC sessions can only be started for running analyses."
            ),
        )

    body = body or VNCStartRequest()
    manager = VNCManager.get_instance()

    # Determine VNC host -- if the analysis has a container_id or machine
    # we could resolve the IP, but for now use the provided host or
    # fall back to localhost (works for single-host Docker setups).
    vnc_host = body.vnc_host or "localhost"

    try:
        session = await manager.create_session(
            analysis_id=str(analysis_id),
            vnc_host=vnc_host,
            vnc_port=body.vnc_port,
            timeout=body.timeout,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    ws_url = f"ws://localhost:{session.ws_port}"

    return VNCStartResponse(
        ws_url=ws_url,
        ws_port=session.ws_port,
        timeout=session.timeout,
    )


@router.post(
    "/submissions/{submission_id}/analyses/{analysis_id}/vnc/stop",
    status_code=204,
)
async def stop_vnc_session(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Stop an active VNC session for the given analysis.

    Terminates the ``websockify`` bridge process.  Returns 204 on
    success or if no session was active.
    """
    await _get_submission(db, submission_id)
    await _get_analysis(db, submission_id, analysis_id)

    manager = VNCManager.get_instance()
    destroyed = await manager.destroy_session(str(analysis_id))
    if destroyed:
        logger.info("VNC session stopped for analysis %s", analysis_id)


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/vnc/status",
    response_model=VNCStatusResponse,
)
async def vnc_session_status(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> VNCStatusResponse:
    """Check whether a VNC session is active for the given analysis."""
    await _get_submission(db, submission_id)
    await _get_analysis(db, submission_id, analysis_id)

    manager = VNCManager.get_instance()
    session = await manager.get_session(str(analysis_id))

    if session is None:
        return VNCStatusResponse(active=False)

    from datetime import UTC, datetime

    elapsed = int((datetime.now(UTC) - session.created_at).total_seconds())

    return VNCStatusResponse(
        active=True,
        ws_url=f"ws://localhost:{session.ws_port}",
        ws_port=session.ws_port,
        timeout=session.timeout,
        elapsed_seconds=elapsed,
    )
