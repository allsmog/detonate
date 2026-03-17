import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, get_storage
from detonate.config import settings
from detonate.models.submission import Submission
from detonate.schemas.analysis import (
    AnalysisConfigRequest,
    AnalysisListResponse,
    AnalysisResponse,
)
from detonate.services.analysis import (
    create_queued_analysis,
    dispatch_dynamic_analysis,
    get_analyses_for_submission,
    get_analysis,
)
from detonate.services.events import subscribe_events

logger = logging.getLogger("detonate.api.routes.analyses")

router = APIRouter()


async def _get_submission(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.post(
    "/submissions/{submission_id}/analyze",
    response_model=AnalysisResponse,
    status_code=202,
)
async def start_analysis(
    submission_id: UUID,
    config: AnalysisConfigRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> AnalysisResponse:
    submission = await _get_submission(db, submission_id)
    analysis = await create_queued_analysis(
        db, submission, config.model_dump() if config else None
    )
    analysis = await dispatch_dynamic_analysis(db, analysis)
    return AnalysisResponse.model_validate(analysis)


@router.get(
    "/submissions/{submission_id}/analyses",
    response_model=AnalysisListResponse,
)
async def list_analyses(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> AnalysisListResponse:
    await _get_submission(db, submission_id)
    analyses = await get_analyses_for_submission(db, submission_id)
    return AnalysisListResponse(
        items=[AnalysisResponse.model_validate(a) for a in analyses],
        total=len(analyses),
    )


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}",
    response_model=AnalysisResponse,
)
async def get_analysis_detail(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> AnalysisResponse:
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisResponse.model_validate(analysis)


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/pcap",
    responses={
        200: {"content": {"application/vnd.tcpdump.pcap": {}}},
        404: {"description": "Analysis or PCAP not found"},
    },
)
async def download_pcap(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download the raw PCAP capture file for a given analysis."""
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Check that the analysis actually has PCAP data
    result = analysis.result or {}
    if "pcap" not in result:
        raise HTTPException(
            status_code=404,
            detail="No PCAP data available for this analysis",
        )

    storage = get_storage()
    object_name = f"pcap/{analysis_id}.pcap"

    try:
        pcap_data = storage.get_file(object_name)
    except Exception:
        raise HTTPException(
            status_code=404,
            detail="PCAP file not found in storage",
        )

    return Response(
        content=pcap_data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="capture-{analysis_id}.pcap"',
        },
    )


@router.post(
    "/submissions/{submission_id}/yara",
)
async def yara_scan(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Scan the original submitted sample with YARA rules (static scan, no sandbox)."""
    if not settings.yara_enabled:
        raise HTTPException(status_code=503, detail="YARA scanning is disabled")

    submission = await _get_submission(db, submission_id)

    try:
        from detonate.services.yara_scanner import YaraScanner

        scanner = YaraScanner()
        result = await scanner.scan_submission(db, submission)
        return result
    except FileNotFoundError as exc:
        logger.error("YARA rules not found: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="YARA rules not found. Ensure rules are installed.",
        )
    except Exception as exc:
        logger.error("YARA scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"YARA scan failed: {exc}")


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/media",
)
async def get_analysis_media(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return screenshot URLs and video URL for an analysis."""
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    result = analysis.result or {}
    screenshot_paths = result.get("screenshot_paths", [])
    video_path = result.get("video_path")

    base = f"/api/v1/submissions/{submission_id}/analyses/{analysis_id}"
    screenshots = [
        {"url": f"{base}/screenshots/{i}", "index": i}
        for i in range(len(screenshot_paths))
    ]

    video_url = (
        f"/api/v1/submissions/{submission_id}/analyses/{analysis_id}/video"
        if video_path
        else None
    )

    return {"screenshots": screenshots, "video_url": video_url}


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/screenshots/{index}",
)
async def get_screenshot(
    submission_id: UUID,
    analysis_id: UUID,
    index: int,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download an individual screenshot."""
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    result = analysis.result or {}
    paths = result.get("screenshot_paths", [])
    if index < 0 or index >= len(paths):
        raise HTTPException(status_code=404, detail="Screenshot not found")

    storage = get_storage()
    try:
        data = storage.get_file(paths[index])
    except Exception:
        raise HTTPException(status_code=404, detail="Screenshot file not found")

    return Response(content=data, media_type="image/png")


@router.get(
    "/submissions/{submission_id}/analyses/{analysis_id}/video",
)
async def get_video(
    submission_id: UUID,
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download the analysis recording video."""
    analysis = await get_analysis(db, submission_id, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    result = analysis.result or {}
    video_path = result.get("video_path")
    if not video_path:
        raise HTTPException(status_code=404, detail="No video available")

    storage = get_storage()
    try:
        data = storage.get_file(video_path)
    except Exception:
        raise HTTPException(status_code=404, detail="Video file not found")

    return Response(
        content=data,
        media_type="video/mp4",
        headers={"Content-Disposition": f'attachment; filename="recording-{analysis_id}.mp4"'},
    )


@router.websocket(
    "/submissions/{submission_id}/analyses/{analysis_id}/ws"
)
async def analysis_events_ws(
    websocket: WebSocket,
    submission_id: UUID,
    analysis_id: UUID,
) -> None:
    """WebSocket endpoint for real-time analysis event streaming.

    Subscribes to the Redis pub/sub channel for the given analysis
    and forwards each event as a JSON message to the connected client.
    Closes after the ``{"type": "complete"}`` event or on disconnect.
    """
    await websocket.accept()

    try:
        async for event in subscribe_events(analysis_id):
            await websocket.send_json(event)
            if event.get("type") == "complete":
                break
    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected for analysis %s", analysis_id)
    except Exception:
        logger.debug("WebSocket error for analysis %s", analysis_id, exc_info=True)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
