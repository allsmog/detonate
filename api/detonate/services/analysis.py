import base64
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_storage
from detonate.config import settings
from detonate.machinery.docker import DockerMachinery
from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.services.suricata import SuricataService

logger = logging.getLogger("detonate.services.analysis")


def _store_pcap(result: dict, analysis_id: str) -> bytes | None:
    """Extract raw PCAP bytes from result, store in MinIO, clean up.

    The machinery puts raw bytes under the ``_pcap_data`` key.  This
    helper uploads them to ``pcap/{analysis_id}.pcap`` in MinIO and
    removes the transient key so it is not persisted into JSONB.

    Returns the raw PCAP bytes (for Suricata) or None.
    """
    pcap_bytes: bytes | None = result.pop("_pcap_data", None)
    if not pcap_bytes:
        return None

    try:
        storage = get_storage()
        object_name = f"pcap/{analysis_id}.pcap"
        storage.upload_file(
            object_name, pcap_bytes, content_type="application/vnd.tcpdump.pcap"
        )
        logger.info(
            "Stored PCAP (%d bytes) at %s", len(pcap_bytes), object_name
        )
    except Exception as exc:
        logger.error("Failed to store PCAP for analysis %s: %s", analysis_id, exc)

    return pcap_bytes


def _store_screenshots(result: dict, analysis_id: str) -> None:
    """Extract screenshot data from result, store in MinIO, clean up transient key."""
    screenshot_data = result.pop("_screenshot_data", None)
    if not screenshot_data:
        return

    try:
        storage = get_storage()
        paths = []
        for name, b64data in screenshot_data:
            import base64 as _b64
            raw = _b64.b64decode(b64data)
            object_name = f"screenshots/{analysis_id}/{name}"
            storage.upload_file(object_name, raw, content_type="image/png")
            paths.append(object_name)
        result["screenshot_paths"] = paths
        logger.info("Stored %d screenshots for analysis %s", len(paths), analysis_id)
    except Exception as exc:
        logger.error("Failed to store screenshots for %s: %s", analysis_id, exc)


def _store_video(result: dict, analysis_id: str) -> None:
    """Extract video data from result, store in MinIO, clean up transient key."""
    video_data = result.pop("_video_data", None)
    if not video_data:
        return

    try:
        import base64 as _b64
        storage = get_storage()
        raw = _b64.b64decode(video_data)
        object_name = f"videos/{analysis_id}.mp4"
        storage.upload_file(object_name, raw, content_type="video/mp4")
        result["video_path"] = object_name
        logger.info("Stored video (%d bytes) for analysis %s", len(raw), analysis_id)
    except Exception as exc:
        logger.error("Failed to store video for %s: %s", analysis_id, exc)


def get_machinery(platform: str = "linux"):
    """Return the appropriate machinery for the given platform."""
    if platform == "windows":
        if not settings.qemu_enabled:
            raise RuntimeError("QEMU is not enabled. Set qemu_enabled=True.")
        from detonate.machinery.qemu import QEMUMachinery
        return QEMUMachinery()
    return DockerMachinery()


async def _run_suricata_if_available(
    result: dict, analysis_id: str, pcap_bytes: bytes | None = None,
) -> dict:
    """Run Suricata IDS on PCAP data if available and enabled.

    If suricata_enabled is False or no PCAP data is present in the
    results, this returns the result dict unchanged.

    Accepts raw pcap_bytes directly (preferred) or falls back to
    base64-encoded pcap_data in the result dict.
    """
    if not settings.suricata_enabled:
        return result

    # Accept raw bytes directly, or fall back to base64-encoded pcap_data
    if pcap_bytes is None:
        pcap_data = result.get("pcap_data")
        if not pcap_data:
            logger.debug(
                "No PCAP data in analysis %s, skipping Suricata", analysis_id
            )
            return result

        try:
            pcap_bytes = base64.b64decode(pcap_data)
        except Exception:
            logger.warning(
                "Failed to decode PCAP data for analysis %s", analysis_id
            )
            return result

    try:
        suricata = SuricataService()
        ids_result = await suricata.analyze_pcap(pcap_bytes, analysis_id)
        result["ids_alerts"] = ids_result.get("ids_alerts", [])
        result["ids_summary"] = ids_result.get("ids_summary", {})
        if ids_result.get("ids_error"):
            result["ids_error"] = ids_result["ids_error"]
    except Exception as exc:
        logger.error("Suricata analysis failed for %s: %s", analysis_id, exc)
        result["ids_alerts"] = []
        result["ids_summary"] = {
            "total_alerts": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "categories": [],
        }
        result["ids_error"] = str(exc)

    return result


async def create_queued_analysis(
    db: AsyncSession,
    submission: Submission,
    config: dict[str, Any] | None = None,
) -> Analysis:
    """Create an Analysis record in 'queued' status without running it."""
    config = config or {}

    analysis = Analysis(
        submission_id=submission.id,
        type="dynamic",
        status="queued",
        config=config,
    )
    db.add(analysis)
    await db.flush()
    return analysis


async def dispatch_dynamic_analysis(
    db: AsyncSession,
    analysis: Analysis,
) -> Analysis:
    """Dispatch a queued analysis to Celery and store the task ID."""
    from worker.tasks.dynamic import run_dynamic_analysis_task

    result = run_dynamic_analysis_task.apply_async(
        args=[str(analysis.id)],
        queue="dynamic",
    )
    analysis.celery_task_id = result.id
    await db.flush()
    return analysis


async def _run_machinery(
    analysis: Analysis,
    submission: Submission,
    config: dict[str, Any],
) -> dict:
    """Run the Docker machinery, with optional machine pool support.

    If sandbox_pool_enabled, acquires a machine from the pool, runs
    the analysis using the pooled container, and releases the machine.
    Otherwise uses the on-demand flow (create container, run, destroy).
    """
    storage = get_storage()
    sample_data = storage.get_file(submission.storage_path)
    platform = config.get("platform", "linux")
    machinery = get_machinery(platform)

    if settings.sandbox_pool_enabled:
        from detonate.services.machine_pool import get_machine_pool

        pool = get_machine_pool()
        machine = await pool.acquire(platform=settings.sandbox_platform)
        analysis.machine_id = machine.id
        try:
            result = await machinery.start(
                sample_data,
                submission.filename or "sample",
                config,
                analysis_id=analysis.id,
                container_id=machine.container_id,
            )
            new_container_id = result.pop("_container_id", None)
            if new_container_id:
                machine.container_id = new_container_id
            return result
        finally:
            try:
                await pool.release(machine)
            except Exception as release_exc:
                logger.error("Failed to release machine %s: %s", machine.name, release_exc)
    else:
        return await machinery.start(
            sample_data,
            submission.filename or "sample",
            config,
            analysis_id=analysis.id,
        )


async def run_dynamic_analysis(
    db: AsyncSession,
    submission: Submission,
    config: dict[str, Any] | None = None,
) -> Analysis:
    """Run dynamic analysis synchronously (used by the Celery worker)."""
    config = config or {}
    started_at = datetime.now(UTC)

    analysis = Analysis(
        submission_id=submission.id,
        type="dynamic",
        status="running",
        config=config,
        started_at=started_at,
    )
    db.add(analysis)
    await db.flush()

    try:
        result = await _run_machinery(analysis, submission, config)

        # Store PCAP in MinIO and get raw bytes for Suricata
        pcap_bytes = _store_pcap(result, str(analysis.id))

        # Store screenshots and video in MinIO
        _store_screenshots(result, str(analysis.id))
        _store_video(result, str(analysis.id))

        # Run Suricata IDS on PCAP if available and enabled
        result = await _run_suricata_if_available(
            result, str(analysis.id), pcap_bytes=pcap_bytes
        )

        completed_at = datetime.now(UTC)
        analysis.result = result
        analysis.status = "completed"
        analysis.completed_at = completed_at
        analysis.duration_seconds = int((completed_at - started_at).total_seconds())

    except Exception as exc:
        logger.error("Dynamic analysis failed: %s", exc)
        completed_at = datetime.now(UTC)
        analysis.status = "failed"
        analysis.result = {"error": str(exc)}
        analysis.completed_at = completed_at
        analysis.duration_seconds = int((completed_at - started_at).total_seconds())

    await db.flush()
    return analysis


async def execute_analysis(
    db: AsyncSession,
    analysis_id: str,
) -> Analysis:
    """Execute an existing queued Analysis record (called by Celery worker)."""
    from uuid import UUID

    result = await db.execute(
        select(Analysis).where(Analysis.id == UUID(analysis_id))
    )
    analysis = result.scalar_one()

    # Load the submission
    sub_result = await db.execute(
        select(Submission).where(Submission.id == analysis.submission_id)
    )
    submission = sub_result.scalar_one()

    started_at = datetime.now(UTC)
    analysis.status = "running"
    analysis.started_at = started_at
    await db.flush()

    try:
        run_result = await _run_machinery(analysis, submission, analysis.config or {})

        # Store PCAP in MinIO and get raw bytes for Suricata
        pcap_bytes = _store_pcap(run_result, analysis_id)

        # Store screenshots and video in MinIO
        _store_screenshots(run_result, analysis_id)
        _store_video(run_result, analysis_id)

        # Run Suricata IDS on PCAP if available and enabled
        run_result = await _run_suricata_if_available(
            run_result, analysis_id, pcap_bytes=pcap_bytes
        )

        completed_at = datetime.now(UTC)
        analysis.result = run_result
        analysis.status = "completed"
        analysis.completed_at = completed_at
        analysis.duration_seconds = int((completed_at - started_at).total_seconds())

    except Exception as exc:
        logger.error("Dynamic analysis failed for analysis %s: %s", analysis_id, exc)
        completed_at = datetime.now(UTC)
        analysis.status = "failed"
        analysis.result = {"error": str(exc)}
        analysis.completed_at = completed_at
        analysis.duration_seconds = int((completed_at - started_at).total_seconds())

    await db.flush()
    return analysis


async def get_analyses_for_submission(
    db: AsyncSession, submission_id: Any
) -> list[Analysis]:
    result = await db.execute(
        select(Analysis)
        .where(Analysis.submission_id == submission_id)
        .order_by(Analysis.started_at.desc().nulls_first())
    )
    return list(result.scalars().all())


async def get_analysis(
    db: AsyncSession, submission_id: Any, analysis_id: Any
) -> Analysis | None:
    result = await db.execute(
        select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.submission_id == submission_id,
        )
    )
    return result.scalar_one_or_none()
