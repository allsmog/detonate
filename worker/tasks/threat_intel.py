import asyncio
import logging

from worker.app import celery_app

logger = logging.getLogger("worker.tasks.threat_intel")


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _execute_enrichment(submission_id: str) -> dict:
    from uuid import UUID

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from detonate.config import settings
    from detonate.models.analysis import Analysis
    from detonate.models.submission import Submission
    from detonate.services.threat_intel.service import ThreatIntelService

    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with session_factory() as db:
        try:
            result = await db.execute(
                select(Submission).where(Submission.id == UUID(submission_id))
            )
            submission = result.scalar_one()

            # Get latest completed analysis if any
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

            service = ThreatIntelService()
            enrichment = await service.enrich_submission(db, submission, analysis)
            await db.commit()
            return enrichment
        except Exception:
            await db.rollback()
            raise
        finally:
            await engine.dispose()


@celery_app.task(name="worker.tasks.threat_intel.run_threat_intel_enrichment")
def run_threat_intel_enrichment(submission_id: str) -> dict:
    """Run threat intel enrichment for a submission as a Celery task."""
    return _run_async(_execute_enrichment(submission_id))
