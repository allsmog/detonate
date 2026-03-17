import asyncio

from worker.app import celery_app


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _summarize(submission_id: str):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from detonate.config import settings
    from detonate.services.ai import summarize_submission
    from detonate.services.llm import get_llm_provider

    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    llm = get_llm_provider()
    async with session_factory() as db:
        try:
            task = await summarize_submission(db, llm, submission_id)
            await db.commit()
            return str(task.id)
        except Exception:
            await db.rollback()
            raise
        finally:
            await engine.dispose()


async def _classify(submission_id: str):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from detonate.config import settings
    from detonate.services.ai import classify_submission
    from detonate.services.llm import get_llm_provider

    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    llm = get_llm_provider()
    async with session_factory() as db:
        try:
            task = await classify_submission(db, llm, submission_id)
            await db.commit()
            return str(task.id)
        except Exception:
            await db.rollback()
            raise
        finally:
            await engine.dispose()


async def _agent_analyze(submission_id: str):
    from uuid import UUID

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from detonate.config import settings
    from detonate.models.submission import Submission
    from detonate.services.agent import run_agent_analysis
    from detonate.services.llm import get_llm_provider

    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    llm = get_llm_provider()
    async with session_factory() as db:
        try:
            result = await db.execute(
                select(Submission).where(Submission.id == UUID(submission_id))
            )
            submission = result.scalar_one()
            task = await run_agent_analysis(db, llm, submission)
            await db.commit()
            return str(task.id)
        except Exception:
            await db.rollback()
            raise
        finally:
            await engine.dispose()


@celery_app.task(name="worker.tasks.ai.summarize_submission")
def summarize_submission_task(submission_id: str) -> str:
    return _run_async(_summarize(submission_id))


@celery_app.task(name="worker.tasks.ai.classify_submission")
def classify_submission_task(submission_id: str) -> str:
    return _run_async(_classify(submission_id))


@celery_app.task(name="worker.tasks.ai.agent_analyze")
def agent_analyze_task(submission_id: str) -> str:
    return _run_async(_agent_analyze(submission_id))
