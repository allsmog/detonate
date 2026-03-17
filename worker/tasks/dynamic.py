import asyncio

from worker.app import celery_app


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _execute_dynamic_analysis(analysis_id: str):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from detonate.config import settings
    from detonate.services.analysis import execute_analysis

    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as db:
        try:
            analysis = await execute_analysis(db, analysis_id)
            await db.commit()
            return str(analysis.id)
        except Exception:
            await db.rollback()
            raise
        finally:
            await engine.dispose()


@celery_app.task(name="worker.tasks.dynamic.run_dynamic_analysis_task")
def run_dynamic_analysis_task(analysis_id: str) -> str:
    return _run_async(_execute_dynamic_analysis(analysis_id))
