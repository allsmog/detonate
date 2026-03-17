import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, get_storage
from detonate.config import settings
from detonate.schemas.health import HealthResponse, ServiceStatus
from detonate.services.storage import StorageService

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
) -> HealthResponse:
    # Check DB
    try:
        await db.execute(text("SELECT 1"))
        db_status = ServiceStatus(status="ok")
    except Exception:
        db_status = ServiceStatus(status="error")

    # Check Redis
    try:
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        redis_status = ServiceStatus(status="ok")
    except Exception:
        redis_status = ServiceStatus(status="error")

    # Check MinIO
    try:
        ok = storage.health_check()
        minio_status = ServiceStatus(status="ok" if ok else "error")
    except Exception:
        minio_status = ServiceStatus(status="error")

    overall = "ok" if all(
        s.status == "ok" for s in [db_status, redis_status, minio_status]
    ) else "degraded"

    return HealthResponse(
        status=overall,
        db=db_status,
        redis=redis_status,
        minio=minio_status,
    )
