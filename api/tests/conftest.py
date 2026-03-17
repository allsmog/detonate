import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from detonate.api.deps import get_storage
from detonate.config import settings
from detonate.main import create_app


@pytest.fixture
async def client():
    # Create a fresh engine per test to avoid stale asyncpg connections
    test_engine = create_async_engine(settings.database_url, echo=False)
    test_session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with test_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    _app = create_app()
    # Override the DB dependency with our test-scoped engine
    from detonate.api.deps import get_db
    _app.dependency_overrides[get_db] = override_get_db

    # Ensure MinIO bucket exists
    storage = get_storage()
    storage.ensure_bucket()

    transport = ASGITransport(app=_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await test_engine.dispose()
