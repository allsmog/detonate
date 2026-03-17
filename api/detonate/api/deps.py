from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.config import settings
from detonate.database import async_session_factory
from detonate.services.llm import BaseLLMProvider, get_llm_provider, is_provider_configured
from detonate.services.storage import StorageService

_storage: StorageService | None = None

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_storage() -> StorageService:
    global _storage
    if _storage is None:
        _storage = StorageService()
    return _storage


def require_ai_enabled() -> BaseLLMProvider:
    if not settings.ai_enabled:
        raise HTTPException(status_code=503, detail="AI features are disabled")
    if not is_provider_configured():
        raise HTTPException(
            status_code=503,
            detail=f"LLM provider '{settings.llm_provider}' is not configured",
        )
    return get_llm_provider()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """Extract and validate the current user from a Bearer JWT or API key.

    Supports two authentication methods:
    - Bearer JWT token (Authorization: Bearer <jwt>)
    - API key (Authorization: Bearer <api_key>)

    Tries JWT decode first; on failure falls back to API key validation.
    """
    from detonate.models.user import User
    from detonate.services.auth import decode_access_token, validate_api_key

    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials

    # Try JWT first
    payload = decode_access_token(token)
    if payload is not None:
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return user

    # Fall back to API key
    user = await validate_api_key(db, token)
    if user is not None:
        return user

    raise HTTPException(status_code=401, detail="Invalid credentials")


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """Return the current user or None when auth is disabled."""
    if not settings.auth_enabled:
        return None
    if credentials is None:
        return None

    from detonate.models.user import User
    from detonate.services.auth import decode_access_token, validate_api_key

    token = credentials.credentials
    payload = decode_access_token(token)
    if payload is not None:
        user_id = payload.get("sub")
        if user_id:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user and user.is_active:
                return user
    user = await validate_api_key(db, token)
    return user


def require_role(role: str):
    """Factory that returns a dependency requiring a specific user role."""
    async def _check(
        user=Depends(get_current_user),
    ):
        if user.role != role and user.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _check
