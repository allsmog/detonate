from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_current_user_optional, get_db
from detonate.config import settings
from detonate.models.user import User
from detonate.models.webhook import Webhook
from detonate.schemas.webhook import (
    VALID_EVENTS,
    WebhookCreateRequest,
    WebhookResponse,
    WebhookTestResponse,
)
from detonate.services.webhook_service import test_webhook

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _require_auth_or_pass(user: User | None) -> User | None:
    """When auth is enabled, user must be present."""
    if settings.auth_enabled and user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.post("", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    body: WebhookCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
) -> WebhookResponse:
    """Create a new webhook subscription."""
    _require_auth_or_pass(user)

    # Validate events
    invalid = [e for e in body.events if e not in VALID_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event(s): {', '.join(invalid)}. "
            f"Valid events: {', '.join(VALID_EVENTS)}",
        )

    webhook = Webhook(
        user_id=user.id if user else None,
        url=body.url,
        secret=body.secret,
        events=body.events,
    )
    db.add(webhook)
    await db.flush()
    await db.refresh(webhook)
    return WebhookResponse.model_validate(webhook)


@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
) -> list[WebhookResponse]:
    """List webhooks. Authenticated users see their own; unauthenticated see global."""
    _require_auth_or_pass(user)

    if user:
        query = select(Webhook).where(Webhook.user_id == user.id)
    else:
        query = select(Webhook).where(Webhook.user_id.is_(None))

    query = query.order_by(Webhook.created_at.desc())
    result = await db.execute(query)
    webhooks = result.scalars().all()
    return [WebhookResponse.model_validate(wh) for wh in webhooks]


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
) -> None:
    """Delete a webhook."""
    _require_auth_or_pass(user)

    query = select(Webhook).where(Webhook.id == webhook_id)
    if user:
        query = query.where(Webhook.user_id == user.id)
    else:
        query = query.where(Webhook.user_id.is_(None))

    result = await db.execute(query)
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await db.delete(webhook)
    await db.flush()


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook_endpoint(
    webhook_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
) -> WebhookTestResponse:
    """Send a test payload to a webhook."""
    _require_auth_or_pass(user)

    query = select(Webhook).where(Webhook.id == webhook_id)
    if user:
        query = query.where(Webhook.user_id == user.id)
    else:
        query = query.where(Webhook.user_id.is_(None))

    result = await db.execute(query)
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    delivery_result = await test_webhook(db, webhook)
    return WebhookTestResponse(**delivery_result)
