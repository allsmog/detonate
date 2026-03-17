import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.webhook import Webhook

logger = logging.getLogger("detonate.services.webhook")

# Maximum consecutive failures before auto-disabling
MAX_FAILURES = 10

# Timeout for webhook delivery requests (seconds)
DELIVERY_TIMEOUT = 10


async def trigger_webhooks(
    db: AsyncSession,
    event_type: str,
    payload: dict,
    user_id: str | None = None,
) -> int:
    """Send webhook notifications for an event.

    Matches all active webhooks subscribed to the given event_type.
    If user_id is provided, also includes webhooks owned by that user
    (in addition to global webhooks with no user_id).

    Returns the count of successfully triggered webhooks.
    """
    query = select(Webhook).where(
        Webhook.is_active.is_(True),
        Webhook.events.any(event_type),
    )
    if user_id:
        query = query.where(
            or_(Webhook.user_id == user_id, Webhook.user_id.is_(None))
        )
    else:
        query = query.where(Webhook.user_id.is_(None))

    result = await db.execute(query)
    webhooks = result.scalars().all()

    if not webhooks:
        return 0

    count = 0
    body = json.dumps(
        {"event": event_type, "data": payload, "timestamp": datetime.now(UTC).isoformat()},
        default=str,
    )

    async with httpx.AsyncClient(timeout=DELIVERY_TIMEOUT) as client:
        for wh in webhooks:
            try:
                headers: dict[str, str] = {
                    "Content-Type": "application/json",
                    "X-Webhook-Event": event_type,
                }

                if wh.secret:
                    sig = hmac.new(
                        wh.secret.encode(), body.encode(), hashlib.sha256
                    ).hexdigest()
                    headers["X-Webhook-Signature"] = f"sha256={sig}"

                resp = await client.post(wh.url, content=body, headers=headers)
                resp.raise_for_status()

                wh.last_triggered_at = datetime.now(UTC)
                wh.failure_count = 0
                count += 1
                logger.debug("Webhook %s delivered for %s", wh.id, event_type)

            except Exception as exc:
                logger.warning("Webhook %s failed: %s", wh.id, exc)
                wh.failure_count = (wh.failure_count or 0) + 1
                if wh.failure_count >= MAX_FAILURES:
                    wh.is_active = False
                    logger.info(
                        "Webhook %s disabled after %d consecutive failures",
                        wh.id,
                        MAX_FAILURES,
                    )

    await db.flush()
    return count


async def test_webhook(
    db: AsyncSession,
    webhook: Webhook,
) -> dict:
    """Send a test payload to a webhook. Returns delivery result."""
    test_payload = {
        "event": "webhook.test",
        "data": {
            "message": "This is a test notification from Detonate.",
            "webhook_id": str(webhook.id),
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }
    body = json.dumps(test_payload, default=str)

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-Webhook-Event": "webhook.test",
    }
    if webhook.secret:
        sig = hmac.new(
            webhook.secret.encode(), body.encode(), hashlib.sha256
        ).hexdigest()
        headers["X-Webhook-Signature"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=DELIVERY_TIMEOUT) as client:
            resp = await client.post(webhook.url, content=body, headers=headers)
            resp.raise_for_status()
            return {
                "success": True,
                "status_code": resp.status_code,
                "error": None,
            }
    except httpx.HTTPStatusError as exc:
        return {
            "success": False,
            "status_code": exc.response.status_code,
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "success": False,
            "status_code": None,
            "error": str(exc),
        }
