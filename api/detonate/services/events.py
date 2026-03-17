"""Redis pub/sub helpers for streaming analysis events."""

import json
import logging
from collections.abc import AsyncGenerator
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis

from detonate.config import settings

logger = logging.getLogger("detonate.services.events")

# Sentinel value published when analysis finishes
COMPLETE_EVENT = json.dumps({"type": "complete"})


def _channel_name(analysis_id: UUID | str) -> str:
    return f"analysis:{analysis_id}:events"


def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.redis_url, decode_responses=True)


async def publish_event(analysis_id: UUID | str, event_data: dict[str, Any]) -> None:
    """Publish a single event to the Redis channel for an analysis."""
    r = _get_redis()
    try:
        payload = json.dumps(event_data)
        await r.publish(_channel_name(analysis_id), payload)
    except Exception:
        logger.debug("Failed to publish event for analysis %s", analysis_id, exc_info=True)
    finally:
        await r.aclose()


async def publish_complete(analysis_id: UUID | str) -> None:
    """Publish the completion sentinel to the Redis channel."""
    r = _get_redis()
    try:
        await r.publish(_channel_name(analysis_id), COMPLETE_EVENT)
    except Exception:
        logger.debug("Failed to publish complete for analysis %s", analysis_id, exc_info=True)
    finally:
        await r.aclose()


async def subscribe_events(analysis_id: UUID | str) -> AsyncGenerator[dict[str, Any], None]:
    """Async generator that yields events from the Redis channel.

    Yields each event as a parsed dict.  Stops when a ``{"type": "complete"}``
    event is received or the channel is closed.
    """
    r = _get_redis()
    pubsub = r.pubsub()
    channel = _channel_name(analysis_id)
    try:
        await pubsub.subscribe(channel)
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue
            yield data
            if data.get("type") == "complete":
                break
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await r.aclose()
