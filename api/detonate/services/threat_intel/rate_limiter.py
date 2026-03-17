import logging

import redis.asyncio as aioredis

from detonate.config import settings

logger = logging.getLogger("detonate.threat_intel.rate_limiter")


class RateLimiter:
    """Redis-backed sliding window rate limiter for threat-intel API calls.

    Uses a simple counter with TTL: the first request within a window sets
    the key and starts the expiry timer.  Subsequent requests increment
    the counter.  Once ``max_requests`` is reached the provider is
    throttled until the window expires.
    """

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.redis_url, decode_responses=True
            )
        return self._redis

    async def is_allowed(
        self,
        provider: str,
        max_requests: int = 4,
        window_seconds: int = 60,
    ) -> bool:
        """Return ``True`` if *provider* has not exceeded its rate limit."""
        try:
            r = await self._get_redis()
            key = f"ratelimit:{provider}"
            current = await r.incr(key)
            if current == 1:
                await r.expire(key, window_seconds)
            return current <= max_requests
        except Exception as exc:
            logger.warning(
                "Rate limiter check failed for %s, allowing request: %s",
                provider,
                exc,
            )
            # Fail open -- if Redis is down we still attempt the lookup.
            return True
