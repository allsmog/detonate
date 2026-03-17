import json
import logging

import redis.asyncio as aioredis

from detonate.config import settings

logger = logging.getLogger("detonate.threat_intel.cache")


class ThreatIntelCache:
    """Redis-backed cache for threat intelligence lookups.

    Keys follow the pattern ``ti:{provider}:{indicator_type}:{indicator}``
    and expire after ``settings.threat_intel_cache_ttl`` seconds (default 1 hour).
    """

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.redis_url, decode_responses=True
            )
        return self._redis

    @staticmethod
    def _key(provider: str, indicator_type: str, indicator: str) -> str:
        return f"ti:{provider}:{indicator_type}:{indicator}"

    async def get(
        self, provider: str, indicator_type: str, indicator: str
    ) -> dict | None:
        try:
            r = await self._get_redis()
            key = self._key(provider, indicator_type, indicator)
            data = await r.get(key)
            return json.loads(data) if data else None
        except Exception as exc:
            logger.warning("Cache get failed for %s/%s: %s", provider, indicator, exc)
            return None

    async def set(
        self,
        provider: str,
        indicator_type: str,
        indicator: str,
        data: dict,
        ttl: int | None = None,
    ) -> None:
        try:
            r = await self._get_redis()
            key = self._key(provider, indicator_type, indicator)
            ttl = ttl or settings.threat_intel_cache_ttl
            await r.setex(key, ttl, json.dumps(data))
        except Exception as exc:
            logger.warning("Cache set failed for %s/%s: %s", provider, indicator, exc)
