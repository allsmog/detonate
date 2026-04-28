"""ThreatFox (abuse.ch) provider.

Free public API; an optional ``Auth-Key`` header increases rate limits.
Endpoints used:
- ``/api/v1/`` with ``query=search_hash`` for SHA-256 lookup
- ``/api/v1/`` with ``query=search_ioc`` for IP/domain lookup
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from detonate.config import settings
from detonate.services.threat_intel.base import BaseThreatIntelProvider

logger = logging.getLogger("detonate.threat_intel.threatfox")


class ThreatFoxProvider(BaseThreatIntelProvider):
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    @property
    def name(self) -> str:
        return "threatfox"

    def is_configured(self) -> bool:
        # Public endpoints work without a key, but rate limits are tight.
        return True

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        key = settings.threatfox_api_key.get_secret_value() if settings.threatfox_api_key else ""
        if key:
            h["Auth-Key"] = key
        return h

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self.BASE_URL, json=payload, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            logger.warning("ThreatFox timeout for %s", payload)
            return None
        except httpx.HTTPStatusError as exc:
            logger.error("ThreatFox HTTP error: %s", exc)
            return None
        except Exception as exc:
            logger.error("ThreatFox error: %s", exc)
            return None
        if data.get("query_status") not in (None, "ok"):
            return None
        return data

    @staticmethod
    def _summarize(entries: list[dict[str, Any]]) -> dict[str, Any]:
        threat_types = sorted({e.get("threat_type") for e in entries if e.get("threat_type")})
        malware_families = sorted({e.get("malware") for e in entries if e.get("malware")})
        confidences = [e.get("confidence_level", 0) or 0 for e in entries]
        return {
            "match_count": len(entries),
            "threat_types": threat_types,
            "malware_families": malware_families,
            "max_confidence": max(confidences) if confidences else 0,
            "first_seen": min((e.get("first_seen") for e in entries if e.get("first_seen")), default=None),
            "last_seen": max((e.get("last_seen") for e in entries if e.get("last_seen")), default=None),
            "samples": entries[:5],
        }

    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        data = await self._post({"query": "search_hash", "hash": sha256})
        if not data:
            return None
        entries = data.get("data") or []
        if not entries:
            return None
        return self._summarize(entries)

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        data = await self._post({"query": "search_ioc", "search_term": ip})
        if not data:
            return None
        entries = data.get("data") or []
        if not entries:
            return None
        return self._summarize(entries)

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        data = await self._post({"query": "search_ioc", "search_term": domain})
        if not data:
            return None
        entries = data.get("data") or []
        if not entries:
            return None
        return self._summarize(entries)
