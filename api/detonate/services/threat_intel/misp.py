"""MISP threat-intelligence integration.

Bidirectional bridge: looks up indicators against the configured MISP
instance and (optionally) pushes observed IOCs back as a new event.
``MISP_PUBLISH=true`` controls whether IOCs from a completed analysis
are published. Requires ``misp_url`` and ``misp_api_key``.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from detonate.config import settings
from detonate.services.threat_intel.base import BaseThreatIntelProvider

logger = logging.getLogger("detonate.threat_intel.misp")


class MISPProvider(BaseThreatIntelProvider):
    @property
    def name(self) -> str:
        return "misp"

    def is_configured(self) -> bool:
        return bool(settings.misp_url and settings.misp_api_key.get_secret_value())

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": settings.misp_api_key.get_secret_value(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _search(self, value: str) -> list[dict[str, Any]] | None:
        if not self.is_configured():
            return None
        url = settings.misp_url.rstrip("/") + "/attributes/restSearch"
        try:
            async with httpx.AsyncClient(verify=settings.misp_verify_tls, timeout=20) as client:
                resp = await client.post(url, json={"value": value}, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            logger.warning("MISP timeout for %s", value)
            return None
        except Exception as exc:
            logger.error("MISP search failed: %s", exc)
            return None
        return ((data.get("response") or {}).get("Attribute")) or []

    @staticmethod
    def _summarize(attrs: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not attrs:
            return None
        events = sorted({a.get("event_id") for a in attrs if a.get("event_id")})
        categories = sorted({a.get("category") for a in attrs if a.get("category")})
        types = sorted({a.get("type") for a in attrs if a.get("type")})
        return {
            "match_count": len(attrs),
            "event_ids": events[:20],
            "categories": categories,
            "types": types,
            "samples": attrs[:5],
        }

    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        attrs = await self._search(sha256)
        return self._summarize(attrs or [])

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        attrs = await self._search(ip)
        return self._summarize(attrs or [])

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        attrs = await self._search(domain)
        return self._summarize(attrs or [])

    # ------------------------------------------------------------------
    # Outbound publish
    # ------------------------------------------------------------------

    async def publish_event(self, info: str, attributes: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Create a new MISP event with the given attributes.

        ``attributes`` items: ``{"type": "ip-dst", "value": "1.2.3.4", ...}``.
        """
        if not self.is_configured() or not settings.misp_publish:
            return None
        url = settings.misp_url.rstrip("/") + "/events/add"
        payload = {
            "Event": {
                "info": info,
                "distribution": 0,  # your org only
                "threat_level_id": 2,  # medium
                "analysis": 1,  # ongoing
                "Attribute": attributes,
            }
        }
        try:
            async with httpx.AsyncClient(verify=settings.misp_verify_tls, timeout=30) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("MISP publish failed: %s", exc)
            return None
