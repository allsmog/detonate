import logging
from typing import Any

import httpx

from detonate.config import settings
from detonate.services.threat_intel.base import BaseThreatIntelProvider

logger = logging.getLogger("detonate.threat_intel.otx")

BASE_URL = "https://otx.alienvault.com"


class OTXProvider(BaseThreatIntelProvider):
    """AlienVault OTX threat intelligence provider."""

    @property
    def name(self) -> str:
        return "otx"

    def is_configured(self) -> bool:
        return bool(settings.otx_api_key)

    def _headers(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": settings.otx_api_key}

    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/api/v1/indicators/file/{sha256}/general"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("OTX rate limit hit for hash %s", sha256)
                return None
            resp.raise_for_status()

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            return {
                "pulse_count": pulse_info.get("count", 0),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "created": p.get("created"),
                        "tags": p.get("tags", []),
                    }
                    for p in pulses[:10]  # cap for readability
                ],
                "tags": list(
                    {tag for p in pulses for tag in p.get("tags", [])}
                )[:20],
            }
        except httpx.HTTPStatusError as exc:
            logger.error("OTX hash lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("OTX hash lookup error: %s", exc)
            return None

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/api/v1/indicators/IPv4/{ip}/general"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("OTX rate limit hit for IP %s", ip)
                return None
            resp.raise_for_status()

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            return {
                "pulse_count": pulse_info.get("count", 0),
                "country_name": data.get("country_name"),
            }
        except httpx.HTTPStatusError as exc:
            logger.error("OTX IP lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("OTX IP lookup error: %s", exc)
            return None

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/api/v1/indicators/domain/{domain}/general"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("OTX rate limit hit for domain %s", domain)
                return None
            resp.raise_for_status()

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            return {
                "pulse_count": pulse_info.get("count", 0),
            }
        except httpx.HTTPStatusError as exc:
            logger.error("OTX domain lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("OTX domain lookup error: %s", exc)
            return None
