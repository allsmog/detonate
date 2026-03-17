import logging
from typing import Any

import httpx

from detonate.config import settings
from detonate.services.threat_intel.base import BaseThreatIntelProvider

logger = logging.getLogger("detonate.threat_intel.abuseipdb")

BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider(BaseThreatIntelProvider):
    """AbuseIPDB threat intelligence provider (IP lookups only)."""

    @property
    def name(self) -> str:
        return "abuseipdb"

    def is_configured(self) -> bool:
        return bool(settings.abuseipdb_api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Key": settings.abuseipdb_api_key,
            "Accept": "application/json",
        }

    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        # AbuseIPDB does not support file hash lookups.
        return None

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers(), params=params)

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limit hit for IP %s", ip)
                return None
            resp.raise_for_status()

            data = resp.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
            }
        except httpx.HTTPStatusError as exc:
            logger.error("AbuseIPDB IP lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("AbuseIPDB IP lookup error: %s", exc)
            return None

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        # AbuseIPDB does not support domain lookups.
        return None
