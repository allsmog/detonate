import logging
from typing import Any

import httpx

from detonate.config import settings
from detonate.services.threat_intel.base import BaseThreatIntelProvider

logger = logging.getLogger("detonate.threat_intel.virustotal")

BASE_URL = "https://www.virustotal.com"


class VirusTotalProvider(BaseThreatIntelProvider):
    """VirusTotal v3 threat intelligence provider."""

    @property
    def name(self) -> str:
        return "virustotal"

    def is_configured(self) -> bool:
        return bool(settings.virustotal_api_key)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": settings.virustotal_api_key}

    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/api/v3/files/{sha256}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit for hash %s", sha256)
                return None
            resp.raise_for_status()

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            classification = data.get("popular_threat_classification", {})

            # Collect engine names that flagged the file
            last_results = data.get("last_analysis_results", {})
            detected_engines = [
                engine
                for engine, info in last_results.items()
                if info.get("category") == "malicious"
            ]

            total = sum(stats.values()) if stats else 0
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total": total,
                "threat_classification": classification.get("suggested_threat_label"),
                "threat_category": (
                    classification.get("popular_threat_category", [{}])[0]
                    .get("value")
                    if classification.get("popular_threat_category")
                    else None
                ),
                "detected_engines": detected_engines[:20],  # cap for readability
            }
        except httpx.HTTPStatusError as exc:
            logger.error("VirusTotal hash lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("VirusTotal hash lookup error: %s", exc)
            return None

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/api/v3/ip_addresses/{ip}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit for IP %s", ip)
                return None
            resp.raise_for_status()

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total": total,
                "country": data.get("country"),
                "as_owner": data.get("as_owner"),
            }
        except httpx.HTTPStatusError as exc:
            logger.error("VirusTotal IP lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("VirusTotal IP lookup error: %s", exc)
            return None

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        url = f"{BASE_URL}/api/v3/domains/{domain}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit for domain %s", domain)
                return None
            resp.raise_for_status()

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total": total,
                "registrar": data.get("registrar"),
                "creation_date": data.get("creation_date"),
            }
        except httpx.HTTPStatusError as exc:
            logger.error("VirusTotal domain lookup failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("VirusTotal domain lookup error: %s", exc)
            return None
