import logging
from typing import Any

import httpx

from detonate.services.threat_intel.base import BaseThreatIntelProvider

logger = logging.getLogger("detonate.threat_intel.urlhaus")


class URLhausProvider(BaseThreatIntelProvider):
    """URLhaus by abuse.ch - free, no API key required.

    Tracks malicious URLs used for malware distribution.  All endpoints
    accept POST requests with form-encoded parameters.
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    @property
    def name(self) -> str:
        return "urlhaus"

    def is_configured(self) -> bool:
        return True  # No API key needed

    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        """Look up a payload by SHA-256 hash.

        POST /payload/ with ``sha256_hash`` parameter.
        """
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/payload/",
                    data={"sha256_hash": sha256},
                )
                resp.raise_for_status()
                data = resp.json()

            if data.get("query_status") == "no_results":
                return None

            return {
                "md5": data.get("md5_hash"),
                "sha256": data.get("sha256_hash"),
                "file_type": data.get("file_type"),
                "file_size": data.get("file_size"),
                "signature": data.get("signature"),
                "firstseen": data.get("firstseen"),
                "lastseen": data.get("lastseen"),
                "url_count": data.get("url_count", 0),
                "urls": [
                    {
                        "url": u.get("url"),
                        "status": u.get("url_status"),
                        "threat": u.get("threat"),
                    }
                    for u in (data.get("urls") or [])[:10]
                ],
            }
        except httpx.TimeoutException:
            logger.warning("URLhaus hash lookup timed out for %s", sha256)
            return None
        except httpx.HTTPStatusError as exc:
            logger.error("URLhaus hash lookup HTTP error: %s", exc)
            return None
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("URLhaus hash lookup malformed response: %s", exc)
            return None
        except Exception as exc:
            logger.error("URLhaus hash lookup error: %s", exc)
            return None

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up a host (IP or domain) for associated malware URLs.

        POST /host/ with ``host`` parameter.
        """
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/host/",
                    data={"host": ip},
                )
                resp.raise_for_status()
                data = resp.json()

            if data.get("query_status") == "no_results":
                return None

            return {
                "url_count": data.get("url_count", 0),
                "urls_online": data.get("urls_online", 0),
                "blacklists": data.get("blacklists", {}),
                "urls": [
                    {
                        "url": u.get("url"),
                        "status": u.get("url_status"),
                        "threat": u.get("threat"),
                        "date_added": u.get("date_added"),
                    }
                    for u in (data.get("urls") or [])[:10]
                ],
            }
        except httpx.TimeoutException:
            logger.warning("URLhaus host lookup timed out for %s", ip)
            return None
        except httpx.HTTPStatusError as exc:
            logger.error("URLhaus host lookup HTTP error: %s", exc)
            return None
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("URLhaus host lookup malformed response: %s", exc)
            return None
        except Exception as exc:
            logger.error("URLhaus host lookup error: %s", exc)
            return None

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Domain lookup uses the same host endpoint as IP lookup."""
        return await self.lookup_ip(domain)
