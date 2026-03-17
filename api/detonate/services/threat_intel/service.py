import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from detonate.services.threat_intel.base import BaseThreatIntelProvider
from detonate.services.threat_intel.cache import ThreatIntelCache
from detonate.services.threat_intel.rate_limiter import RateLimiter

logger = logging.getLogger("detonate.threat_intel.service")


class ThreatIntelService:
    """Aggregates results from all configured threat-intel providers.

    Each lookup is cached in Redis and protected by a per-provider rate limiter
    so that free-tier API quotas are not exhausted.
    """

    def __init__(self) -> None:
        self._providers: list[BaseThreatIntelProvider] = []
        self._cache = ThreatIntelCache()
        self._rate_limiter = RateLimiter()
        self._init_providers()

    # ------------------------------------------------------------------
    # Provider registration
    # ------------------------------------------------------------------

    def _init_providers(self) -> None:
        from detonate.services.threat_intel.abuseipdb import AbuseIPDBProvider
        from detonate.services.threat_intel.malwarebazaar import MalwareBazaarProvider
        from detonate.services.threat_intel.otx import OTXProvider
        from detonate.services.threat_intel.urlhaus import URLhausProvider
        from detonate.services.threat_intel.virustotal import VirusTotalProvider

        for cls in (
            VirusTotalProvider, AbuseIPDBProvider, OTXProvider,
            URLhausProvider, MalwareBazaarProvider,
        ):
            provider = cls()
            if provider.is_configured():
                self._providers.append(provider)
                logger.info("Threat-intel provider '%s' is configured", provider.name)
            else:
                logger.debug("Threat-intel provider '%s' is NOT configured", provider.name)

    # ------------------------------------------------------------------
    # Cache-aware lookup helper
    # ------------------------------------------------------------------

    async def _lookup_with_cache(
        self,
        provider: BaseThreatIntelProvider,
        lookup_type: str,
        indicator: str,
        lookup_fn,
    ) -> dict[str, Any]:
        """Execute a single-provider lookup with caching and rate limiting.

        Returns a dict with keys: ``provider``, ``data``, ``cached``, ``error``.
        """
        # 1. Check cache
        cached = await self._cache.get(provider.name, lookup_type, indicator)
        if cached is not None:
            return {
                "provider": provider.name,
                "data": cached,
                "cached": True,
                "error": None,
            }

        # 2. Check rate limit
        if not await self._rate_limiter.is_allowed(provider.name):
            logger.warning(
                "Rate limit exceeded for provider '%s', skipping %s lookup",
                provider.name,
                lookup_type,
            )
            return {
                "provider": provider.name,
                "data": None,
                "cached": False,
                "error": "Rate limit exceeded",
            }

        # 3. Call provider
        try:
            data = await lookup_fn(indicator)
        except Exception as exc:
            logger.error(
                "Provider '%s' %s lookup failed for %s: %s",
                provider.name,
                lookup_type,
                indicator,
                exc,
            )
            return {
                "provider": provider.name,
                "data": None,
                "cached": False,
                "error": str(exc),
            }

        # 4. Cache successful result
        if data is not None:
            await self._cache.set(provider.name, lookup_type, indicator, data)

        return {
            "provider": provider.name,
            "data": data,
            "cached": False,
            "error": None,
        }

    # ------------------------------------------------------------------
    # Public lookup methods
    # ------------------------------------------------------------------

    async def lookup_hash(self, sha256: str) -> list[dict[str, Any]]:
        """Query all providers for a file hash."""
        results: list[dict[str, Any]] = []
        for provider in self._providers:
            result = await self._lookup_with_cache(
                provider, "hash", sha256, provider.lookup_hash
            )
            results.append(result)
        return results

    async def lookup_ip(self, ip: str) -> list[dict[str, Any]]:
        """Query all providers for an IP address."""
        results: list[dict[str, Any]] = []
        for provider in self._providers:
            result = await self._lookup_with_cache(
                provider, "ip", ip, provider.lookup_ip
            )
            results.append(result)
        return results

    async def lookup_domain(self, domain: str) -> list[dict[str, Any]]:
        """Query all providers for a domain."""
        results: list[dict[str, Any]] = []
        for provider in self._providers:
            result = await self._lookup_with_cache(
                provider, "domain", domain, provider.lookup_domain
            )
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Submission enrichment
    # ------------------------------------------------------------------

    async def enrich_submission(
        self,
        db: AsyncSession,
        submission,
        analysis=None,
    ) -> dict[str, Any]:
        """Run full enrichment for a submission.

        * Always queries the submission's SHA-256 hash.
        * If a completed *analysis* is provided, extracts IPs and domains
          from its ``result`` (network connections, PCAP, DNS queries) and
          looks those up as well.
        * Stores the aggregate payload in ``submission.threat_intel`` (JSONB)
          so it can be returned quickly on subsequent reads.
        """
        enrichment: dict[str, Any] = {
            "hash_results": [],
            "ip_results": {},
            "domain_results": {},
        }

        # Hash lookup
        if submission.file_hash_sha256:
            enrichment["hash_results"] = await self.lookup_hash(
                submission.file_hash_sha256
            )

        # Network indicators from analysis
        if analysis and analysis.result:
            ips, domains = self._extract_network_indicators(analysis.result)

            for ip in ips:
                enrichment["ip_results"][ip] = await self.lookup_ip(ip)

            for domain in domains:
                enrichment["domain_results"][domain] = await self.lookup_domain(domain)

        # Persist on the submission row (best-effort; column may not exist yet)
        try:
            submission.threat_intel = enrichment  # type: ignore[attr-defined]
            db.add(submission)
        except Exception:
            logger.debug(
                "Could not persist threat_intel on submission %s "
                "(column may not exist yet)",
                submission.id,
            )

        return enrichment

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> list[dict[str, Any]]:
        """Return the configuration state of every known provider."""
        from detonate.services.threat_intel.abuseipdb import AbuseIPDBProvider
        from detonate.services.threat_intel.otx import OTXProvider
        from detonate.services.threat_intel.virustotal import VirusTotalProvider

        all_providers = [VirusTotalProvider(), AbuseIPDBProvider(), OTXProvider()]
        return [
            {"name": p.name, "configured": p.is_configured()}
            for p in all_providers
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_network_indicators(
        result: dict[str, Any],
    ) -> tuple[set[str], set[str]]:
        """Pull unique IPs and domains from an analysis result dict."""
        ips: set[str] = set()
        domains: set[str] = set()

        # Network connections from sandbox telemetry
        for conn in result.get("network", []):
            addr = conn.get("address")
            if addr:
                ips.add(addr)

        # PCAP data
        pcap = result.get("pcap", {})
        for conn in pcap.get("connections", []):
            for key in ("src", "dst"):
                addr = conn.get(key)
                if addr:
                    ips.add(addr)

        for dns in pcap.get("dns_queries", []):
            query = dns.get("query")
            if query:
                domains.add(query)

        for host in pcap.get("http_hosts", []):
            if host:
                domains.add(host)

        # Filter out common private/loopback addresses
        private_prefixes = ("10.", "172.", "192.168.", "127.", "0.")
        ips = {
            ip
            for ip in ips
            if not any(ip.startswith(prefix) for prefix in private_prefixes)
        }

        return ips, domains
