from typing import Any

from pydantic import BaseModel


class ThreatIntelProviderResult(BaseModel):
    """A single provider's lookup result."""

    provider: str
    data: dict[str, Any] | None = None
    cached: bool = False
    error: str | None = None


class ThreatIntelHashResponse(BaseModel):
    """Response for a file-hash lookup across all providers."""

    sha256: str
    results: list[ThreatIntelProviderResult]


class ThreatIntelIPResponse(BaseModel):
    """Response for an IP address lookup across all providers."""

    ip: str
    results: list[ThreatIntelProviderResult]


class ThreatIntelAggregateResponse(BaseModel):
    """Full enrichment response for a submission (hash + network indicators)."""

    hash_results: list[ThreatIntelProviderResult] = []
    ip_results: dict[str, list[ThreatIntelProviderResult]] = {}
    domain_results: dict[str, list[ThreatIntelProviderResult]] = {}


class ThreatIntelProviderStatus(BaseModel):
    name: str
    configured: bool


class ThreatIntelStatusResponse(BaseModel):
    """Which threat-intel providers are configured on this instance."""

    providers: list[ThreatIntelProviderStatus]
