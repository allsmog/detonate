from abc import ABC, abstractmethod
from typing import Any


class BaseThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name used as a key in results and cache."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True when all required credentials are present."""
        ...

    @abstractmethod
    async def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        """Look up a file hash. Returns normalised result dict or None."""
        ...

    @abstractmethod
    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up an IP address. Returns normalised result dict or None."""
        ...

    @abstractmethod
    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Look up a domain. Returns normalised result dict or None."""
        ...
